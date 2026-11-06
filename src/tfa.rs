//! # Telegram Two-Factor Authentication (TFA) — стиль BaronessAuth / tiAuth
//!
//! Команды:
//!   • /link                      — запросить код привязки в ЛС бота
//!   • /link <код>                — ввести код привязки (приходит от бота)
//!   • /tfa on                    — включить подтверждение входа через ТГ
//!   • /tfa off                   — отключить подтверждение входа (привязка остаётся)
//!   • /tfa status                — статус привязки и 2FA
//!
//! Поток:
//!   1. Игрок пишет /link в игре → бот присылает в ЛС: "Привязка {nick}. Код: XXXXXX. Введите /link XXXXXX в игре"
//!   2. Игрок пишет /link XXXXXX в игре → аккаунт привязан к chat_id
//!   3. При входе с привязанным ТГ и включённым 2FA → бот шлёт: "Вход {nick} с IP. Подтвердить? /da /net"
//!   4. Игрок пишет /da или /net в боте → вход разрешён/запрещён
//!   5. /tfa off — отключает требуемое подтверждение, но привязка chat_id остаётся

use anyhow::{bail, Result};
use dashmap::DashMap;
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Код привязки (ожидает ввода в игре).
#[derive(Debug, Clone)]
pub struct LinkCode {
    pub chat_id: i64,
    pub code: String,
    pub username: String,
    pub expires_at: Instant,
}

/// Подтверждение входа (ожидает ответа в боте).
#[derive(Debug, Clone)]
pub struct LoginConfirm {
    pub player_uuid: Uuid,
    pub username: String,
    pub ip: IpAddr,
    pub chat_id: i64,
    pub expires_at: Instant,
}

/// Данные привязки аккаунта.
#[derive(Debug, Clone)]
pub struct AccountTfa {
    pub username: String,
    pub chat_id: Option<i64>,
    pub tfa_enabled: bool, // требуется ли подтверждение входа
}

impl AccountTfa {
    pub fn new(username: String) -> Self {
        Self { username, chat_id: None, tfa_enabled: false }
    }
}

/// Менеджер TFA.
pub struct TfaManager {
    /// username → AccountTfa
    pub accounts: DashMap<String, AccountTfa>,
    /// код → LinkCode (ожидает ввода в игре)
    pub link_codes: DashMap<String, LinkCode>,
    /// player_uuid → LoginConfirm (ожидает ответа в боте)
    pub login_confirms: DashMap<Uuid, LoginConfirm>,
    /// chat_id → player_uuid (обратный поиск для команд бота)
    pub chat_to_player: DashMap<i64, Uuid>,
    pub bot_token: String,
    pub client: Client,
    pub code_ttl: Duration,
    pub confirm_ttl: Duration,
    pub offset: i64, // последний обработанный update_id
}

impl TfaManager {
    pub fn new(bot_token: String) -> Result<Self> {
        Ok(Self {
            accounts: DashMap::new(),
            link_codes: DashMap::new(),
            login_confirms: DashMap::new(),
            chat_to_player: DashMap::new(),
            bot_token,
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            code_ttl: Duration::from_minutes(10),
            confirm_ttl: Duration::from_minutes(3),
            offset: 0,
        })
    }

    // ═══════════════════════════════════════════════════════════════════
    // ПРИВЯЗКА (инициируется из игры)
    // ═══════════════════════════════════════════════════════════════════

    /// Запросить код привязки. Бот шлёт сообщение в ЛС chat_id.
    pub async fn request_link(&self, chat_id: i64, username: String) -> Result<String> {
        let code: String = (0..6)
            .map(|_| char::from(b'A' + rand::thread_rng().next_u32() % 26))
            .chain((0..2).map(|_| char::from(b'0' + rand::thread_rng().next_u32() % 10)))
            .collect();

        let link = LinkCode {
            chat_id,
            code: code.clone(),
            username: username.clone(),
            expires_at: Instant::now() + self.code_ttl,
        };
        self.link_codes.insert(code.clone(), link);

        let text = format!(
            "🔗 <b>Привязка Telegram к RustProxy</b>\n\n\
             Игрок: <b>{}</b>\n\
             Код привязки: <code>{}</code>\n\n\
             Введите в игре: <b>/link {}</b>\n\
             Код действителен 10 минут.",
            username, code, code
        );
        self.send_tg_message(chat_id, &text).await?;

        Ok(code)
    }

    /// Проверить код привязки (вводится в игре: /link <код>).
    pub fn verify_link(&self, code: &str, player_uuid: Uuid, username: &str) -> Result<i64> {
        if let Some(link) = self.link_codes.get(code) {
            if Instant::now() > link.expires_at {
                self.link_codes.remove(code);
                bail!("Код привязки истёк. Запросите новый через /link.");
            }
            if link.username != username {
                bail!("Код не belongs к этому аккаунту.");
            }
            let chat_id = link.chat_id;
            self.link_codes.remove(code);

            // Сохраняем привязку
            self.accounts.entry(username.to_string()).or_insert_with(|| AccountTfa::new(username.to_string()));
            if let Some(mut acc) = self.accounts.get_mut(username) {
                acc.chat_id = Some(chat_id);
                acc.tfa_enabled = false; // по умолчанию 2FA выключен после привязки
            }
            self.chat_to_player.insert(chat_id, player_uuid);

            Ok(chat_id)
        } else {
            bail!("Неверный код привязки. Запросите новый через /link.")
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // ПОДТВЕРЖДЕНИЕ ВХОДА (2FA — инициируется прокси при входе)
    // ═══════════════════════════════════════════════════════════════════

    /// Запросить подтверждение входа. Бот шлёт сообщение в ЛС chat_id.
    pub async fn request_login_confirm(&self, player_uuid: Uuid, username: &str, ip: IpAddr, chat_id: i64) -> Result<()> {
        let confirm = LoginConfirm {
            player_uuid,
            username: username.to_string(),
            ip,
            chat_id,
            expires_at: Instant::now() + self.confirm_ttl,
        };
        self.login_confirms.insert(player_uuid, confirm);

        let text = format!(
            "🚪 <b>Вход в игру RustProxy</b>\n\n\
             Игрок: <b>{}</b>\n\
             IP: <code>{}</code>\n\n\
             Подтвердить вход?\n\
             Напишите <b>/da</b> — разрешить\n\
             Напишите <b>/net</b> — отклонить\n\
             (запрос действует 3 минуты)",
            username, ip
        );
        self.send_tg_message(chat_id, &text).await
    }

    /// Обработать ответ из бота (/da или /net).
    pub fn handle_bot_response(&self, chat_id: i64, text: &str) -> Result<Option<Uuid>> {
        let text = text.trim();

        // Ищем подтверждение входа для этого chat_id
        let confirm = self.login_confirms.iter()
            .find(|c| c.value().chat_id == chat_id)
            .map(|c| c.value().clone());

        if let Some(confirm) = confirm {
            if Instant::now() > confirm.expires_at {
                self.login_confirms.remove(&confirm.player_uuid);
                bail!("Запрос на вход истёк.");
            }

            match text {
                "/da" | "/yes" | "/д" => {
                    let uuid = confirm.player_uuid;
                    self.login_confirms.remove(&uuid);
                    return Ok(Some(uuid)); // вход разрешён
                }
                "/net" | "/no" | "/н" => {
                    let uuid = confirm.player_uuid;
                    self.login_confirms.remove(&uuid);
                    bail!("Вход отклонён через Telegram.");
                }
                _ => {}
            }
        }

        Ok(None) // не нашли подтверждение или неизвестная команда
    }

    /// Проверка, требуется ли 2FA для этого игрока.
    pub fn requires_tfa(&self, username: &str) -> bool {
        self.accounts.get(username)
            .map(|a| a.tfa_enabled)
            .unwrap_or(false)
    }

    /// Включить/выключить 2FA.
    pub fn toggle_tfa(&self, username: &str, enable: bool) -> Result<()> {
        if let Some(mut acc) = self.accounts.get_mut(username) {
            acc.tfa_enabled = enable;
            Ok(())
        } else {
            bail!("Аккаунт не найден. Привяжите Telegram через /link.")
        }
    }

    pub fn get_chat_id(&self, username: &str) -> Option<i64> {
        self.accounts.get(username).map(|a| a.chat_id).flatten()
    }

    pub fn is_linked(&self, username: &str) -> bool {
        self.accounts.get(username)
            .map(|a| a.chat_id.is_some())
            .unwrap_or(false)
    }

    // ═══════════════════════════════════════════════════════════════════
    // TELEGRAM BOT API (polling)
    // ═══════════════════════════════════════════════════════════════════

    /// Опросить обновления от бота (getUpdates).
    pub async fn poll_updates(&mut self) -> Result<Vec<TgUpdate>> {
        let url = format!(
            "https://api.telegram.org/bot{}/getUpdates?offset={}&limit=100&timeout=2",
            self.bot_token, self.offset + 1
        );
        let resp: TgUpdatesResponse = self.client.get(&url).send().await?.json().await?;

        let mut updates = Vec::new();
        for upd in resp.result {
            self.offset = upd.update_id;
            if let Some(msg) = upd.message {
                if let Some(text) = msg.text {
                    updates.push(TgUpdate {
                        chat_id: msg.chat.id,
                        text,
                    });
                }
            }
        }
        Ok(updates)
    }

    /// Отправить сообщение через Bot API.
    pub async fn send_tg_message(&self, chat_id: i64, text: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        });
        self.client.post(&url).json(&payload).send().await?;
        Ok(())
    }

    /// Очистка просроченных кодов и подтверждений (фоновая задача).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.link_codes.retain(|_, c| now < c.expires_at);
        self.login_confirms.retain(|_, c| now < c.expires_at);
    }
}

/// Обновление от Telegram Bot API.
#[derive(Debug, Clone)]
pub struct TgUpdate {
    pub chat_id: i64,
    pub text: String,
}

#[derive(Debug, Deserialize)]
struct TgUpdatesResponse {
    ok: bool,
    result: Vec<TgUpdateRaw>,
}

#[derive(Debug, Deserialize)]
struct TgUpdateRaw {
    update_id: i64,
    message: Option<TgMessageRaw>,
}

#[derive(Debug, Deserialize)]
struct TgMessageRaw {
    chat: TgChatRaw,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgChatRaw {
    id: i64,
}

impl Default for TfaManager {
    fn default() -> Self {
        Self::new("BOT_TOKEN_PLACEHOLDER".to_string()).unwrap()
    }
}
