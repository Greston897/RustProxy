//! # Telegram Two-Factor Authentication (TFA) — стиль tiAuth / NullCordX
//!
//! Поток:
//!   1. /link в игре → бот шлёт в ЛС multiline-сообщение с кодом привязки
//!   2. /link <код> в игре → аккаунт привязан к chat_id
//!   3. При входе с привязанным ТГ и включённым 2FA → бот шлёт сообщение
//!      с INLINE-КНОПКАМИ ✅ Разрешить / ❌ Запретить (callback_query, как в tiAuth)
//!   4. Нажатие кнопки в боте → вход разрешён/запрещён (игроку в чат приходит ответ)
//!   5. /tfa off — отключает требуемое подтверждение, привязка chat_id остаётся

use anyhow::{bail, Result};
use dashmap::DashMap;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Код привязки (ожидает ввода в игре: /link <код>).
#[derive(Debug, Clone)]
pub struct LinkCode {
    pub chat_id: i64,
    pub code: String,
    pub username: String,
    pub expires_at: Instant,
}

/// Подтверждение входа (ожидает ответа в боте — кнопки или /da /net).
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

/// Обновление от Telegram Bot API (сообщение или нажатие inline-кнопки).
#[derive(Debug, Clone)]
pub struct TgUpdate {
    pub chat_id: i64,
    pub text: String,
    pub callback_query: Option<TgCallbackQuery>,
}

/// Нажатие inline-кнопки.
#[derive(Debug, Clone)]
pub struct TgCallbackQuery {
    pub id: String,
    pub chat_id: i64,
    pub data: String,
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
    callback_query: Option<TgCallbackQueryRaw>,
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

#[derive(Debug, Deserialize)]
struct TgCallbackQueryRaw {
    id: String,
    message: Option<TgCallbackMessageRaw>,
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgCallbackMessageRaw {
    chat: TgChatRaw,
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
            code_ttl: Duration::from_secs(600),
            confirm_ttl: Duration::from_secs(180),
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
            "🔗 <b>Привязка Telegram к RustProxy</b>\n\n\n             Игрок: <b>{}</b>\n\n             Код привязки: <code>{}</code>\n\n             Введите в игре: <b>/link {}</b>\n\n             Код действителен 10 минут.",
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
                bail!("Код не принадлежит этому аккаунту.");
            }
            let chat_id = link.chat_id;
            self.link_codes.remove(code);

            // chat_id не должен быть привязан к другому аккаунту
            if self.accounts.iter().any(|a| a.value().chat_id == Some(chat_id)) {
                bail!("Этот Telegram уже привязан к другому аккаунту.");
            }

            self.accounts.entry(username.to_string()).or_insert_with(|| AccountTfa::new(username.to_string()));
            if let Some(mut acc) = self.accounts.get_mut(username) {
                acc.chat_id = Some(chat_id);
                acc.tfa_enabled = false;
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

    /// Запросить подтверждение входа. Бот шлёт сообщение с inline-кнопками ✅ / ❌.
    pub async fn request_login_confirm(&self, player_uuid: Uuid, username: &str, ip: IpAddr, chat_id: i64) -> Result<()> {
        // chat_id должен быть привязан к этому аккаунту
        let acc = self.accounts.get(username).ok_or_else(|| anyhow::anyhow!("Аккаунт не привязан к Telegram"))?;
        if acc.chat_id != Some(chat_id) {
            bail!("Этот chat_id не привязан к аккаунту {}.", username);
        }

        let confirm = LoginConfirm {
            player_uuid,
            username: username.to_string(),
            ip,
            chat_id,
            expires_at: Instant::now() + self.confirm_ttl,
        };
        self.login_confirms.insert(player_uuid, confirm);

        let text = format!(
            "🚪 <b>Вход в игру RustProxy</b>\n\n\n             Игрок: <b>{}</b>\n\n             IP: <code>{}</code>\n\n             Подтвердить вход?",
            username, ip
        );

        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Разрешить", "callback_data": format!("da:{}", player_uuid)},
                    {"text": "❌ Запретить", "callback_data": format!("net:{}", player_uuid)}
                ]]
            }
        });
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        self.client.post(&url).json(&payload).send().await?;
        Ok(())
    }

    /// Обработать ответ из бота (текст /da /net или нажатие inline-кнопки).
    pub fn handle_bot_response(&self, chat_id: i64, text: &str, callback_data: Option<&str>) -> Result<Option<Uuid>> {
        // 1. Инлайн-кнопка (callback_query)
        if let Some(data) = callback_data {
            if let Some((action, uuid_str)) = data.split_once(':') {
                if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                    let confirm = self.login_confirms.get(&uuid).map(|c| c.value().clone());
                    if let Some(confirm) = confirm {
                        if Instant::now() > confirm.expires_at {
                            self.login_confirms.remove(&uuid);
                            bail!("Запрос на вход истёк.");
                        }
                        match action {
                            "da" => {
                                self.login_confirms.remove(&uuid);
                                return Ok(Some(uuid)); // вход разрешён
                            }
                            "net" => {
                                self.login_confirms.remove(&uuid);
                                bail!("Вход отклонён через Telegram.");
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // 2. Текстовые команды /da /net (обратная совместимость)
        let text = text.trim();
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
                    return Ok(Some(uuid));
                }
                "/net" | "/no" | "/н" => {
                    let uuid = confirm.player_uuid;
                    self.login_confirms.remove(&uuid);
                    bail!("Вход отклонён через Telegram.");
                }
                _ => {}
            }
        }

        Ok(None)
    }

    /// Ответить на callback_query (убрать часики загрузки у кнопки).
    pub async fn answer_callback_query(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let payload = json!({
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": false
        });
        let url = format!("https://api.telegram.org/bot{}/answerCallbackQuery", self.bot_token);
        self.client.post(&url).json(&payload).send().await?;
        Ok(())
    }

    /// Отправить игроку в ЛС результат подтверждения.
    pub async fn send_login_result(&self, chat_id: i64, username: &str, allowed: bool) -> Result<()> {
        let text = if allowed {
            format!("✅ Вход для <b>{}</b> разрешён. Можете заходить на сервер.", username)
        } else {
            format!("❌ Вход для <b>{}</b> отклонён.", username)
        };
        self.send_tg_message(chat_id, &text).await
    }

    /// Проверка, требуется ли 2FA для этого игрока.
    pub fn requires_tfa(&self, username: &str) -> bool {
        self.accounts.get(username).map(|a| a.tfa_enabled).unwrap_or(false)
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
        self.accounts.get(username).map(|a| a.chat_id.is_some()).unwrap_or(false)
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
            let mut text = String::new();
            let mut cb = None;

            if let Some(msg) = upd.message {
                if let Some(t) = msg.text {
                    text = t;
                }
            }
            if let Some(cqr) = upd.callback_query {
                if let Some(chat) = cqr.message.and_then(|m| Some(m.chat.id)) {
                    cb = Some(TgCallbackQuery { id: cqr.id, chat_id: chat, data: cqr.data.unwrap_or_default() });
                }
                if text.is_empty() {
                    text = cqr.data.unwrap_or_default();
                }
            }

            if !text.is_empty() || cb.is_some() {
                let chat_id = cb.as_ref().map(|c| c.chat_id).unwrap_or_else(|| {
                    upd.message.as_ref().map(|m| m.chat.id).unwrap_or(0)
                });
                updates.push(TgUpdate { chat_id, text, callback_query: cb });
            }
        }
        Ok(updates)
    }

    /// Отправить сообщение через Bot API.
    pub async fn send_tg_message(&self, chat_id: i64, text: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let payload = json!({
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

impl Default for TfaManager {
    fn default() -> Self {
        Self::new("BOT_TOKEN_PLACEHOLDER".to_string()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn link_code_flow() {
        let mgr = TfaManager::new("token".to_string()).unwrap();
        let uuid = Uuid::new_v4();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        mgr.accounts.insert("player".to_string(), AccountTfa::new("player".to_string()));
        assert!(mgr.verify_link("AAAAAA", uuid, "player").is_err()); // неверный код
    }
}
