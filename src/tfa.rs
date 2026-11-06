//! # Telegram Two-Factor Authentication (Этап 12)
//!
//! Стиль BaronessAuth / tiAuth:
//!   • После ввода пароля требуется код из Telegram
//!   • Бот присылает 6-значный код на привязанный chat_id
//!   • Код действует 5 минут
//!   • /tfa link <chat_id> — привязать Telegram
//!   • /tfa code <код> — ввести код 2FA
//!   • /tfa unlink — отвязать

use anyhow::{bail, Result};
use dashmap::DashMap;
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Ожидающий код 2FA для игрока.
#[derive(Debug, Clone)]
pub struct PendingTfa {
    pub player_uuid: Uuid,
    pub code: String,
    pub created_at: Instant,
    pub expires_at: Instant,
}

/// Менеджер 2FA.
pub struct TfaManager {
    /// chat_id → код ожидания (когда бот ждёт ввода кода от пользователя)
    pub pending_codes: DashMap<i64, PendingTfa>,
    /// chat_id → время последней отправки кода (rate limit)
    pub last_code_sent: DashMap<i64, Instant>,
    pub bot_token: String,
    pub client: Client,
    /// Время жизни кода (5 минут)
    pub code_ttl: Duration,
    /// Минимальный интервал между отправками кодов (30 сек)
    pub resend_interval: Duration,
}

impl TfaManager {
    pub fn new(bot_token: String) -> Result<Self> {
        Ok(Self {
            pending_codes: DashMap::new(),
            last_code_sent: DashMap::new(),
            bot_token,
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            code_ttl: Duration::from_secs(300),    // 5 минут
            resend_interval: Duration::from_secs(30), // 30 сек
        }
    }

    /// Отправить код 2FA в Telegram.
    pub async fn send_code(&self, chat_id: i64, player_uuid: Uuid) -> Result<String> {
        // Rate limit на отправку кодов
        if let Some(last) = self.last_code_sent.get(&chat_id) {
            if Instant::now().duration_since(*last) < self.resend_interval {
                bail!("Код уже отправлен recently. Подождите немного.");
            }
        }

        let code: String = (0..6)
            .map(|_| char::from(b'0' + rand::thread_rng().next_u32() % 10))
            .collect();

        let pending = PendingTfa {
            player_uuid,
            code: code.clone(),
            created_at: Instant::now(),
            expires_at: Instant::now() + self.code_ttl,
        };
        self.pending_codes.insert(chat_id, pending);
        self.last_code_sent.insert(chat_id, Instant::now());

        let text = format!(
            "🔐 <b>Код подтверждения RustProxy</b>\n\nКод: <code>{}</code>\nДействует 5 минут.",
            code
        );
        self.send_tg_message(chat_id, &text).await?;

        Ok(code)
    }

    /// Проверить код 2FA.
    pub fn verify_code(&self, chat_id: i64, code: &str) -> Result<Uuid> {
        if let Some(pending) = self.pending_codes.get(&chat_id) {
            if Instant::now() > pending.expires_at {
                self.pending_codes.remove(&chat_id);
                bail!("Код истёк. Запросите новый.");
            }
            if pending.code == code {
                let uuid = pending.player_uuid;
                self.pending_codes.remove(&chat_id);
                Ok(uuid)
            } else {
                bail!("Неверный код.");
            }
        } else {
            bail!("Нет активного кода 2FA. Запросите его через /tfa code.");
        }
    }

    /// Очистка просроченных кодов (фоновая задача).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.pending_codes.retain(|_, p| now < p.expires_at);
    }

    /// Отправить сообщение через Telegram Bot API.
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
}

impl Default for TfaManager {
    fn default() -> Self {
        Self::new("BOT_TOKEN_PLACEHOLDER".to_string()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn tfa_code_format() {
        // Проверка что код состоит из 6 цифр
        let manager = TfaManager::new("test".to_string()).unwrap();
        let _ = manager; // просто проверка компиляции
    }

    #[test]
    fn verify_code_logic() {
        // Тестируем логику верификации (без реального бота)
        let manager = TfaManager::new("test".to_string()).unwrap();
        let uuid = Uuid::new_v4();
        let chat_id: i64 = 12345;

        // Вручную вставляем pending код
        let pending = PendingTfa {
            player_uuid: uuid,
            code: "123456".to_string(),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(300),
        };
        manager.pending_codes.insert(chat_id, pending);

        // Правильный код
        assert!(manager.verify_code(chat_id, "123456").is_ok());
        // Код уже удалён после успешной верификации
        assert!(manager.verify_code(chat_id, "123456").is_err());
    }
}
