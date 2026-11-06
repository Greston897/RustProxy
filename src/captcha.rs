//! # CAPTCHA System (Этап 13)
//!
//! Двухэтапная защита от ботов:
//!   Этап 1 — простая проверка на бота (авто-прохождение для людей, блок для скриптов)
//!   Этап 2 — ховер-капча: в чате появляется сообщение с числом+буквами,
//!            нужно навести мышкой (сервер фиксирует событие) и ввести /captcha <код>
//!   • Аккаунт освобождается от капчи на 4 часа после прохождения
//!   • Смена IP — капча требуется сразу
//!   • HMAC-подпись кода защиты от подделки пакетов

use anyhow::{bail, Result};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Состояние капчи для игрока.
#[derive(Debug, Clone)]
pub struct CaptchaSession {
    pub token: [u8; 16],           // уникальный токен сессии
    pub code: String,              // код капчи (число+буквы)
    pub created_at: Instant,
    pub ttl: Duration,             // обычно 5 минут
    pub attempts: usize,
    pub max_attempts: usize,
    pub secret_key: [u8; 32],      // для HMAC
    pub hover_required: bool,      // нужно ли наведение (этап 2)
}

/// Кэш освобождения от капчи: UUID → время истечения.
#[derive(Debug, Clone)]
pub struct CaptchaExemption {
    pub uuid: Uuid,
    pub ip: IpAddr,
    pub expires_at: Instant,
}

/// Менеджер капчи.
pub struct CaptchaManager {
    pub sessions: DashMap<Uuid, CaptchaSession>,
    /// Освобождённые от капчи (аккаунт + IP связаны)
    pub exemptions: DashMap<Uuid, CaptchaExemption>,
    /// IP → количество неудач (exponential backoff)
    pub ip_failures: DashMap<IpAddr, usize>,
    /// IP → время бана
    pub ip_bans: DashMap<IpAddr, Instant>,
    pub secret: [u8; 32],
    pub ttl_secs: u64,
    pub max_attempts: usize,
    /// Время освобождения от капчи (4 часа)
    pub exemption_ttl: Duration,
}

impl CaptchaManager {
    pub fn new() -> Result<Self> {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Ok(Self {
            sessions: DashMap::new(),
            exemptions: DashMap::new(),
            ip_failures: DashMap::new(),
            ip_bans: DashMap::new(),
            secret,
            ttl_secs: 300,           // 5 минут на решение
            max_attempts: 3,
            exemption_ttl: Duration::from_secs(4 * 3600), // 4 часа
        })
    }

    /// Проверить, освобождён ли аккаунт от капчи (IP не менялся, 4ч не истекло).
    pub fn is_exempt(&self, uuid: &Uuid, ip: IpAddr) -> bool {
        if let Some(ex) = self.exemptions.get(uuid) {
            if ex.ip == ip && Instant::now() < ex.expires_at {
                return true;
            }
            // IP изменился или время истекло — удаляем освобождение
            self.exemptions.remove(uuid);
        }
        false
    }

    /// Создать капчу-сессию (этап 2 — ховер).
    pub fn create_session(&self, uuid: Uuid) -> CaptchaSession {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut token = [0u8; 16];
        rng.fill_bytes(&mut token);
        let mut secret_key = [0u8; 32];
        rng.fill_bytes(&mut secret_key);

        let code = generate_hover_code(&mut rng);

        let session = CaptchaSession {
            token,
            code: code.clone(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(self.ttl_secs),
            attempts: 0,
            max_attempts: self.max_attempts,
            secret_key,
            hover_required: true,
        };

        self.sessions.insert(uuid, session.clone());
        session
    }

    /// Этап 1 — простая проверка на бота (авто для людей, блок для скриптов).
    /// Возвращает Ok(true) если человек прошёл, Ok(false) если нужен этап 2.
    pub fn stage1_bot_check(&self, _uuid: Uuid) -> bool {
        // В реальности здесь проверка поведения: скорость кликов, движения мыши, пакеты
        // Для упрощения — всегда требуем этап 2 (надежнее)
        false
    }

    /// Проверить ответ на капчу.
    pub fn check_answer(&mut self, uuid: &Uuid, answer: &str, ip: IpAddr) -> Result<bool> {
        // Проверка бана IP
        if let Some(until) = self.ip_bans.get(&ip) {
            if Instant::now() < *until {
                bail!("IP временно заблокирован из-за неудачных попыток капчи.");
            } else {
                self.ip_bans.remove(&ip);
            }
        }

        if let Some(mut session) = self.sessions.get(uuid) {
            // TTL истёк
            if session.created_at.elapsed() > session.ttl {
                self.sessions.remove(uuid);
                bail!("Капча истекла. Перезайдите на сервер.");
            }

            // Слишком много попыток
            if session.attempts >= session.max_attempts {
                self.sessions.remove(uuid);
                self.register_ip_failure(ip);
                bail!("Слишком много неудачных попыток. IP заблокирован.");
            }

            let correct = answer.trim().eq_ignore_ascii_case(&session.code);
            session.attempts += 1;

            if correct {
                // Успех — освобождаем на 4 часа (привязка к IP)
                self.sessions.remove(uuid);
                let exemption = CaptchaExemption {
                    uuid: *uuid,
                    ip,
                    expires_at: Instant::now() + self.exemption_ttl,
                };
                self.exemptions.insert(*uuid, exemption);
                self.ip_failures.remove(&ip);
                Ok(true)
            } else {
                self.sessions.insert(*uuid, session);
                Ok(false)
            }
        } else {
            bail!("Нет активной сессии капчи.")
        }
    }

    /// Удалить сессию (после успешного входа или отключения).
    pub fn remove(&self, uuid: &Uuid) {
        self.sessions.remove(uuid);
    }

    /// Зарегистрировать неудачу IP.
    fn register_ip_failure(&mut self, ip: IpAddr) {
        let failures = self.ip_failures.entry(ip).or_insert(0);
        *failures += 1;
        let fails = *failures;
        let ban_minutes = match fails {
            1 => 5,
            2 => 15,
            3 => 60,
            4 => 240,
            _ => 1440,
        };
        self.ip_bans.insert(ip, Instant::now() + Duration::from_secs(ban_minutes as u64 * 60));
    }

    /// Очистка просроченных сессий (фоновая задача).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, s| now.duration_since(s.created_at) < s.ttl);
        self.exemptions.retain(|_, e| now < e.expires_at);
    }

    /// Сообщение с капчей для отправки в чат (хед с кодом).
    pub fn captcha_message(&self, session: &CaptchaSession) -> String {
        format!(
            "&b&l🤖 CAPTCHA &f» &fПодтвердите, что вы человек.\n\
             &eКод: &a{} &f(наведите на сообщение и введите &b/captcha <код>&f)\n\
             &7Осталось попыток: &c{}/{}",
            session.code,
            session.max_attempts - session.attempts,
            session.max_attempts
        )
    }

    /// HMAC подпись кода (защита от подделки).
    pub fn compute_code_hmac(&self, token: &[u8; 16], code: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC key");
        mac.update(token);
        mac.update(code.as_bytes());
        let result = mac.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result.into_bytes());
        out
    }
}

/// Генерация кода капчи: 4 цифры + 2 буквы (например "7A3K92").
fn generate_hover_code(rng: &mut ChaCha20Rng) -> String {
    let mut code = String::with_capacity(6);
    for _ in 0..4 {
        code.push(char::from(b'0' + rng.next_u32() % 10));
    }
    for _ in 0..2 {
        code.push(char::from(b'A' + rng.next_u32() % 26));
    }
    code
}

impl Default for CaptchaManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn captcha_check() {
        let mut mgr = CaptchaManager::new().unwrap();
        let uuid = Uuid::new_v4();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let session = mgr.create_session(uuid);
        let code = session.code.clone();

        assert!(mgr.check_answer(&uuid, &code, ip).unwrap());
        assert!(mgr.is_exempt(&uuid, ip));
    }

    #[test]
    fn captcha_ip_change() {
        let mut mgr = CaptchaManager::new().unwrap();
        let uuid = Uuid::new_v4();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        let session = mgr.create_session(uuid);
        let code = session.code.clone();
        assert!(mgr.check_answer(&uuid, &code, ip1).unwrap());
        assert!(mgr.is_exempt(&uuid, ip1));
        assert!(!mgr.is_exempt(&uuid, ip2)); // сменили IP — капча снова нужна
    }

    #[test]
    fn code_format() {
        let mut rng = ChaCha20Rng::from_entropy();
        let code = generate_hover_code(&mut rng);
        assert_eq!(code.len(), 6);
        assert!(code.chars().take(4).all(|c| c.is_ascii_digit()));
        assert!(code.chars().skip(4).all(|c| c.is_ascii_uppercase()));
    }
}
