//! # Система авторизации (Этап 12)
//!
//! Простая и надёжная, как BaronessAuth / tiAuth:
//!   • /register <пароль>  (алиас /reg)
//!   • /login <пароль>     (алиас /l)
//!   • Кэш по IP: если IP не менялся — 1 час до повторного ввода пароля
//!   • Если IP сменился — пароль запрашивается сразу
//!   • Аккаунты хранятся в памяти (DashMap) + опционально файл
//!   • SHA-256 с солью для паролей

use anyhow::{bail, Result};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Профиль игрока (Mojang-стиль).
#[derive(Debug, Clone)]
pub struct PlayerProfile {
    pub uuid: Uuid,
    pub username: String,
    pub properties: Vec<String>,
}

/// Сессия игрока.
#[derive(Debug, Clone)]
pub struct Session {
    pub profile: PlayerProfile,
    pub access_token: Option<String>,
}

/// Данные аккаунта игрока.
#[derive(Debug, Clone)]
pub struct Account {
    pub uuid: Uuid,
    pub username: String,
    pub password_hash: String,
    pub salt: String,
    pub created_at: Instant,
    pub last_login: Option<Instant>,
    pub last_ip: Option<IpAddr>,
    pub total_logins: u32,
    /// Telegram chat_id для 2FA (опционально)
    pub tg_chat_id: Option<i64>,
    /// 2FA включён?
    pub tfa_enabled: bool,
}

impl Account {
    pub fn new(username: String, password: &str) -> Self {
        let salt = generate_salt();
        let password_hash = hash_password(password, &salt);
        Self {
            uuid: Uuid::new_v4(),
            username,
            password_hash,
            salt,
            created_at: Instant::now(),
            last_login: None,
            last_ip: None,
            total_logins: 0,
            tg_chat_id: None,
            tfa_enabled: false,
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        self.password_hash == hash_password(password, &self.salt)
    }

    pub fn enable_tfa(&mut self, chat_id: i64) {
        self.tg_chat_id = Some(chat_id);
        self.tfa_enabled = true;
    }

    pub fn disable_tfa(&mut self) {
        self.tg_chat_id = None;
        self.tfa_enabled = false;
    }
}

/// Кэш авторизации по IP (избегаем повторного ввода пароля).
#[derive(Debug, Clone)]
pub struct AuthCacheEntry {
    pub account_username: String,
    pub player_uuid: Uuid,
    pub ip: IpAddr,
    pub authenticated_at: Instant,
    pub expires_at: Instant,
}

/// Менеджер авторизации.
pub struct AuthManager {
    /// username → Account
    pub accounts: DashMap<String, Account>,
    /// IP → кэш авторизации (кто вошёл с этого IP и когда истекает)
    pub ip_cache: DashMap<IpAddr, AuthCacheEntry>,
    /// UUID → username (быстрый обратный поиск)
    pub uuid_to_username: DashMap<Uuid, String>,
    /// Время кэша авторизации (по умолчанию 1 час)
    pub cache_ttl: Duration,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            accounts: DashMap::new(),
            ip_cache: DashMap::new(),
            uuid_to_username: DashMap::new(),
            cache_ttl: Duration::from_secs(3600), // 1 час по умолчанию
        }
    }

    /// Установить TTL кэша IP (из конфига).
    pub fn set_cache_ttl(&mut self, ttl_secs: u64) {
        self.cache_ttl = Duration::from_secs(ttl_secs);
    }

    /// Зарегистрировать аккаунт.
    pub fn register(&self, username: &str, password: &str) -> Result<Uuid> {
        if self.accounts.contains_key(username) {
            bail!("Аккаунт с таким ником уже существует.");
        }
        if username.len() < 3 || username.len() > 16 {
            bail!("Ник должен быть от 3 до 16 символов.");
        }
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            bail!("Ник может содержать только буквы, цифры и подчёркивание.");
        }
        if password.len() < 4 {
            bail!("Пароль должен быть не короче 4 символов.");
        }

        let account = Account::new(username.to_string(), password);
        let uuid = account.uuid;
        self.accounts.insert(username.to_string(), account);
        self.uuid_to_username.insert(uuid, username.to_string());
        Ok(uuid)
    }

    /// Войти по паролю. Возвращает Ok если пароль верный.
    pub fn login(&self, username: &str, password: &str, player_uuid: Uuid, ip: IpAddr) -> Result<()> {
        let account = self
            .accounts
            .get(username)
            .ok_or_else(|| anyhow::anyhow!("Аккаунт не найден. Используйте /reg <пароль>"))?;

        if !account.verify_password(password) {
            bail!("Неверный пароль.");
        }

        // Проверка 2FA
        if account.tfa_enabled {
            // 2FA проверка происходит отдельно через tfa модуль
            // Здесь только помечаем, что нужен 2FA
            bail!("Требуется подтверждение через Telegram (2FA). Используйте /tfa <код>");
        }

        // Обновляем кэш по IP
        let entry = AuthCacheEntry {
            account_username: username.to_string(),
            player_uuid,
            ip,
            authenticated_at: Instant::now(),
            expires_at: Instant::now() + self.cache_ttl,
        };
        self.ip_cache.insert(ip, entry);

        // Обновляем аккаунт
        if let Some(mut acc) = self.accounts.get_mut(username) {
            acc.last_login = Some(Instant::now());
            acc.last_ip = Some(ip);
            acc.total_logins += 1;
        }

        Ok(())
    }

    /// Проверить, авторизован ли игрок с этого IP (кэш).
    /// Возвращает (username, uuid) если кэш валиден, None если нужно логиньться заново.
    pub fn check_ip_auth(&self, ip: IpAddr) -> Option<(String, Uuid)> {
        if let Some(entry) = self.ip_cache.get(&ip) {
            if Instant::now() < entry.expires_at {
                return Some((entry.account_username.clone(), entry.player_uuid));
            } else {
                // Кэш истёк — удаляем
                self.ip_cache.remove(&ip);
            }
        }
        None
    }

    /// Удалить кэш по IP (например, при смене IP или выходе).
    pub fn invalidate_ip(&self, ip: &IpAddr) {
        self.ip_cache.remove(ip);
    }

    /// Инвалидировать весь кэш для игрока (при смене IP).
    pub fn invalidate_player(&self, uuid: &Uuid) {
        if let Some(username) = self.uuid_to_username.get(uuid) {
            let username = username.clone();
            // Удаляем все кэш-записи для этого аккаунта
            self.ip_cache.retain(|_, entry| entry.account_username != username);
        }
    }

    /// Получить аккаунт по нику.
    pub fn get_account(&self, username: &str) -> Option<Account> {
        self.accounts.get(username).map(|e| e.clone())
    }

    /// Сбросить регистрацию аккаунта (удаляет аккаунт完全).
    pub fn reset_account(&self, username: &str) -> Result<()> {
        if !self.accounts.contains_key(username) {
            bail!(\"Аккаунт не найден.\");
        }
        self.accounts.remove(username);
        // Удаляем обратную связь UUID→username
        let uuid_opt = self.uuid_to_username.iter().find(|e| e.value() == username).map(|e| *e.key());
        if let Some(uuid) = uuid_opt {
            self.uuid_to_username.remove(&uuid);
        }
        Ok(())
    }

    /// Сменить пароль аккаунту (команда /auth player <ник> password <пароль>).
    pub fn set_password(&self, username: &str, new_password: &str) -> Result<()> {
        if new_password.len() < 4 {
            bail!("Пароль должен быть не короче 4 символов.");
        }
        if let Some(mut acc) = self.accounts.get_mut(username) {
            acc.password_hash = hash_password(new_password, &acc.salt);
            Ok(())
        } else {
            bail!("Аккаунт не найден.")
        }
    }

    /// Проверка существования аккаунта.
    pub fn account_exists(&self, username: &str) -> bool {
        self.accounts.contains_key(username)
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Очистка просроченного кэша IP (фоновая задача).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.ip_cache.retain(|_, e| now < e.expires_at);
    }
}

/// Офлайн-UUID игрока (NAMESPACE_DNS от "OfflinePlayer:<ник>").
pub fn offline_uuid(username: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, format!("OfflinePlayer:{}", username).as_bytes())
}

/// Генерация случайной соли.
fn generate_salt() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("{:x}", buf)
}

/// Хеш пароля: SHA-256(salt + password).
fn hash_password(password: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn register_and_login() {
        let am = AuthManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let uuid = Uuid::new_v4();

        assert!(am.register("testplayer", "password123").is_ok());
        assert!(am.login("testplayer", "password123", uuid, ip).is_ok());
        assert!(am.check_ip_auth(ip).is_some());
    }

    #[test]
    fn wrong_password() {
        let am = AuthManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let uuid = Uuid::new_v4();

        assert!(am.register("testplayer", "password123").is_ok());
        assert!(am.login("testplayer", "wrongpass", uuid, ip).is_err());
    }

    #[test]
    fn ip_cache_invalidation() {
        let am = AuthManager::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let uuid = Uuid::new_v4();

        assert!(am.register("testplayer", "password123").is_ok());
        assert!(am.login("testplayer", "password123", uuid, ip1).is_ok());
        assert!(am.check_ip_auth(ip1).is_some());
        // Сменили IP — кэш не валиден
        assert!(am.check_ip_auth(ip2).is_none());
    }
}
