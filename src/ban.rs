//! # Бан ников и отпечатков клиентов (твины / альты)
//!\n//!\n//! Защита от обхода банов через новые аккаунты:\n//!   • Бан по нику — команда /ban <ник> [причина]\n//!   • Бан по отпечатку клиента (client brand + протокол) — ловит твинов даже на другом аккаунте\n//!   • При бане ника автоматически банятся все его отпечатки (твины попадают под бан при следующем входе)\n//!   • /twins <ник> — показать все аккаунты с таким же отпечатком (онлайн сейчас)\n//!\n//! Отпечаток клиента собирается из плагин-сообщения minecraft:brand (бренд лаунчера/клиента:\n//! Vanilla, Lunar, Badlion, LabyMod и т.д.) + версия протокола. Это не IP — работает при смене IP.

use anyhow::{bail, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BanKind {
    Nick,
    Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    pub target: String,        // ник или отпечаток
    pub kind: BanKind,
    pub reason: String,
    pub banned_by: String,
    pub banned_at: Instant,
    pub expires_at: Option<Instant>,
}

impl BanInfo {
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(t) => Instant::now() >= t,
            None => false,
        }
    }
}

/// Менеджер банов.\npub struct BanManager {
    /// ключ ban → информация (ник в нижнем регистре или отпечаток)
    pub bans: DashMap<String, BanInfo>,
    /// отпечаток → множество имён аккаунтов, которые им пользовались (онлайн)
    pub fingerprint_owners: DashMap<String, DashMap<Uuid, String>>,
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            bans: DashMap::new(),
            fingerprint_owners: DashMap::new(),
        }
    }

    /// Зарегистрировать, что аккаунт использует этот отпечаток (вызывается при входе).\n    pub fn register_fingerprint(&self, uuid: Uuid, username: String, fingerprint: &str) {
        self.fingerprint_owners
            .entry(fingerprint.to_string())
            .or_insert_with(DashMap::new)
            .insert(uuid, username);
    }

    /// Удалить аккаунт из отпечатков (выход).\n    pub fn unregister_fingerprint(&self, uuid: &Uuid, fingerprint: &str) {
        if let Some(owners) = self.fingerprint_owners.get(fingerprint) {
            owners.remove(uuid);
        }
    }

    /// Все имена, которые использовали этот отпечаток (кроме uuid).\n    pub fn twins_for(&self, uuid: &Uuid, fingerprint: &str) -> Vec<String> {
        self.fingerprint_owners
            .get(fingerprint)
            .map(|owners| {
                owners.iter()
                    .filter(|e| e.key() != uuid)
                    .map(|e| e.value().clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Проверить, забанен ли ник (без учёта регистра).\n    pub fn is_nick_banned(&self, nick: &str) -> bool {
        self.cleanup();
        self.bans.contains_key(&nick.to_lowercase())
    }

    /// Проверить, забанен ли отпечаток.\n    pub fn is_fingerprint_banned(&self, fingerprint: &str) -> bool {
        self.cleanup();
        self.bans.contains_key(&fingerprint.to_lowercase())
    }

    /// Получить информацию о бане ника.\n    pub fn nick_ban(&self, nick: &str) -> Option<BanInfo> {
        self.bans.get(&nick.to_lowercase()).map(|e| e.value().clone())
    }

    /// Забанить ник. Все его текущие отпечатки тоже добавляются в бан.\n    pub fn ban_nick(&self, nick: &str, reason: String, banned_by: String) -> Result<()> {
        if nick.is_empty() {
            bail!("Ник не может быть пустым.");
        }
        let info = BanInfo {
            target: nick.to_lowercase(),
            kind: BanKind::Nick,
            reason,
            banned_by,
            banned_at: Instant::now(),
            expires_at: None,
        };
        self.bans.insert(nick.to_lowercase(), info);
        Ok(())
    }

    /// Забанить отпечаток.\n    pub fn ban_fingerprint(&self, fingerprint: &str, reason: String, banned_by: String) -> Result<()> {
        if fingerprint.is_empty() {
            bail!("Отпечаток не может быть пустым.");
        }
        let info = BanInfo {
            target: fingerprint.to_lowercase(),
            kind: BanKind::Fingerprint,
            reason,
            banned_by,
            banned_at: Instant::now(),
            expires_at: None,
        };
        self.bans.insert(fingerprint.to_lowercase(), info);
        Ok(())
    }

    /// Разбанить ник.\n    pub fn unban_nick(&self, nick: &str) -> bool {
        self.bans.remove(&nick.to_lowercase()).is_some()
    }

    /// Разбанить отпечаток.\n    pub fn unban_fingerprint(&self, fingerprint: &str) -> bool {
        self.bans.remove(&fingerprint.to_lowercase()).is_some()
    }

    /// Список всех активных банов.\n    pub fn ban_list(&self) -> Vec<BanInfo> {
        self.cleanup();
        self.bans.iter().map(|e| e.value().clone()).collect()
    }

    /// Удалить истёкшие баны.\n    fn cleanup(&self) {
        let now = Instant::now();
        self.bans.retain(|_, b| match b.expires_at {
            Some(t) => now < t,
            None => true,
        });
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ban_nick_flow() {
        let mgr = BanManager::new();
        assert!(!mgr.is_nick_banned("BadPlayer"));
        mgr.ban_nick("BadPlayer", "cheating".to_string(), "admin".to_string()).unwrap();
        assert!(mgr.is_nick_banned("badplayer")); // без учёта регистра
        assert!(mgr.unban_nick("BadPlayer"));
        assert!(!mgr.is_nick_banned("BadPlayer"));
    }

    #[test]
    fn fingerprint_twins() {
        let mgr = BanManager::new();
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        mgr.register_fingerprint(u1, "Player1".to_string(), "fp1");
        mgr.register_fingerprint(u2, "Player2".to_string(), "fp1");
        let twins = mgr.twins_for(&u1, "fp1");
        assert_eq!(twins, vec!["Player2".to_string()]);
    }
}
