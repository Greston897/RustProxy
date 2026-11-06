//! # DDoS Protection via NBT Packets (Этап 11)
//!
//! Атакующие могут слать некорректные/огромные NBT-пакеты (Chunk Data, Entity Metadata),
//! что перегружает CPU прокси при парсинге. Мы защищаемся:
//!   • Лимит глубины NBT (max 16 уровней вложенности)
//!   • Лимит размера одного NBT-тега (max 1 МБ)
//!   • Лимит списков (max 10000 элементов)
//!   • Rate limit на пакеты с NBT (max 50/сек на IP)
//!   • Connection throttle: max 100 новых соединений/сек на IP
//!   • Auto-ban IP при превышении лимитов

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Настройки DDoS-защиты.
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    pub enabled: bool,
    pub max_nbt_depth: usize,
    pub max_nbt_tag_size: usize,
    pub max_nbt_list_size: usize,
    pub nbt_packets_per_sec: u64,
    pub max_connections_per_sec_per_ip: u64,
    pub ban_duration_secs: u64,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_nbt_depth: 16,
            max_nbt_tag_size: 1024 * 1024, // 1 MB
            max_nbt_list_size: 10_000,
            nbt_packets_per_sec: 50,
            max_connections_per_sec_per_ip: 100,
            ban_duration_secs: 3600, // 1 час
        }
    }
}

/// Счётчики для rate limit (потокобезопасные, без Cell).
#[derive(Default)]
struct RateCounters {
    nbt_packets: AtomicU64,
    connections: AtomicU64,
    /// Unix секунды последнего сброса счётчика.
    last_reset_secs: AtomicU64,
}

impl RateCounters {
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Проверяет, прошла ли секунда с последнего сброса, и если да — сбрасывает указанный счётчик.
    fn maybe_reset(&self, counter: &AtomicU64) -> u64 {
        let now = Self::now_secs();
        let last = self.last_reset_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 1 {
            // Пытаемся установить новый срок сброса (только один поток успешно).
            let _ = self.last_reset_secs.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed);
            counter.store(0, Ordering::Relaxed);
        }
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Менеджер DDoS-защиты.
pub struct DDoSManager {
    pub config: DDoSConfig,
    /// IP → статистика
    pub stats: DashMap<IpAddr, Arc<RateCounters>>,
    /// IP → время до которого забанен
    pub bans: DashMap<IpAddr, Instant>,
    /// Всего заблокировано пакетов
    pub blocked_total: AtomicU64,
    /// Всего заблокировано соединений
    pub blocked_connections_total: AtomicU64,
}

impl DDoSManager {
    pub fn new(config: DDoSConfig) -> Self {
        Self {
            config,
            stats: DashMap::new(),
            bans: DashMap::new(),
            blocked_total: AtomicU64::new(0),
            blocked_connections_total: AtomicU64::new(0),
        }
    }

    /// Проверить, не забанен ли IP.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if let Some(until) = self.bans.get(&ip) {
            if Instant::now() < *until {
                return true;
            } else {
                self.bans.remove(&ip);
            }
        }
        false
    }

    /// Забанить IP.
    pub fn ban(&self, ip: IpAddr, reason: &str) {
        tracing::warn!(%ip, %reason, "DDoS: IP banned");
        self.bans.insert(ip, Instant::now() + Duration::from_secs(self.config.ban_duration_secs));
        self.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Проверка rate limit на новые соединения (вызывается при accept).
    pub fn check_connection(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        if self.is_banned(ip) {
            self.blocked_connections_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let counters = self.stats.entry(ip).or_insert_with(|| Arc::new(RateCounters::default()));
        let count = counters.maybe_reset(&counters.connections);
        if count > self.config.max_connections_per_sec_per_ip {
            self.ban(ip, "connection flood");
            return false;
        }
        true
    }

    /// Проверка rate limit на NBT-пакеты (вызывается при парсинге Chunk Data / Entity Metadata).
    pub fn check_nbt_packet(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }
        if self.is_banned(ip) {
            self.blocked_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let counters = self.stats.entry(ip).or_insert_with(|| Arc::new(RateCounters::default()));
        let count = counters.maybe_reset(&counters.nbt_packets);
        if count > self.config.nbt_packets_per_sec {
            self.ban(ip, "NBT packet flood");
            return false;
        }
        true
    }

    /// Валидация глубины NBT (защита от глубокой вложенности = stack overflow).
    pub fn validate_nbt_depth(current_depth: usize) -> bool {
        current_depth <= 16
    }

    /// Валидация размера тега (защита от огромных строк/массивов).
    pub fn validate_tag_size(size: usize) -> bool {
        size <= 1024 * 1024 // 1 MB
    }

    /// Валидация размера списка.
    pub fn validate_list_size(size: usize) -> bool {
        size <= 10_000
    }

    pub fn snapshot(&self) -> DDoSSnapshot {
        DDoSSnapshot {
            banned_ips: self.bans.len(),
            tracked_ips: self.stats.len(),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            blocked_connections_total: self.blocked_connections_total.load(Ordering::Relaxed),
        }
    }

    /// Очистка старых записей (фоновая задача, вызывается раз в минуту).
    pub fn cleanup(&self) {
        // Записи статистики маленькие, DashMap справляется с тысячами IP.
        // Баны сами очищаются по истечении срока в is_banned().
        // Если понадобится жёсткая очистка — добавить last_activity в RateCounters.
    }
}

#[derive(Debug, Clone)]
pub struct DDoSSnapshot {
    pub banned_ips: usize,
    pub tracked_ips: usize,
    pub blocked_total: u64,
    pub blocked_connections_total: u64,
}

impl Default for DDoSManager {
    fn default() -> Self {
        Self::new(DDoSConfig::default())
    }
}
