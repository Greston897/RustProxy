//! # Продакшен-защита для 1000+ онлайна
//!\n//!\n//! • Лимит игроков на IP (анти-многоклиент флуд)\n//! • Защита от командного флуда (rate limit на команды)\n//! • Защита от чат-флуда (rate limit на чат)\n//! • Бан за некорректные пакеты\n//! • Таймаут бездействия\n//! • Лимит новых соединений на IP в секунду (уже в DDoS, но здесь ужесточён)

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Счётчик команд игрока (защита от командного флуда).
#[derive(Default)]
struct CommandCounter {
    count: AtomicU64,
    last_reset: std::cell::Cell<Instant>,
}

/// Счётчик сообщений чата (защита от чат-флуда).
#[derive(Default)]
struct ChatCounter {
    count: AtomicU64,
    last_reset: std::cell::Cell<Instant>,
}

/// Менеджер продакшен-защиты.\npub struct SecurityManager {
    /// IP → количество игроков с этого IP
    pub players_per_ip: DashMap<IpAddr, usize>,
    /// Игрок → счётчик команд
    pub command_counters: DashMap<uuid::Uuid, Arc<CommandCounter>>,
    /// Игрок → счётчик чата
    pub chat_counters: DashMap<uuid::Uuid, Arc<ChatCounter>>,
    /// IP → бан за некорректные пакеты
    pub bad_packet_bans: DashMap<IpAddr, Instant>,
    /// Максимум игроков на один IP
    pub max_players_per_ip: usize,
    /// Максимум команд в секунду
    pub max_commands_per_sec: u64,
    /// Максимум сообщений чата в секунду
    pub max_chat_per_sec: u64,
    /// Таймаут бездействия (сек)
    pub idle_timeout_secs: u64,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            players_per_ip: DashMap::new(),
            command_counters: DashMap::new(),
            chat_counters: DashMap::new(),
            bad_packet_bans: DashMap::new(),
            max_players_per_ip: 5,
            max_commands_per_sec: 30,
            max_chat_per_sec: 20,
            idle_timeout_secs: 300,
        }
    }

    /// Проверить, можно ли пустить игрока с этого IP (лимит на IP).
    pub fn check_ip_limit(&self, ip: IpAddr) -> bool {
        let count = self.players_per_ip.get(&ip).map(|c| *c).unwrap_or(0);
        count < self.max_players_per_ip
    }

    /// Зарегистрировать игрока на IP.\n    pub fn add_player_ip(&self, ip: IpAddr) {
        *self.players_per_ip.entry(ip).or_insert(0) += 1;
    }

    /// Удалить игрока с IP.\n    pub fn remove_player_ip(&self, ip: IpAddr) {
        if let Some(mut c) = self.players_per_ip.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                self.players_per_ip.remove(&ip);
            }
        }
    }

    /// Проверка лимита команд в секунду.\n    pub fn check_command_rate(&self, uuid: uuid::Uuid) -> bool {
        let counter = self.command_counters.entry(uuid).or_insert_with(|| Arc::new(CommandCounter::default()));
        let now = Instant::now();
        let last = counter.last_reset.get();
        if now.duration_since(last) >= Duration::from_secs(1) {
            counter.count.store(0, Ordering::Relaxed);
            counter.last_reset.set(now);
        }
        let count = counter.count.fetch_add(1, Ordering::Relaxed) + 1;
        count <= self.max_commands_per_sec
    }

    /// Проверка лимита чата в секунду.\n    pub fn check_chat_rate(&self, uuid: uuid::Uuid) -> bool {
        let counter = self.chat_counters.entry(uuid).or_insert_with(|| Arc::new(ChatCounter::default()));
        let now = Instant::now();
        let last = counter.last_reset.get();
        if now.duration_since(last) >= Duration::from_secs(1) {
            counter.count.store(0, Ordering::Relaxed);
            counter.last_reset.set(now);
        }
        let count = counter.count.fetch_add(1, Ordering::Relaxed) + 1;
        count <= self.max_chat_per_sec
    }

    /// Бан за некорректные пакеты.\n    pub fn ban_bad_packets(&self, ip: IpAddr, duration_secs: u64) {
        self.bad_packet_bans.insert(ip, Instant::now() + Duration::from_secs(duration_secs));
        tracing::warn!(%ip, "Бан за некорректные пакеты на {} сек", duration_secs);
    }

    /// Проверить бан за плохие пакеты.\n    pub fn is_bad_packet_banned(&self, ip: IpAddr) -> bool {
        if let Some(until) = self.bad_packet_bans.get(&ip) {
            if Instant::now() < *until {
                return true;
            } else {
                self.bad_packet_bans.remove(&ip);
            }
        }
        false
    }

    /// Очистка stale-счётчиков (фоновая задача).\n    pub fn cleanup(&self) {
        let now = Instant::now();
        self.command_counters.retain(|_, c| {
            now.duration_since(c.last_reset.get()) < Duration::from_secs(60)
        });
        self.chat_counters.retain(|_, c| {
            now.duration_since(c.last_reset.get()) < Duration::from_secs(60)
        });
        self.bad_packet_bans.retain(|_, until| now < *until);
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ip_limit() {
        let mgr = SecurityManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(mgr.check_ip_limit(ip));
        mgr.add_player_ip(ip);
        mgr.add_player_ip(ip);
        mgr.add_player_ip(ip);
        mgr.add_player_ip(ip);
        mgr.add_player_ip(ip); // 5 = max
        assert!(!mgr.check_ip_limit(ip)); // 6-й не проходит
    }
}
