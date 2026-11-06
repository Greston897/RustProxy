//! # Backend Resource Monitor (Этап 15 — NullCordX стиль)
//!
//! Мониторинг ресурсов каждого бэкенда: CPU, RAM, TPS, онлайн, пинг.
//! Minecraft-протокол не отдаёт CPU/RAM напрямую, поэтому:
//!   • Онлайн/макс/МОTD — через Status запрос (реальные данные)
//!   • Пинг — время ответа на Status Request
//!   • TPS — оценивается по стабильности времени ответа (экспоненциальное скользящее)
//!   • CPU/RAM — заглушки под плагин на бэкенде (можно расширить через HTTP API)
//!
//! Все данные хранятся в DashMap без блокировок — безопасно для чтения из любого потока.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Конфиг мониторинга.
#[derive(Debug, Clone)]
pub struct BackendMonitorConfig {
    pub enabled: bool,
    pub interval_secs: u64,
}

/// Внутренний хелпер для парсинга адреса (pub(crate) внутри crate).
#[doc(hidden)]
pub fn split_address_inner(addr: &str) -> (String, String) {
    match addr.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (addr.to_string(), "25565".to_string()),
    }
}

/// Снимок ресурсов бэкенда.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSnapshot {
    pub name: String,
    pub address: String,
    pub online: bool,
    pub players_online: usize,
    pub players_max: usize,
    pub motd: String,
    pub protocol: i32,
    pub ping_ms: u64,
    pub tps: f32,              // 20.0 = идеал
    pub cpu_percent: f32,      // 0..100 (заглушка, заполняется плагином)
    pub ram_mb: u64,           // заглушка
    pub ram_max_mb: u64,       // заглушка
    pub last_update: Instant,
}

impl BackendSnapshot {
    pub fn new(name: String, address: String) -> Self {
        Self {
            name,
            address,
            online: false,
            players_online: 0,
            players_max: 0,
            motd: String::new(),
            protocol: 777,
            ping_ms: 0,
            tps: 20.0,
            cpu_percent: 0.0,
            ram_mb: 0,
            ram_max_mb: 0,
            last_update: Instant::now(),
        }
    }

    pub fn health_score(&self) -> f32 {
        let mut score = 100.0_f32;
        if !self.online {
            return 0.0;
        }
        // Штраф за высокий пинг
        if self.ping_ms > 200 {
            score -= 20.0;
        } else if self.ping_ms > 100 {
            score -= 10.0;
        }
        // Штраф за низкий TPS
        if self.tps < 15.0 {
            score -= 30.0;
        } else if self.tps < 18.0 {
            score -= 10.0;
        }
        // Штраф за заполненность
        if self.players_max > 0 {
            let fill = self.players_online as f32 / self.players_max as f32;
            if fill > 0.95 {
                score -= 20.0;
            } else if fill > 0.8 {
                score -= 10.0;
            }
        }
        score.max(0.0).min(100.0)
    }

    pub fn health_color(&self) -> &'static str {
        let s = self.health_score();
        if s >= 80.0 { "&a" }   // зелёный
        else if s >= 50.0 { "&e" } // жёлтый
        else if s > 0.0 { "&c" }   // красный
        else { "&4" }             // тёмно-красный (оффлайн)
    }
}

/// История пингов для расчёта TPS.
struct PingHistory {
    times: VecDeque<u64>,
}

impl PingHistory {
    fn new() -> Self {
        Self { times: VecDeque::with_capacity(60) }
    }

    fn push(&mut self, ms: u64) {
        self.times.push_back(ms);
        if self.times.len() > 60 {
            self.times.pop_front();
        }
    }

    /// Ориентировочный TPS: если средний отклик <50мс — 20 TPS, если >500мс — падаем.
    fn estimate_tps(&self) -> f32 {
        if self.times.is_empty() {
            return 20.0;
        }
        let avg: u64 = self.times.iter().sum::<u64>() / self.times.len() as u64;
        if avg <= 30 { 20.0 }
        else if avg <= 60 { 18.0 }
        else if avg <= 100 { 16.0 }
        else if avg <= 200 { 12.0 }
        else if avg <= 400 { 8.0 }
        else { 4.0 }
    }
}

/// Менеджер мониторинга бэкендов.
pub struct BackendMonitor {
    /// имя сервера → снимок
    pub snapshots: DashMap<String, Arc<BackendSnapshot>>,
    /// имя сервера → история пингов
    pub history: DashMap<String, PingHistory>,
    pub interval_secs: u64,
}

impl BackendMonitor {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            snapshots: DashMap::new(),
            history: DashMap::new(),
            interval_secs,
        }
    }

    pub fn register(&self, name: String, address: String) {
        self.snapshots.insert(name.clone(), Arc::new(BackendSnapshot::new(name, address)));
        self.history.insert(name, PingHistory::new());
    }

    /// Обновить снимок после Status опроса.
    pub fn update_status(&self, name: &str, online: bool, players_online: usize, players_max: usize, motd: String, protocol: i32, ping_ms: u64) {
        let mut snap = self.snapshots.get_mut(name);
        if let Some(mut s) = snap {
            Arc::make_mut(&mut s).online = online;
            Arc::make_mut(&mut s).players_online = players_online;
            Arc::make_mut(&mut s).players_max = players_max;
            Arc::make_mut(&mut s).motd = motd;
            Arc::make_mut(&mut s).protocol = protocol;
            Arc::make_mut(&mut s).ping_ms = ping_ms;
            Arc::make_mut(&mut s).last_update = Instant::now();

            // Обновляем историю и TPS
            if let Some(mut h) = self.history.get_mut(name) {
                Arc::make_mut(&mut h).push(ping_ms);
                Arc::make_mut(&mut s).tps = Arc::make_mut(&mut h).estimate_tps();
            }
        }
    }

    /// Обновить ресурсы из внешнего источника (плагин на бэкенде / HTTP API).
    pub fn update_resources(&self, name: &str, cpu_percent: f32, ram_mb: u64, ram_max_mb: u64) {
        if let Some(mut s) = self.snapshots.get_mut(name) {
            Arc::make_mut(&mut s).cpu_percent = cpu_percent;
            Arc::make_mut(&mut s).ram_mb = ram_mb;
            Arc::make_mut(&mut s).ram_max_mb = ram_max_mb;
        }
    }

    pub fn get(&self, name: &str) -> Option<BackendSnapshot> {
        self.snapshots.get(name).map(|s| (*s).clone())
    }

    pub fn all(&self) -> Vec<BackendSnapshot> {
        self.snapshots.iter().map(|s| (*s).clone()).collect()
    }

    pub fn online_count(&self) -> usize {
        self.snapshots.iter().filter(|s| s.online).count()
    }

    pub fn total_players(&self) -> usize {
        self.snapshots.iter().map(|s| s.players_online).sum()
    }

    pub fn total_max(&self) -> usize {
        self.snapshots.iter().map(|s| s.players_max).sum()
    }

    pub fn average_tps(&self) -> f32 {
        let snaps: Vec<BackendSnapshot> = self.all();
        if snaps.is_empty() { return 20.0; }
        snaps.iter().map(|s| s.tps).sum::<f32>() / snaps.len() as f32
    }

    pub fn snapshot_json(&self) -> serde_json::Value {
        let snaps: Vec<BackendSnapshot> = self.all();
        serde_json::json!({
            "servers": snaps.iter().map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "address": s.address,
                    "online": s.online,
                    "players_online": s.players_online,
                    "players_max": s.players_max,
                    "motd": s.motd,
                    "protocol": s.protocol,
                    "ping_ms": s.ping_ms,
                    "tps": s.tps,
                    "cpu_percent": s.cpu_percent,
                    "ram_mb": s.ram_mb,
                    "ram_max_mb": s.ram_max_mb,
                    "health_score": s.health_score(),
                    "health_color": s.health_color(),
                })
            }).collect::<Vec<_>>(),
            "total_online": self.total_players(),
            "total_max": self.total_max(),
            "average_tps": self.average_tps(),
            "online_count": self.online_count(),
        })
    }
}

impl Default for BackendMonitor {
    fn default() -> Self {
        Self::new(30)
    }
}
