//! Метрики прокси для мониторинга нагрузки (2к CCU).
//! Все счетчики атомарные — безопасны для чтения из любого потока без блокировок.

use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

pub struct Metrics {
    /// Всего активных соединений игроков к прокси
    pub active_connections: AtomicUsize,
    /// Всего игроков в фазе Play (на серверах)
    pub active_players: AtomicUsize,
    /// Всего пересланных пакетов клиент → бэкенд
    pub packets_client_to_backend: AtomicU64,
    /// Всего пересланных пакетов бэкенд → клиент
    pub packets_backend_to_client: AtomicU64,
    /// Всего ошибок чтения/записи
    pub errors_total: AtomicU64,
    /// Всего попыток подключения к бэкендам
    pub backend_connects_total: AtomicU64,
    /// Всего неудачных подключений к бэкендам
    pub backend_connect_errors: AtomicU64,
    /// Всего переводов пакетов ViaVersion
    pub translations_total: AtomicU64,
    /// Всего ошибок перевода пакетов
    pub translation_errors: AtomicU64,
    /// Всего команд /server (переключений сервера)
    pub server_switches_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            active_players: AtomicUsize::new(0),
            packets_client_to_backend: AtomicU64::new(0),
            packets_backend_to_client: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            backend_connects_total: AtomicU64::new(0),
            backend_connect_errors: AtomicU64::new(0),
            translations_total: AtomicU64::new(0),
            translation_errors: AtomicU64::new(0),
            server_switches_total: AtomicU64::new(0),
        }
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_active_players(&self) {
        self.active_players.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_players(&self) {
        self.active_players.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_packets_c2b(&self) {
        self.packets_client_to_backend.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_packets_b2c(&self) {
        self.packets_backend_to_client.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backend_connects(&self) {
        self.backend_connects_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backend_connect_errors(&self) {
        self.backend_connect_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_translations(&self) {
        self.translations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_translation_errors(&self) {
        self.translation_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_server_switches(&self) {
        self.server_switches_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            active_players: self.active_players.load(Ordering::Relaxed),
            packets_client_to_backend: self.packets_client_to_backend.load(Ordering::Relaxed),
            packets_backend_to_client: self.packets_backend_to_client.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            backend_connects_total: self.backend_connects_total.load(Ordering::Relaxed),
            backend_connect_errors: self.backend_connect_errors.load(Ordering::Relaxed),
            translations_total: self.translations_total.load(Ordering::Relaxed),
            translation_errors: self.translation_errors.load(Ordering::Relaxed),
            server_switches_total: self.server_switches_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub active_connections: usize,
    pub active_players: usize,
    pub packets_client_to_backend: u64,
    pub packets_backend_to_client: u64,
    pub errors_total: u64,
    pub backend_connects_total: u64,
    pub backend_connect_errors: u64,
    pub translations_total: u64,
    pub translation_errors: u64,
    pub server_switches_total: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
