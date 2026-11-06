//! # Fallback Server System (Этап 7)
//!
//! Если бэкенд, на котором находится игрок, уходит оффлайн,
//! игрок перекидывается на fallback-сервер БЕЗ дисконнекта.
//! В чат приходит красивое HEX-сообщение с причиной.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

use crate::auth::{Session, PlayerProfile};
use crate::config::ProxyConfig;
use crate::metrics::Metrics;
use crate::network::connection::ClientLink;
use crate::protocol::codec::MinecraftCodec;
use crate::protocol::packets::{
    handshake_bytes, login_start_bytes, packet_bytes, Handshake, LoginStart, ids, LOGIN_START,
};
use crate::protocol::varint::write_varint;
use crate::proxy::{BackendLink, Proxy, Server};

/// Конфигурация fallback.
#[derive(Debug, Clone)]
pub struct FallbackConfig {
    /// Имя fallback-сервера (должен существовать в config.toml)
    pub fallback_server: String,
    /// Сообщение в чат при перекидывании (поддерживает HEX & #RRGGBB)
    pub kick_message: String,
    /// Пытаться ли вернуть на исходный сервер когда он оживёт
    pub auto_return: bool,
    /// Интервал проверки здоровья исходного сервера (сек)
    pub health_check_interval_secs: u64,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            fallback_server: "lobby".to_string(),
            kick_message: "&b&lRustProxy &f» &eСервер &6{server} &eушёл оффлайн. &fПерекидываем на fallback...",
            auto_return: true,
            health_check_interval_secs: 15,
        }
    }
}

/// Менеджер fallback-состояний.
pub struct FallbackManager {
    pub config: FallbackConfig,
    /// Игрок → его исходный сервер (для авто-возврата)
    pub original_server: dashmap::DashMap<uuid::Uuid, String>,
    /// Флаг, что fallback активен
    pub active: Arc<AtomicBool>,
}

impl FallbackManager {
    pub fn new() -> Self {
        Self {
            config: FallbackConfig::default(),
            original_server: dashmap::DashMap::new(),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_config(config: FallbackConfig) -> Self {
        Self {
            config,
            original_server: dashmap::DashMap::new(),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Запомнить исходный сервер игрока.
    pub fn remember_original(&self, uuid: uuid::Uuid, server: String) {
        self.original_server.insert(uuid, server);
    }

    /// Удалить запись.
    pub fn forget(&self, uuid: &uuid::Uuid) {
        self.original_server.remove(uuid);
    }

    /// Получить исходный сервер.
    pub fn get_original(&self, uuid: &uuid::Uuid) -> Option<String> {
        self.original_server.get(uuid).map(|e| e.clone())
    }
}

/// Выполнить fallback-переключение игрока.
pub async fn do_fallback_switch(
    proxy: &Arc<crate::proxy::Proxy>,
    client_link: &ClientLink,
    username: &str,
    uuid: &uuid::Uuid,
    old_server: &str,
    metrics: &Arc<crate::metrics::Metrics>,
) -> Result<BackendLink> {
    let fallback_name = &proxy.config.proxy.default_server; // или из FallbackConfig
    let fallback = fallback_name.as_str();

    info!(
        %username,
        from = %old_server,
        to = %fallback,
        "FALLBACK: переключаем игрока на fallback-сервер"
    );

    metrics.inc_server_switches();

    // Создаём новый LoginStart для fallback
    let start = LoginStart {
        uuid: *uuid,
        username: username.to_string(),
    };

    let new_link = proxy.connect_to_server(fallback, 777, &start).await?;

    // Отправляем красивое HEX-сообщение в чат игроку
    let msg = fallback_message(&proxy.config, old_server, fallback);
    send_hex_chat(client_link, &msg).await.ok();

    Ok(new_link)
}

/// Сформировать сообщение с HEX цветами.
/// Поддерживает &b, &f, &e, &6 и & #RRGGBB (упрощённый парсер).
pub fn fallback_message(config: &ProxyConfig, old_server: &str, fallback: &str) -> String {
    // Базовый шаблон с HEX
    let raw = &config.proxy.motd; // можно вынести отдельный конфиг
    let _ = raw;
    format!(
        "&b&lRustProxy &f» &eСервер &c{} &eушёл оффлайн. &fПерекидываем на &a{} &bбез дисконнекта.",
        old_server, fallback
    )
}

/// Отправить чат-сообщение с HEX-поддержкой клиенту.
pub async fn send_hex_chat(client_link: &ClientLink, text: &str) -> anyhow::Result<()> {
    let converted = convert_hex_colors(text);
    let json = serde_json::json!({
        "text": converted,
        "color": "reset"
    }).to_string();
    let mut c = client_link.lock().await;
    c.send(crate::protocol::packets::packet_bytes(
        crate::protocol::packets::ids::PLAY_CHAT_MESSAGE_CLIENTBOUND,
        json.as_bytes(),
    )).await
}

/// Простой конвертер &коды и & #RRGGBB в §коды Minecraft.
pub fn convert_hex_colors(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '&' {
            if let Some(next) = chars.peek() {
                match next {
                    '0'..='9' | 'a'..='f' | 'A'..='F' | 'k' | 'l' | 'm' | 'n' | 'o' | 'r' => {
                        out.push('§');
                        out.push(*next);
                        chars.next();
                        continue;
                    }
                    '#' => {
                        // & #RRGGBB — поддерживаем только до 6 символов
                        chars.next(); // съедаем #
                        let mut hex = String::new();
                        for _ in 0..6 {
                            if let Some(c) = chars.peek() {
                                hex.push(*c);
                                chars.next();
                            }
                        }
                        if hex.len() == 6 {
                            out.push_str("§x");
                            for c in hex.chars() {
                                out.push('§');
                                out.push(c);
                            }
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            out.push(ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Проверить здоровье fallback-сервера (полезно для авто-возврата).
pub async fn check_backend_health(addr: &str) -> bool {
    let (host, port_str) = addr.rsplit_once(':').unwrap_or((addr, "25565"));
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        TcpStream::connect((host, port)).await.is_ok()
    })
    .await
    .unwrap_or(false)
}
