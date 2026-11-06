//! Ядро прокси: реестр серверов, сессии игроков, подключение к бэкендам.
//! Интеграция: auth (login/reg), TFA (Telegram /link), CAPTCHA, Fallback, DDoS,
//! метрики, мониторинг ресурсов бэкендов, клики [connect]/[server] в лобби.

use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tokio_util::codec::Framed;
use futures_util::sink::SinkExt;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::AuthManager;
use crate::backend_monitor::BackendMonitor;
use crate::captcha::CaptchaManager;
use crate::config::ProxyConfig;
use crate::ddos_protection::DDoSManager;
use crate::fallback::FallbackManager;
use crate::metrics::Metrics;
use crate::network::listener;
use crate::protocol::codec::MinecraftCodec;
use crate::protocol::encryption::ServerKeyPair;
use crate::protocol::packets::{
    handshake_bytes, login_start_bytes, packet_bytes, Handshake, LoginStart, ids, LOGIN_START,
};
use crate::protocol::varint::{read_varint, read_string};
use crate::protocol::versions;
use crate::tfa::TfaManager;

pub struct Proxy {
    pub config: Arc<ProxyConfig>,
    pub auth: AuthManager,
    pub tfa: Arc<Mutex<TfaManager>>,
    pub captcha: Arc<Mutex<CaptchaManager>>,
    pub key_pair: ServerKeyPair,
    pub metrics: Arc<Metrics>,
    pub ddos: Arc<DDoSManager>,
    pub fallback: Arc<FallbackManager>,
    pub monitor: BackendMonitor,
    pub servers: Arc<dashmap::DashMap<String, Arc<Server>>>,
    pub players: Arc<dashmap::DashMap<Uuid, Arc<PlayerSession>>>,
    pub backend_pool: Arc<
        dashmap::DashMap<String, Arc<tokio::sync::Mutex<Vec<PooledBackendConnection>>>>,
    >,
    pub shutdown: AtomicBool,
}

pub struct PooledBackendConnection {
    pub framed: Framed<TcpStream, MinecraftCodec>,
    pub protocol: i32,
    pub last_used: Instant,
}

pub struct Server {
    pub name: String,
    pub address: String,
    pub enabled: bool,
    pub online: AtomicBool,
    pub players: AtomicUsize,
    pub max: usize,
    pub motd: Arc<tokio::sync::RwLock<String>>,
}

pub struct PlayerSession {
    pub uuid: Uuid,
    pub username: String,
    pub connected_at: Instant,
    pub client_protocol: i32,
    pub server_protocol: i32,
    pub authenticated: bool,
    pub tfa_verified: bool,
    pub captcha_verified: bool,
    pub login_ip: Option<std::net::IpAddr>,
}

pub struct BackendLink {
    pub server: Arc<Server>,
    pub framed: Framed<TcpStream, MinecraftCodec>,
    pub protocol: i32,
    pub from_pool: bool,
}

impl PlayerSession {
    pub fn new(uuid: Uuid, username: &str, client_protocol: i32, server_protocol: i32) -> Self {
        Self {
            uuid,
            username: username.to_string(),
            connected_at: Instant::now(),
            client_protocol,
            server_protocol,
            authenticated: false,
            tfa_verified: false,
            captcha_verified: false,
            login_ip: None,
        }
    }
}

impl Proxy {
    pub async fn new(config: Arc<ProxyConfig>) -> Result<Self> {
        let auth = AuthManager::new();
        let tfa = Arc::new(Mutex::new(TfaManager::new(config.tfa.bot_token.clone())?));
        let captcha = Arc::new(Mutex::new(CaptchaManager::new()?));
        let key_pair = ServerKeyPair::generate()?;
        info!("RSA ключевая пара сгенерирована (1024 бит)");
        let metrics = Arc::new(Metrics::new());
        let ddos = Arc::new(DDoSManager::new(config.ddos_config()));
        let fallback = Arc::new(FallbackManager::with_config(config.fallback_config()));
        let monitor = BackendMonitor::new(config.monitor_config().interval_secs);

        let servers = Arc::new(dashmap::DashMap::new());
        for s in &config.servers {
            if s.enabled {
                monitor.register(s.name.clone(), s.address.clone());
                servers.insert(
                    s.name.clone(),
                    Arc::new(Server {
                        name: s.name.clone(),
                        address: s.address.clone(),
                        enabled: true,
                        online: AtomicBool::new(false),
                        players: AtomicUsize::new(0),
                        max: 0,
                        motd: Arc::new(tokio::sync::RwLock::new(String::new())),
                    }),
                );
            }
        }
        let backend_pool = Arc::new(dashmap::DashMap::new());
        Ok(Self {
            config: Arc::clone(&config),
            auth,
            tfa,
            captcha,
            key_pair,
            metrics,
            ddos,
            fallback,
            monitor,
            servers,
            players: Arc::new(dashmap::DashMap::new()),
            backend_pool,
            shutdown: AtomicBool::new(false),
        })
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let config = Arc::clone(&self.config);
        let pinger = Arc::clone(&self);
        let monitor_proxy = Arc::clone(&self);

        let listener_task = tokio::spawn(listener::run(config, self.clone()));
        let pinger_task = tokio::spawn(pinger.start_pinger());
        let monitor_task = tokio::spawn(monitor_proxy.start_monitor());
        let tfa_task = {
            let p = Arc::clone(&self);
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(2));
                loop {
                    interval.tick().await;
                    if p.is_shutting_down() {
                        return;
                    }
                    let updates = match p.tfa.lock().await.poll_updates().await {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("tfa poll error: {e}");
                            continue;
                        }
                    };
                    for upd in updates {
                        match p.tfa.lock().await.handle_bot_response(upd.chat_id, &upd.text) {
                            Ok(Some(uuid)) => {
                                info!(%uuid, "TFA login confirmed via Telegram (/da)");
                                if let Some(ps) = p.players.get(&uuid) {
                                    let mut new_ps = (*ps).clone();
                                    new_ps.tfa_verified = true;
                                    new_ps.authenticated = true;
                                    p.players.insert(uuid, Arc::new(new_ps));
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                warn!("tfa bot response: {e}");
                            }
                        }
                    }
                }
            })
        };

        tokio::signal::ctrl_c().await.ok();
        info!("Graceful shutdown...");

        self.shutdown.store(true, Ordering::SeqCst);
        listener_task.abort();
        pinger_task.abort();
        monitor_task.abort();
        tfa_task.abort();

        let player_uuids: Vec<Uuid> = self.players.iter().map(|e| *e.key()).collect();
        for uuid in player_uuids {
            self.players.remove(&uuid);
        }

        for entry in self.backend_pool.iter() {
            let mut conns = entry.value().lock().await;
            conns.clear();
        }

        info!("Shutdown завершён");
        Ok(())
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    async fn start_pinger(self: Arc<Self>) {
        let interval_secs = self.config.ping_interval_secs();
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if self.is_shutting_down() {
                return;
            }
            let servers: Vec<Arc<Server>> = self
                .servers
                .iter()
                .filter(|e| e.enabled)
                .map(|e| e.clone())
                .collect();
            for server in servers {
                let proxy = Arc::clone(&self);
                let srv = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(e) = proxy.ping_server(&srv).await {
                        debug!("ping {} failed: {e}", srv.name);
                        srv.online.store(false, Ordering::Relaxed);
                    }
                });
            }
        }
    }

    async fn start_monitor(self: Arc<Self>) {
        let interval = self.config.monitor_config().interval_secs;
        let mut ticker = time::interval(Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            if self.is_shutting_down() {
                return;
            }
            // Обновляем метрики мониторинга из текущих снимков серверов
            for entry in self.servers.iter() {
                let s = entry.value();
                let online = s.players.load(Ordering::Relaxed);
                let max = s.max.load(Ordering::Relaxed);
                let motd = s.motd.read().await.clone();
                self.monitor.update_status(
                    &s.name,
                    s.online.load(Ordering::Relaxed),
                    online,
                    max,
                    motd,
                    versions::MAX_PROTOCOL,
                    0, // ping_ms обновляется отдельно, если нужно
                );
            }
        }
    }

    async fn ping_server(&self, server: &Arc<Server>) -> Result<()> {
        use crate::protocol::packets::split_packet;
        let (host, port_str) = split_address(&server.address);
        let port: u16 = port_str.parse()?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))?
        .context("connect to backend for ping")?;

        let mut framed = Framed::new(stream, MinecraftCodec::new());
        let handshake = Handshake {
            protocol_version: versions::MAX_PROTOCOL,
            server_address: host,
            port,
            next_state: 1,
        };
        framed
            .send(packet_bytes(ids::HANDSHAKE, &handshake_bytes(&handshake)))
            .await
            .context("send ping handshake")?;
        framed
            .send(packet_bytes(ids::STATUS_REQUEST, &[]))
            .await
            .context("send ping status request")?;

        let pkt = tokio::time::timeout(
            Duration::from_secs(5),
            framed.next(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ping read timeout"))?
        .context("backend closed during ping")?
        .context("ping read error")?;

        let (id, body) = split_packet(&pkt)?;
        if id != ids::STATUS_RESPONSE {
            bail!("expected status response, got id {id}");
        }

        let status: serde_json::Value = serde_json::from_slice(body)
            .context("parse status response json")?;

        let players_online = status
            .get("players")
            .and_then(|p| p.get("online"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let players_max = status
            .get("players")
            .and_then(|p| p.get("max"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let motd = status
            .get("description")
            .and_then(|d| d.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let now = Instant::now();
        // ping_ms не знаем без замеров, оставим 0 (можно замерять отдельно)
        self.monitor.update_status(
            &server.name,
            true,
            players_online,
            players_max,
            motd,
            versions::MAX_PROTOCOL,
            0,
        );

        server.online.store(true, Ordering::Relaxed);
        server.players.store(players_online, Ordering::Relaxed);
        server.max.store(players_max, Ordering::Relaxed);
        *server.motd.write().await = motd;

        debug!(
            "ping {} @ {}: online={}/{} motd={}",
            server.name, server.address, players_online, players_max, motd
        );
        Ok(())
    }

    pub async fn connect_to_server(
        &self,
        name: &str,
        protocol: i32,
        start: &LoginStart,
    ) -> Result<BackendLink> {
        self.metrics.inc_backend_connects();

        let server = self
            .servers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("server '{name}' not found"))
            .map(|entry| entry.clone())?;

        if let Some(pool_entry) = self.backend_pool.get(name) {
            let mut pool = pool_entry.lock().await;
            if let Some(pos) = pool.iter().position(|c| c.protocol == protocol) {
                let pooled = pool.remove(pos);
                info!("переиспользование соединения из пула для {} (протокол {})", name, protocol);
                return Ok(BackendLink {
                    server,
                    framed: pooled.framed,
                    protocol,
                    from_pool: true,
                });
            }
        }

        let (host, port_str) = split_address(&server.address);
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("bad port in server address {}", server.address))?;

        info!(
            "подключение к бэкенду {} (протокол {}) @ {}:{}",
            name,
            versions::version_name(protocol),
            host,
            port
        );

        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connect to backend {name} @ {}", server.address))?;

        stream.set_nodelay(true).context("set TCP_NODELAY")?;
        let _ = stream.set_send_buffer_size(256 * 1024);
        let _ = stream.set_recv_buffer_size(256 * 1024);

        let mut framed = Framed::new(stream, MinecraftCodec::new());
        let handshake = Handshake {
            protocol_version: protocol,
            server_address: host,
            port,
            next_state: 2,
        };
        framed
            .send(packet_bytes(ids::HANDSHAKE, &handshake_bytes(&handshake)))
            .await
            .context("send handshake to backend")?;
        framed
            .send(packet_bytes(LOGIN_START, &login_start_bytes(start)))
            .await
            .context("send login start to backend")?;

        Ok(BackendLink {
            server,
            framed,
            protocol,
            from_pool: false,
        })
    }

    pub async fn return_to_pool(&self, link: BackendLink) {
        if !link.from_pool {
            return;
        }
        if let Some(pool_entry) = self.backend_pool.get(&link.server.name) {
            let mut pool = pool_entry.lock().await;
            const MAX_POOL_PER_SERVER: usize = 64;
            if pool.len() < MAX_POOL_PER_SERVER {
                pool.push(PooledBackendConnection {
                    framed: link.framed,
                    protocol: link.protocol,
                    last_used: Instant::now(),
                });
            }
        }
    }

    pub fn player_count(&self) -> usize {
        self.players.len()
    }

    pub fn server_names(&self) -> Vec<String> {
        self.servers.iter().map(|e| e.key().clone()).collect()
    }

    pub async fn build_status_response(&self) -> serde_json::Value {
        use crate::messages::format_message;
        let mut samples = Vec::new();
        let mut total_online = 0usize;
        let mut total_max = 0usize;

        for entry in self.servers.iter() {
            let s = entry.value();
            let online = s.players.load(Ordering::Relaxed);
            let max = s.max.load(Ordering::Relaxed);
            total_online += online;
            total_max += max;
            if online > 0 && samples.len() < 5 {
                let motd = s.motd.read().await.clone();
                samples.push(serde_json::json!({
                    "name": s.name,
                    "id": s.name,
                    "motd": format_message(&motd),
                    "players": {"max": max, "online": online},
                }));
            }
        }

        let proxy_players = self.players.len();

        serde_json::json!({
            "description": {"text": format_message(&self.config.status.motd)},
            "players": {
                "max": self.config.status.max_players,
                "online": proxy_players,
                "sample": samples,
            },
            "version": {
                "name": self.config.proxy.name.clone(),
                "protocol": versions::MAX_PROTOCOL,
            },
            "enforcesSecureChat": false,
            "previewsChat": false,
            "modinfo": {"type": "FML", "modList": []},
        })
    }
}

/// Внутренний хелпер для split_address (public внутри crate).
pub fn split_address_inner(addr: &str) -> (String, String) {
    split_address(addr)
}

fn split_address(addr: &str) -> (String, String) {
    match addr.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (addr.to_string(), "25565".to_string()),
    }
}

impl Server {
    pub fn address(&self) -> SocketAddr {
        self.address.parse::<SocketAddr>().unwrap_or_else(|_| {
            let (host, port) = split_address(&self.address);
            format!("{host}:{port}").parse().expect("valid socket addr")
        })
    }
}
