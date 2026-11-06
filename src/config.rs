use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

fn default_true() -> bool {
    true
}

fn default_max_players() -> u32 {
    2000
}

fn default_compression_threshold() -> i32 {
    256
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_worker_threads() -> usize {
    0
}

fn default_bind() -> String {
    "0.0.0.0:25565".to_string()
}

fn default_default_server() -> String {
    "lobby".to_string()
}

fn default_fallback_server() -> String {
    "lobby".to_string()
}

fn default_status_motd() -> String {
    "&bRustProxy &7| &e1.16.5 → 26.3".to_string()
}

fn default_auth_mode() -> String {
    "offline".to_string()
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_ping_interval_secs() -> u64 {
    30
}

fn default_cache_ttl_secs() -> u64 {
    3600
}

fn default_monitor_interval_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySection,
    pub network: NetworkSection,
    pub status: StatusSection,
    pub auth: AuthSection,
    pub auth_local: AuthLocalSection,
    pub captcha: CaptchaSection,
    pub tfa: TfaSection,
    pub ddos: DDoSSection,
    pub fallback: FallbackSection,
    pub monitor: MonitorSection,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxySection {
    pub name: String,
    pub motd: String,
    #[serde(default = "default_true")]
    pub online_mode: bool,
    #[serde(default = "default_max_players")]
    pub max_players: u32,
    #[serde(default = "default_compression_threshold")]
    pub compression_threshold: i32,
    #[serde(default = "default_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_timeout_secs")]
    pub write_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_default_server")]
    pub default_server: String,
    #[serde(default = "default_fallback_server")]
    pub fallback_server: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkSection {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusSection {
    #[serde(default = "default_status_motd")]
    pub motd: String,
    #[serde(default = "default_max_players")]
    pub max_players: u32,
    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthSection {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthLocalSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptchaSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_captcha_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_captcha_max_attempts")]
    pub max_attempts: usize,
    #[serde(default = "default_exemption_hours")]
    pub exemption_hours: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TfaSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DDoSSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_nbt_depth")]
    pub max_nbt_depth: usize,
    #[serde(default = "default_nbt_tag_size")]
    pub max_nbt_tag_size: usize,
    #[serde(default = "default_nbt_list_size")]
    pub max_nbt_list_size: usize,
    #[serde(default = "default_nbt_pps")]
    pub nbt_packets_per_sec: u64,
    #[serde(default = "default_max_conn_per_sec")]
    pub max_connections_per_sec_per_ip: u64,
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FallbackSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_fallback_server")]
    pub fallback_server: String,
    #[serde(default = "default_true")]
    pub auto_return: bool,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
    #[serde(default = "default_kick_message")]
    pub kick_message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_monitor_interval_secs")]
    pub interval_secs: u64,
}

fn default_captcha_ttl() -> u64 {
    300
}

fn default_captcha_max_attempts() -> usize {
    3
}

fn default_exemption_hours() -> u64 {
    4
}

fn default_nbt_depth() -> usize {
    16
}

fn default_nbt_tag_size() -> usize {
    1024 * 1024
}

fn default_nbt_list_size() -> usize {
    10_000
}

fn default_nbt_pps() -> u64 {
    50
}

fn default_max_conn_per_sec() -> u64 {
    100
}

fn default_ban_duration() -> u64 {
    3600
}

fn default_health_check_interval() -> u64 {
    15
}

fn default_kick_message() -> String {
    "&b&lRustProxy &f» &eСервер &c{server} &eушёл оффлайн. &fПерекидываем на &a{fallback} &bбез дисконнекта.".to_string()
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {:?}", path.as_ref().display()))?;
        let cfg: ProxyConfig = toml::from_str(&text).context("failed to parse config.toml")?;
        Ok(cfg)
    }

    pub fn auth_mode(&self) -> crate::auth::AuthMode {
        match self.auth.mode.to_lowercase().as_str() {
            "offline" => crate::auth::AuthMode::Offline,
            "microsoft" => crate::auth::AuthMode::Microsoft,
            _ => crate::auth::AuthMode::Online,
        }
    }

    pub fn worker_threads(&self) -> usize {
        let n = self.network.worker_threads;
        if n == 0 {
            num_cpus::get()
        } else {
            n
        }
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        self.network.bind.parse().context("invalid network.bind")
    }

    pub fn cache_ttl_secs(&self) -> u64 {
        self.auth_local.cache_ttl_secs
    }

    pub fn exemption_secs(&self) -> u64 {
        self.captcha.exemption_hours * 3600
    }

    pub fn ddos_config(&self) -> crate::ddos_protection::DDoSConfig {
        crate::ddos_protection::DDoSConfig {
            enabled: self.ddos.enabled,
            max_nbt_depth: self.ddos.max_nbt_depth,
            max_nbt_tag_size: self.ddos.max_nbt_tag_size,
            max_nbt_list_size: self.ddos.max_nbt_list_size,
            nbt_packets_per_sec: self.ddos.nbt_packets_per_sec,
            max_connections_per_sec_per_ip: self.ddos.max_connections_per_sec_per_ip,
            ban_duration_secs: self.ddos.ban_duration_secs,
        }
    }

    pub fn fallback_config(&self) -> crate::fallback::FallbackConfig {
        crate::fallback::FallbackConfig {
            fallback_server: self.fallback.fallback_server.clone(),
            kick_message: self.fallback.kick_message.clone(),
            auto_return: self.fallback.auto_return,
            health_check_interval_secs: self.fallback.health_check_interval_secs,
        }
    }

    pub fn monitor_config(&self) -> crate::backend_monitor::BackendMonitorConfig {
        crate::backend_monitor::BackendMonitorConfig {
            enabled: self.monitor.enabled,
            interval_secs: self.monitor.interval_secs,
        }
    }
}
