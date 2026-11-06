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
    #[serde(default)]
    pub translations: TranslationsSection,
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

/// Все текстовые сообщения прокси (поддерживают HEX & #RRGGBB и multiline \n).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TranslationsSection {
    pub auth_required: String,
    pub welcome: String,
    pub registered: String,
    pub login_success: String,
    pub logged_out: String,
    pub account_not_found: String,
    pub wrong_password: String,
    pub account_deleted: String,
    pub password_changed: String,
    pub password_too_short: String,
    pub username_invalid: String,
    pub tfa_on: String,
    pub tfa_off: String,
    pub tfa_link_first: String,
    pub tfa_status: String,
    pub tfa_help: String,
    pub tfa_2fa_required: String,
    pub tfa_confirm_sent: String,
    pub tfa_confirmed: String,
    pub tfa_denied: String,
    pub tfa_not_linked: String,
    pub link_code_sent: String,
    pub link_success: String,
    pub link_not_linked: String,
    pub link_invalid_code: String,
    pub link_expired: String,
    pub link_wrong_account: String,
    pub link_tg_already_used: String,
    pub captcha_passed: String,
    pub captcha_wrong: String,
    pub captcha_usage: String,
    pub captcha_too_many: String,
    pub captcha_expired: String,
    pub captcha_no_session: String,
    pub captcha_ip_banned: String,
    pub server_switch: String,
    pub server_list_header: String,
    pub server_list_footer: String,
    pub server_list_line: String,
    pub server_online: String,
    pub server_offline: String,
    pub player_not_found: String,
    pub player_found: String,
    pub proxy_stats: String,
    pub unknown_command: String,
    pub no_permission: String,
    pub alert_sent: String,
    pub alert_usage: String,
    pub perm_usage: String,
    pub perm_granted: String,
    pub perm_revoked: String,
    pub perm_unknown: String,
    pub auth_usage: String,
    pub help_header: String,
    pub help_cmd_login: String,
    pub help_cmd_register: String,
    pub help_cmd_logout: String,
    pub help_cmd_link: String,
    pub help_cmd_tfa: String,
    pub help_cmd_captcha: String,
    pub help_cmd_server: String,
    pub help_cmd_hub: String,
    pub help_cmd_find: String,
    pub help_cmd_serverlist: String,
    pub help_cmd_ping: String,
    pub help_cmd_help: String,
    pub help_admin_header: String,
    pub help_auth_delete: String,
    pub help_auth_password: String,
    pub help_perm_grant: String,
    pub help_perm_revoke: String,
    pub shutdown_message: String,
    pub fallback_kick: String,
}

impl Default for TranslationsSection {
    fn default() -> Self {
        Self {
            auth_required: "&c&lТребуется авторизация &f» &fВведите &a/l <пароль> &fили &a/reg <пароль>\n&7Добро пожаловать, &e{player}\n&7После авторизации используйте &a/hub &fдля перехода на лобби.".to_string(),
            welcome: "&a&lАвторизация &f» &fДобро пожаловать, &e{player}\n&7Используйте &a/server <имя> &fили &a/hub &fдля перехода на сервер.\n&fСписок серверов: &a/serverlist".to_string(),
            registered: "&a&lРегистрация &f» &fАккаунт создан. Теперь &a/login <пароль>".to_string(),
            login_success: "&a&lАвторизация &f» &fДобро пожаловать, &e{player}".to_string(),
            logged_out: "&c&lВы вышли из аккаунта &f» &fВведите &a/login <пароль> &fдля входа.".to_string(),
            account_not_found: "&cАккаунт не найден. Зарегистрируйтесь: &f/reg <пароль>".to_string(),
            wrong_password: "&cНеверный пароль.".to_string(),
            account_deleted: "&aАккаунт &f{target} &aудалён из базы аутентификации.".to_string(),
            password_changed: "&aПароль для &f{target} &aизменён.".to_string(),
            password_too_short: "&cПароль должен быть не короче 4 символов.".to_string(),
            username_invalid: "&cНик может содержать только буквы, цифры, подчёркивание и дефис (3-16 символов).".to_string(),
            tfa_on: "&a&l2FA &f» &fПодтверждение входа включено.".to_string(),
            tfa_off: "&c&l2FA &f» &fПодтверждение входа отключено (привязка остаётся).".to_string(),
            tfa_link_first: "&cСначала привяжите Telegram: &f/link".to_string(),
            tfa_status: "&7TFA: &fПривязано: {linked}\n&72FA: &f{enabled}".to_string(),
            tfa_help: "&7TFA команды: &f/tfa on &7| &f/tfa off &7| &f/tfa status".to_string(),
            tfa_2fa_required: "&cТребуется подтверждение через Telegram (2FA).".to_string(),
            tfa_confirm_sent: "&b&l2FA &f» &fЗапрос подтверждения отправлен в Telegram. Ответьте &a/da &fили &c/net &fв боте.".to_string(),
            tfa_confirmed: "&a&lВход подтверждён &f» &fДобро пожаловать, &e{player}".to_string(),
            tfa_denied: "&cВход отклонён через Telegram.".to_string(),
            tfa_not_linked: "&c2FA включён, но Telegram не привязан. Обратитесь к администрации.".to_string(),
            link_code_sent: "&a&lTelegram &f» &fКод привязки отправлен в бота. Введите &f/link <код>".to_string(),
            link_success: "&a&lTelegram &f» &fПривязан к чату &a{chat_id}".to_string(),
            link_not_linked: "&cTelegram не привязан к аккаунту. Обратитесь к администрации.".to_string(),
            link_invalid_code: "&cНеверный код привязки. Запросите новый через /link.".to_string(),
            link_expired: "&cКод привязки истёк. Запросите новый через /link.".to_string(),
            link_wrong_account: "&cКод не принадлежит этому аккаунту.".to_string(),
            link_tg_already_used: "&cЭтот Telegram уже привязан к другому аккаунту.".to_string(),
            captcha_passed: "&a&lCAPTCHA &f» &fПройдено! Освобождение на 4 часа.".to_string(),
            captcha_wrong: "&cНеверный код капчи. Попробуйте ещё раз.".to_string(),
            captcha_usage: "&cИспользование: &f/captcha <код>".to_string(),
            captcha_too_many: "&cСлишком много неудачных попыток. IP заблокирован.".to_string(),
            captcha_expired: "&cКапча истекла. Перезайдите на сервер.".to_string(),
            captcha_no_session: "&cНет активной сессии капчи.".to_string(),
            captcha_ip_banned: "&cIP временно заблокирован из-за неудачных попыток капчи.".to_string(),
            server_switch: "&aПереключился на сервер &f{server}".to_string(),
            server_list_header: "&7=== &bСерверы &7===".to_string(),
            server_list_footer: "\n&fНажмите &a[connect] &fчтобы подключиться.".to_string(),
            server_list_line: "{status} {name} &f{players}/{max} &7{motd}".to_string(),
            server_online: "&a●".to_string(),
            server_offline: "&c●".to_string(),
            player_not_found: "&cИгрок &f{player} &cне найден на серверах.".to_string(),
            player_found: "&7Игрок &f{player} &7на сервере: &a{servers}".to_string(),
            proxy_stats: "&7Прокси: &f{count} &7игроков | &7TPS: &a{tps} &7| &7Серверов: &a{online}/{total}".to_string(),
            unknown_command: "&cНеизвестная команда. &f/help".to_string(),
            no_permission: "&cНет прав на эту команду.".to_string(),
            alert_sent: "&aАлерт отправлен всем игрокам.".to_string(),
            alert_usage: "&cИспользование: &f/alert <сообщение>".to_string(),
            perm_usage: "&7Использование: &f/perm user <ник> <право> &7| &f/perm user <ник> -<право>".to_string(),
            perm_granted: "&aПраво &f{perm} &aвыдано &f{nick}&a.".to_string(),
            perm_revoked: "&cПраво &f{perm} &cзабрано у &f{nick}&c.".to_string(),
            perm_unknown: "&cНеизвестное право. &f/help".to_string(),
            auth_usage: "&7Использование: &f/auth player <ник> delete &7— удалить аккаунт\n&7&f/auth player <ник> password <пароль> &7— сменить пароль".to_string(),
            help_header: "&7=== &bRustProxy &7Команды &7===".to_string(),
            help_cmd_login: "&f/l <пароль> &7— вход".to_string(),
            help_cmd_register: "&f/reg <пароль> &7— регистрация".to_string(),
            help_cmd_logout: "&f/logout &7— выход из аккаунта".to_string(),
            help_cmd_link: "&f/link &7— привязать Telegram".to_string(),
            help_cmd_tfa: "&f/tfa <on|off|status> &7— 2FA".to_string(),
            help_cmd_captcha: "&f/captcha <код> &7— капча".to_string(),
            help_cmd_server: "&f/server <имя> &7— перейти на сервер".to_string(),
            help_cmd_hub: "&f/hub &7— на лобби".to_string(),
            help_cmd_find: "&f/find <игрок> &7— найти игрока".to_string(),
            help_cmd_serverlist: "&f/serverlist &7— список серверов".to_string(),
            help_cmd_ping: "&f/ping &7— пинг прокси".to_string(),
            help_cmd_help: "&f/help &7— эта справка".to_string(),
            help_admin_header: "&7--- Админ ---".to_string(),
            help_auth_delete: "&f/auth player <ник> delete &7— удалить аккаунт".to_string(),
            help_auth_password: "&f/auth player <ник> password <пароль> &7— сменить пароль".to_string(),
            help_perm_grant: "&f/perm user <ник> <право> &7— выдать право".to_string(),
            help_perm_revoke: "&f/perm user <ник> -<право> &7— забрать право".to_string(),
            shutdown_message: "&c&lРЕБУТ СЕРВЕРА &f» &fПрокси перезагружается. Переподключитесь через несколько секунд.".to_string(),
            fallback_kick: "&b&lRustProxy &f» &eСервер &c{server} &eушёл оффлайн. &fПерекидываем на &a{fallback} &bбез дисконнекта.".to_string(),
        }
    }
}

/// Подставить значения в шаблон перевода ({player}, {target} и т.д.)

impl ProxyConfig {
    pub fn t(&self, key: &str, replacements: &[(&str, &str)]) -> String {
    let template = match key {
        "auth_required" => &self.translations.auth_required,
        "welcome" => &self.translations.welcome,
        "registered" => &self.translations.registered,
        "login_success" => &self.translations.login_success,
        "logged_out" => &self.translations.logged_out,
        "account_not_found" => &self.translations.account_not_found,
        "wrong_password" => &self.translations.wrong_password,
        "account_deleted" => &self.translations.account_deleted,
        "password_changed" => &self.translations.password_changed,
        "password_too_short" => &self.translations.password_too_short,
        "username_invalid" => &self.translations.username_invalid,
        "tfa_on" => &self.translations.tfa_on,
        "tfa_off" => &self.translations.tfa_off,
        "tfa_link_first" => &self.translations.tfa_link_first,
        "tfa_status" => &self.translations.tfa_status,
        "tfa_help" => &self.translations.tfa_help,
        "tfa_2fa_required" => &self.translations.tfa_2fa_required,
        "tfa_confirm_sent" => &self.translations.tfa_confirm_sent,
        "tfa_confirmed" => &self.translations.tfa_confirmed,
        "tfa_denied" => &self.translations.tfa_denied,
        "tfa_not_linked" => &self.translations.tfa_not_linked,
        "link_code_sent" => &self.translations.link_code_sent,
        "link_success" => &self.translations.link_success,
        "link_not_linked" => &self.translations.link_not_linked,
        "link_invalid_code" => &self.translations.link_invalid_code,
        "link_expired" => &self.translations.link_expired,
        "link_wrong_account" => &self.translations.link_wrong_account,
        "link_tg_already_used" => &self.translations.link_tg_already_used,
        "captcha_passed" => &self.translations.captcha_passed,
        "captcha_wrong" => &self.translations.captcha_wrong,
        "captcha_usage" => &self.translations.captcha_usage,
        "captcha_too_many" => &self.translations.captcha_too_many,
        "captcha_expired" => &self.translations.captcha_expired,
        "captcha_no_session" => &self.translations.captcha_no_session,
        "captcha_ip_banned" => &self.translations.captcha_ip_banned,
        "server_switch" => &self.translations.server_switch,
        "server_list_header" => &self.translations.server_list_header,
        "server_list_footer" => &self.translations.server_list_footer,
        "server_list_line" => &self.translations.server_list_line,
        "server_online" => &self.translations.server_online,
        "server_offline" => &self.translations.server_offline,
        "player_not_found" => &self.translations.player_not_found,
        "player_found" => &self.translations.player_found,
        "proxy_stats" => &self.translations.proxy_stats,
        "unknown_command" => &self.translations.unknown_command,
        "no_permission" => &self.translations.no_permission,
        "alert_sent" => &self.translations.alert_sent,
        "alert_usage" => &self.translations.alert_usage,
        "perm_usage" => &self.translations.perm_usage,
        "perm_granted" => &self.translations.perm_granted,
        "perm_revoked" => &self.translations.perm_revoked,
        "perm_unknown" => &self.translations.perm_unknown,
        "auth_usage" => &self.translations.auth_usage,
        "help_header" => &self.translations.help_header,
        "help_cmd_login" => &self.translations.help_cmd_login,
        "help_cmd_register" => &self.translations.help_cmd_register,
        "help_cmd_logout" => &self.translations.help_cmd_logout,
        "help_cmd_link" => &self.translations.help_cmd_link,
        "help_cmd_tfa" => &self.translations.help_cmd_tfa,
        "help_cmd_captcha" => &self.translations.help_cmd_captcha,
        "help_cmd_server" => &self.translations.help_cmd_server,
        "help_cmd_hub" => &self.translations.help_cmd_hub,
        "help_cmd_find" => &self.translations.help_cmd_find,
        "help_cmd_serverlist" => &self.translations.help_cmd_serverlist,
        "help_cmd_ping" => &self.translations.help_cmd_ping,
        "help_cmd_help" => &self.translations.help_cmd_help,
        "help_admin_header" => &self.translations.help_admin_header,
        "help_auth_delete" => &self.translations.help_auth_delete,
        "help_auth_password" => &self.translations.help_auth_password,
        "help_perm_grant" => &self.translations.help_perm_grant,
        "help_perm_revoke" => &self.translations.help_perm_revoke,
        "shutdown_message" => &self.translations.shutdown_message,
        "fallback_kick" => &self.translations.fallback_kick,
        _ => key, // неизвестный ключ — возвращаем как есть
    };

    let mut result = template.to_string();
    for (placeholder, value) in replacements {
        result = result.replace(&format!("{{{}}}", placeholder), value);
    }
    crate::messages::format_message(&result)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {:?}", path_str))?;
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
