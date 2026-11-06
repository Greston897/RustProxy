//! Обработка одного соединения игрока с полной интеграцией:
//! Auth (/login /register /l /reg, /auth, /logout), TFA (Telegram /link + /da /net), CAPTCHA, Fallback,
//! DDoS NBT, все команды BungeeCord (кроме /reply /vanish /message /spy),
//! чат-компоненты с clickEvent для [connect]/[server] в лобби.

use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::select;
use tokio::stream::StreamExt;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::codec::Framed;
use futures_util::sink::SinkExt;
use tracing::{debug, error, info, warn};

use crate::auth::{offline_uuid, AuthManager, AuthMode, PlayerProfile, Session};
use crate::permissions::Permission;
use crate::backend_monitor::BackendMonitor;
use crate::captcha::CaptchaManager;
use crate::config::ProxyConfig;
use crate::ddos_protection::DDoSManager;
use crate::fallback;
use crate::messages::{self, format_message, convert_to_minecraft};
use crate::metrics::Metrics;
use serde_json::json;
use crate::protocol::codec::MinecraftCodec;
use crate::protocol::encryption::{self, generate_shared_secret};
use crate::protocol::packets::{
    self, encryption_begin_bytes, encryption_request_bytes, login_success_bytes, parse_encryption_begin,
    parse_encryption_request, parse_handshake, parse_login_start, packet_bytes, split_packet,
    ids::{HANDSHAKE, LOGIN_DISCONNECT, LOGIN_ENCRYPTION_BEGIN, LOGIN_ENCRYPTION_REQUEST, LOGIN_SET_COMPRESSION,
          LOGIN_START, LOGIN_SUCCESS, PLAY_CHAT_MESSAGE, PLAY_CHAT_MESSAGE_CLIENTBOUND,
          STATUS_REQUEST, STATUS_PING, STATUS_RESPONSE, STATUS_PONG},
    EncryptionBegin, EncryptionRequest, LoginStart, LoginSuccess,
};
use crate::protocol::translate::{translate_clientbound, translate_serverbound, TranslationResult};
use crate::protocol::translate::versions::version_info;
use crate::protocol::varint::{read_string, read_varint, varint_bytes, write_varint};
use crate::protocol::versions;
use crate::proxy::{BackendLink, PlayerSession, Proxy};
use crate::tfa::TfaManager;
use uuid::Uuid;

pub type ClientLink = Arc<tokio::sync::Mutex<Framed<TcpStream, MinecraftCodec>>>;

pub async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
) -> Result<()> {
    if proxy.is_shutting_down() {
        return Ok(());
    }

    proxy.metrics.inc_active_connections();
    let _conn_guard = ConnectionGuard {
        metrics: Arc::clone(&proxy.metrics),
    };

    let mut client = Framed::new(stream, MinecraftCodec::new());
    let peer_ip = peer.ip();

    // Продакшен-защита: бан за некорректные пакеты
    if proxy.security.is_bad_packet_banned(peer_ip) {
        return Ok(());
    }

    // Продакшен-защита: лимит игроков на IP
    if !proxy.security.check_ip_limit(peer_ip) {
        warn!(%peer, "Лимит игроков на IP превышен");
        return Ok(());
    }

    // -------------------- Handshake --------------------
    let packet = read_next_with_timeout(&mut client, config.proxy.read_timeout_secs).await?
        .context("peer closed before handshake")?;
    let (id, body) = split_packet(&packet).context("handshake has no packet id")?;
    if id != HANDSHAKE {
        bail!("first packet is not a handshake (id={id})");
    }
    let handshake = parse_handshake(body).context("parse handshake")?;
    debug!(%peer, protocol = handshake.protocol_version, state = handshake.next_state, "handshake");

    if !versions::is_supported(handshake.protocol_version) {
        warn!(%peer, protocol = handshake.protocol_version, "unsupported protocol version");
        if handshake.next_state == 2 {
            send_login_disconnect(&mut client, "&cUnsupported protocol version on this proxy").await?;
        }
        return Ok(());
    }

    match handshake.next_state {
        1 => handle_status(&mut client, &config, peer, &proxy).await?,
        2 => {
            handle_login(&mut client, handshake.protocol_version, config, proxy, peer, peer_ip).await?
        }
        other => bail!("unsupported next state {other}"),
    }
}

struct ConnectionGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.dec_active_connections();
    }
}

// -------------------- Status (ping) --------------------
async fn handle_status(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    config: &ProxyConfig,
    peer: SocketAddr,
    proxy: &Arc<Proxy>,
) -> Result<()> {
    let response = proxy.build_status_response().await;
    let response_bytes = packet_bytes(STATUS_RESPONSE, response.to_string().as_bytes());

    debug!(%peer, "status session started");
    loop {
        match read_next_with_timeout(client, config.proxy.read_timeout_secs).await? {
            Some(pkt) => {
                let (id, body) = split_packet(&pkt)?;
                match id {
                    STATUS_REQUEST => {
                        client.send(response_bytes.clone()).await?;
                    }
                    STATUS_PING => {
                        client.send(packet_bytes(STATUS_PONG, body)).await?;
                    }
                    _ => {}
                }
            }
            None => break,
        }
    }
    Ok(())
}

// -------------------- Login --------------------
async fn handle_login(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    protocol: i32,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    peer: SocketAddr,
    peer_ip: IpAddr,
) -> Result<()> {
    // 1. Login Start
    let packet = read_next_with_timeout(client, config.proxy.read_timeout_secs).await?
        .context("peer closed before login start")?;
    let (id, body) = split_packet(&packet).context("login start has no packet id")?;
    if id != LOGIN_START {
        bail!("expected login start, got id {id}");
    }
    let start = parse_login_start(&body).context("parse login start")?;

    // Валидация имени игрока (защита от слишком длинных / некорректных ников)
    if start.username.is_empty()
        || start.username.len() > 16
        || !start.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        warn!(%peer, "Некорректное имя игрока: {}", start.username);
        send_login_disconnect(
            client,
            &convert_to_minecraft("&cНекорректное имя игрока."),
        )
        .await?;
        return Ok(());
    }

    debug!(%peer, username = %start.username, uuid = %start.uuid, protocol, "login start");

    // 2. IP-кэш авторизации (1 час, сброс при смене IP)
    if let Some((cached_username, cached_uuid)) = proxy.auth.check_ip_auth(peer_ip) {
        if cached_uuid == start.uuid {
            debug!(%peer, "IP auth cache hit for {}", cached_username);
            return handle_login_cached(
                client, protocol, config, proxy, peer, &start, cached_username, cached_uuid, peer_ip,
            ).await;
        }
        proxy.auth.invalidate_ip(&peer_ip);
    }

    // 3. Локальная регистрация/логин (опционально)
    if config.auth_local.enabled && !proxy.auth.account_exists(&start.username) {
        send_login_disconnect(
            client,
            &convert_to_minecraft("&cАккаунт не найден. Зарегистрируйтесь: &f/reg <пароль>"),
        )
        .await?;
        return Ok(());
    }

    // 4. Сессия (офлайн / онлайн / Microsoft-заглушка)
    let session = match config.auth_mode() {
        AuthMode::Offline | AuthMode::Microsoft => {
            let uuid = if start.uuid != Uuid::nil() {
                start.uuid
            } else {
                offline_uuid(&start.username)
            };
            Session {
                profile: PlayerProfile {
                    uuid,
                    username: start.username.clone(),
                    properties: vec![],
                },
                access_token: None,
            }
        }
        AuthMode::Online => {
            let uuid = if start.uuid != Uuid::nil() {
                start.uuid
            } else {
                offline_uuid(&start.username)
            };
            Session {
                profile: PlayerProfile {
                    uuid,
                    username: start.username.clone(),
                    properties: vec![],
                },
                access_token: None,
            }
        }
    };

    // 5. Шифрование (Online mode)
    if config.auth_mode() == AuthMode::Online {
        perform_client_encryption(client, &proxy, &start.username).await?;
    }

    // 6. Сжатие
    if config.proxy.compression_threshold > 0 {
        let threshold = config.proxy.compression_threshold;
        client.codec_mut().set_compression(threshold);
        client
            .send(packet_bytes(LOGIN_SET_COMPRESSION, &varint_bytes(threshold)))
            .await?;
    }

    // 7. Login Success
    let success = LoginSuccess {
        uuid: session.profile.uuid,
        username: session.profile.username.clone(),
    };
    client
        .send(packet_bytes(LOGIN_SUCCESS, &login_success_bytes(&success)))
        .await?;
    info!(%peer, username = %session.profile.username, uuid = %session.profile.uuid, "login success");

    // 8. Подключение к бэкенду + релей логин-фазы
    let default_server = config.proxy.default_server.clone();
    let BackendLink {
        server: _,
        framed: backend,
        protocol: backend_protocol,
    } = proxy.connect_to_server(&default_server, protocol, &start).await?;
    relay_login_phase(client, backend, &*proxy, &start).await?;

    // 9. Play
    handle_play_full(
        client, backend, proxy.config.clone(), proxy, session, protocol,
        backend_protocol, default_server, peer_ip,
    ).await?
}

/// Логин через IP-кэш (без пароля, без TFA).
async fn handle_login_cached(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    protocol: i32,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    peer: SocketAddr,
    start: &LoginStart,
    cached_username: String,
    cached_uuid: Uuid,
    peer_ip: IpAddr,
) -> Result<()> {
    if config.auth_mode() == AuthMode::Online {
        perform_client_encryption(client, &proxy, &cached_username).await?;
    }

    if config.proxy.compression_threshold > 0 {
        let threshold = config.proxy.compression_threshold;
        client.codec_mut().set_compression(threshold);
        client
            .send(packet_bytes(LOGIN_SET_COMPRESSION, &varint_bytes(threshold)))
            .await?;
    }

    let success = LoginSuccess {
        uuid: cached_uuid,
        username: cached_username.clone(),
    };
    client
        .send(packet_bytes(LOGIN_SUCCESS, &login_success_bytes(&success)))
        .await?;

    let BackendLink {
        server: _,
        framed: backend,
        protocol: backend_protocol,
    } = proxy.connect_to_server(&config.proxy.default_server, protocol, start).await?;
    relay_login_phase(client, backend, &*proxy, start).await?;

    handle_play_cached(
        client, proxy.config.clone(), proxy, cached_uuid, cached_username, protocol,
        backend_protocol, config.proxy.default_server.clone(), peer_ip,
    ).await
}

// -------------------- Play: с требованием пароля --------------------
async fn handle_play_full(
    client: Framed<TcpStream, MinecraftCodec>,
    backend: Framed<TcpStream, MinecraftCodec>,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    session: Session,
    client_protocol: i32,
    server_protocol: i32,
    server_name: String,
    peer_ip: IpAddr,
) -> Result<()> {
    let uuid = session.profile.uuid;
    let username = session.profile.username.clone();
    let metrics = Arc::clone(&proxy.metrics);

    metrics.inc_active_players();

    // Продакшен-защита: учитываем игрока в лимите на IP
    proxy.security.add_player_ip(peer_ip);

    let client = Arc::new(tokio::sync::Mutex::new(client));
    let backend = Arc::new(tokio::sync::Mutex::new(backend));

    proxy.players.insert(
        uuid,
        Arc::new(PlayerSession::new(uuid, &username, client_protocol, server_protocol)),
    );

    // Сообщение: нужна авторизация
    let auth_msg = build_auth_required_message(&*config, &username);
    {
        let mut c = client.lock().await;
        c.send(packet_bytes(
            PLAY_CHAT_MESSAGE_CLIENTBOUND,
            auth_msg.as_bytes(),
        ))
        .await?;
    }

    info!(%username, "entered play state (awaiting auth)");

    let (abort_tx, abort_rx) = mpsc::unbounded_channel::<()>();
    let mut current_abort_tx = Some(abort_tx);

    let b_client = Arc::clone(&client);
    let b_backend = Arc::clone(&backend);
    let cp = client_protocol;
    let sp = server_protocol;
    let m = Arc::clone(&metrics);
    let p = Arc::clone(&proxy);
    let sn = server_name.clone();
    let uid = uuid;
    let un = username.clone();
    let rt = config.proxy.read_timeout_secs;
    let mut backend_task: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        backend_to_client_loop(
            b_backend, b_client, abort_rx, un, rt, sp, cp, m, p, sn, uid,
        ).await;
    }));

    let result = client_to_backend_loop_auth(
        client, backend, &config, &proxy, &session, username, client_protocol,
        server_protocol, &mut current_abort_tx, Arc::clone(&metrics), Arc::clone(&proxy),
        peer_ip, server_name,
    ).await;

    if let Some(h) = backend_task.take() {
        h.abort();
    }

    proxy.players.remove(&uuid);
    proxy.captcha.lock().await.remove(&uuid);
    proxy.auth.invalidate_ip(&peer_ip);
    proxy.security.remove_player_ip(peer_ip);
    metrics.dec_active_players();
    info!(%username, "left play state");
    result
}

/// Play: auth уже пройден через IP-кэш.
async fn handle_play_cached(
    client: Framed<TcpStream, MinecraftCodec>,
    backend: Framed<TcpStream, MinecraftCodec>,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    uuid: Uuid,
    username: String,
    client_protocol: i32,
    server_protocol: i32,
    server_name: String,
    peer_ip: IpAddr,
) -> Result<()> {
    let metrics = Arc::clone(&proxy.metrics);
    metrics.inc_active_players();

    // Продакшен-защита: учитываем игрока в лимите на IP
    proxy.security.add_player_ip(peer_ip);

    let client = Arc::new(tokio::sync::Mutex::new(client));
    let backend = Arc::new(tokio::sync::Mutex::new(backend));

    let mut ps = PlayerSession::new(uuid, &username, client_protocol, server_protocol);
    ps.authenticated = true;
    ps.login_ip = Some(peer_ip);
    proxy.players.insert(uuid, Arc::new(ps));

    // Приветствие
    let welcome = build_welcome_message(&*config, &username);
    {
        let mut c = client.lock().await;
        c.send(packet_bytes(
            PLAY_CHAT_MESSAGE_CLIENTBOUND,
            welcome.as_bytes(),
        ))
        .await?;
    }

    info!(%username, "entered play state (auth cached)");

    let (abort_tx, abort_rx) = mpsc::unbounded_channel::<()>();
    let mut current_abort_tx = Some(abort_tx);

    let b_client = Arc::clone(&client);
    let b_backend = Arc::clone(&backend);
    let cp = client_protocol;
    let sp = server_protocol;
    let m = Arc::clone(&metrics);
    let p = Arc::clone(&proxy);
    let sn = server_name.clone();
    let un = username.clone();
    let rt = config.proxy.read_timeout_secs;
    let uid = uuid;
    let mut backend_task: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        backend_to_client_loop(
            b_backend, b_client, abort_rx, un, rt, sp, cp, m, p, sn, uid,
        ).await;
    }));

    let result = client_to_backend_loop_cached(
        client, backend, &config, &proxy, uuid, &username, client_protocol,
        server_protocol, &mut current_abort_tx, Arc::clone(&metrics), Arc::clone(&proxy),
        peer_ip, server_name,
    ).await;

    if let Some(h) = backend_task.take() {
        h.abort();
    }

    proxy.players.remove(&uuid);
    proxy.auth.invalidate_ip(&peer_ip);
    proxy.security.remove_player_ip(peer_ip);
    metrics.dec_active_players();
    info!(%username, "left play state");
    result
}

// -------------------- Шифрование (Online mode) --------------------
async fn perform_client_encryption(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    proxy: &Proxy,
    username: &str,
) -> Result<()> {
    let verify_token = encryption::generate_verify_token();
    let req = EncryptionRequest {
        server_id: String::new(),
        public_key: proxy.key_pair.public_key_der(),
        verify_token: verify_token.clone(),
    };
    client
        .send(packet_bytes(
            LOGIN_ENCRYPTION_REQUEST,
            &encryption_request_bytes(&req),
        ))
        .await?;
    debug!(%username, "encryption request sent");

    let packet = read_next_with_timeout(client, proxy.config.proxy.read_timeout_secs).await?
        .context("client closed before encryption begin")?;
    let (id, body) = split_packet(&packet).context("encryption begin has no packet id")?;
    if id != LOGIN_ENCRYPTION_BEGIN {
        bail!("expected encryption begin, got id {id}");
    }
    let begin = parse_encryption_begin(body).context("parse encryption begin")?;

    if begin.verify_token != verify_token {
        bail!("verify token mismatch (possible spoofing)");
    }

    let shared_secret = proxy
        .key_pair
        .decrypt_shared_secret(&begin.shared_secret)
        .context("failed to decrypt shared secret")?;
    if shared_secret.len() != 16 {
        bail!("shared secret must be 16 bytes, got {}", shared_secret.len());
    }
    let mut secret_arr = [0u8; 16];
    secret_arr.copy_from_slice(&shared_secret);

    client.codec_mut().enable_encryption(&secret_arr);
    info!(%username, "client encryption enabled (AES/CFB8)");
    Ok(())
}

// -------------------- Релей логин-фазы бэкенд → клиент --------------------
async fn relay_login_phase(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    mut backend: Framed<TcpStream, MinecraftCodec>,
    proxy: &Proxy,
    start: &LoginStart,
) -> Result<()> {
    loop {
        match read_next_with_timeout(&mut backend, proxy.config.proxy.read_timeout_secs).await? {
            Some(pkt) => {
                let (id, body) = split_packet(&pkt)?;
                match id {
                    LOGIN_SET_COMPRESSION => {
                        let threshold =
                            read_varint(body).ok_or_else(|| anyhow!("compression varint"))?.1;
                        client.codec_mut().set_compression(threshold);
                        client.send(pkt).await?;
                    }
                    LOGIN_SUCCESS => {
                        client.send(pkt).await?;
                        return Ok(());
                    }
                    LOGIN_DISCONNECT => {
                        client.send(pkt).await?;
                        bail!("backend disconnected player during login");
                    }
                    LOGIN_ENCRYPTION_REQUEST => {
                        let req = parse_encryption_request(body).context("parse backend encryption request")?;
                        let secret = generate_shared_secret();
                        let pub_key = encryption::parse_spki_public_key(&req.public_key)
                            .context("parse backend public key")?;
                        let encrypted_secret = encryption::encrypt_with_public_key(&pub_key, &secret)
                            .context("encrypt shared secret for backend")?;
                        let begin = EncryptionBegin {
                            shared_secret: encrypted_secret.clone(),
                            verify_token: req.verify_token.clone(),
                        };
                        backend
                            .send(packet_bytes(
                                LOGIN_ENCRYPTION_BEGIN,
                                &encryption_begin_bytes(&begin),
                            ))
                            .await?;
                        let mut secret_arr = [0u8; 16];
                        secret_arr.copy_from_slice(&secret);
                        backend.codec_mut().enable_encryption(&secret_arr);
                        info!("backend encryption enabled (AES/CFB8)");
                    }
                    _ => {
                        client.send(pkt).await?;
                    }
                }
            }
            None => bail!("backend closed connection during login"),
        }
    }
}

// -------------------- Play: бэкенд → клиент --------------------
async fn backend_to_client_loop(
    backend: ClientLink,
    client: ClientLink,
    mut abort_rx: mpsc::UnboundedReceiver<()>,
    username: String,
    read_timeout_secs: u64,
    server_protocol: i32,
    client_protocol: i32,
    metrics: Arc<Metrics>,
    proxy: Arc<Proxy>,
    server_name: String,
    uuid: Uuid,
) {
    let from_ver = version_info(server_protocol);
    let to_ver = version_info(client_protocol);

    loop {
        select! {
            res = async {
                let mut b = backend.lock().await;
                read_next_with_timeout(&mut *b, read_timeout_secs).await
            } => match res {
                Ok(Some(pkt)) => {
                    metrics.inc_packets_b2c();

                    let (id, body) = match split_packet(&pkt) {
                        Ok((id, body)) => (id, body.to_vec()),
                        Err(_) => {
                            let mut c = client.lock().await;
                            let _ = c.send(pkt).await;
                            continue;
                        }
                    };

                    let result = match translate_clientbound(id, &body, from_ver, to_ver) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(%username, "clientbound translation failed for {}: {e}", id);
                            metrics.inc_translation_errors();
                            TranslationResult::PassThrough(id, body)
                        }
                    };

                    let send_bytes = match result {
                        TranslationResult::Packet(new_id, data) => {
                            let mut out = Vec::new();
                            write_varint(new_id, &mut out);
                            out.extend_from_slice(&data);
                            out
                        }
                        TranslationResult::PassThrough(_, data) => {
                            let mut out = Vec::new();
                            write_varint(id, &mut out);
                            out.extend_from_slice(&data);
                            out
                        }
                        TranslationResult::Skip => continue,
                    };

                    let mut c = client.lock().await;
                    if c.send(send_bytes).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    warn!(%username, "backend disconnected");
                    return;
                }
                Err(e) => {
                    error!(%username, "backend read error: {e}");
                    metrics.inc_errors();
                    return;
                }
            },
            _ = abort_rx.recv() => return,
        }
    }
}

// -------------------- Play: клиент → бэкенд (с auth / паролем / TFA / капча) --------------------
async fn client_to_backend_loop_auth(
    client: ClientLink,
    backend: ClientLink,
    config: &Arc<ProxyConfig>,
    proxy: &Arc<Proxy>,
    session: &Session,
    username: String,
    client_protocol: i32,
    server_protocol: i32,
    abort_tx: &mut Option<mpsc::UnboundedSender<()>>,
    metrics: Arc<Metrics>,
    proxy_arc: Arc<Proxy>,
    peer_ip: IpAddr,
    server_name: String,
) -> Result<()> {
    use crate::protocol::translate::TranslationResult;

    let start = LoginStart {
        uuid: session.profile.uuid,
        username: session.profile.username.clone(),
    };

    let from_ver = version_info(client_protocol);
    let to_ver = version_info(server_protocol);

    loop {
        let pkt = {
            let mut c = client.lock().await;
            match read_next_with_timeout(&mut *c, config.proxy.read_timeout_secs).await {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(e.into()),
            }
        };

        // Перехват команд прокси
        if let Some(cmd) = parse_proxy_command(&pkt) {
            // Продакшен-защита: лимит команд в секунду
            if !proxy_arc.security.check_command_rate(session.profile.uuid) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                continue;
            }
            handle_all_commands(
                &client, &proxy_arc, &username, &session.profile.uuid, &cmd, peer_ip,
                abort_tx, &server_name, client_protocol,
            ).await?;
            continue;
        }

        // Если не авторизован — блокируем всё кроме чата (команды)
        let is_auth = proxy_arc.players.get(&session.profile.uuid)
            .map(|s| s.authenticated).unwrap_or(false);
        if !is_auth {
            let (id, _) = split_packet(&pkt).unwrap_or((0, &[]));
            if id != PLAY_CHAT_MESSAGE {
                continue;
            }
        }

        metrics.inc_packets_c2b();

        let (id, body) = match split_packet(&pkt) {
            Ok((id, body)) => (id, body.to_vec()),
            Err(_) => {
                let mut b = backend.lock().await;
                if b.send(pkt).await.is_err() {
                    metrics.inc_errors();
                    break;
                }
                continue;
            }
        };

        if is_nbt_packet(id) {
            if !proxy_arc.ddos.check_nbt_packet(peer_ip) {
                warn!(%username, "DDoS: NBT out rate limit");
                metrics.inc_errors();
                continue;
            }
        }

        let result = match translate_serverbound(id, &body, from_ver, to_ver) {
            Ok(r) => r,
            Err(e) => {
                warn!(%username, "serverbound translation failed {}: {e}", id);
                metrics.inc_translation_errors();
                TranslationResult::PassThrough(id, body)
            }
        };

        let send_bytes = match result {
            TranslationResult::Packet(new_id, data) => {
                let mut out = Vec::new();
                write_varint(new_id, &mut out);
                out.extend_from_slice(&data);
                out
            }
            TranslationResult::PassThrough(_, data) => {
                let mut out = Vec::new();
                write_varint(id, &mut out);
                out.extend_from_slice(&data);
                out
            }
            TranslationResult::Skip => continue,
        };

        {
            let mut b = backend.lock().await;
            if b.send(send_bytes).await.is_err() {
                metrics.inc_errors();
                break;
            }
        }
    }
    Ok(())
}

// -------------------- Play: клиент → бэкенд (auth cached) --------------------
async fn client_to_backend_loop_cached(
    client: ClientLink,
    backend: ClientLink,
    config: &Arc<ProxyConfig>,
    proxy: &Arc<Proxy>,
    uuid: Uuid,
    username: String,
    client_protocol: i32,
    server_protocol: i32,
    abort_tx: &mut Option<mpsc::UnboundedSender<()>>,
    metrics: Arc<Metrics>,
    proxy_arc: Arc<Proxy>,
    peer_ip: IpAddr,
    server_name: String,
) -> Result<()> {
    use crate::protocol::translate::TranslationResult;

    let start = LoginStart { uuid, username: username.clone() };
    let from_ver = version_info(client_protocol);
    let to_ver = version_info(server_protocol);

    loop {
        let pkt = {
            let mut c = client.lock().await;
            match read_next_with_timeout(&mut *c, config.proxy.read_timeout_secs).await {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(e.into()),
            }
        };

        if let Some(cmd) = parse_proxy_command(&pkt) {
            if !proxy_arc.security.check_command_rate(uuid) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                continue;
            }
            handle_all_commands(
                &client, &proxy_arc, &username, &uuid, &cmd, peer_ip,
                abort_tx, &server_name, client_protocol,
            ).await?;
            continue;
        }

        metrics.inc_packets_c2b();

        let (id, body) = match split_packet(&pkt) {
            Ok((id, body)) => (id, body.to_vec()),
            Err(_) => {
                let mut b = backend.lock().await;
                if b.send(pkt).await.is_err() {
                    metrics.inc_errors();
                    break;
                }
                continue;
            }
        };

        if is_nbt_packet(id) {
            if !proxy_arc.ddos.check_nbt_packet(peer_ip) {
                warn!(%username, "DDoS: NBT out rate limit");
                metrics.inc_errors();
                continue;
            }
        }

        let result = match translate_serverbound(id, &body, from_ver, to_ver) {
            Ok(r) => r,
            Err(e) => {
                warn!(%username, "serverbound translation failed {}: {e}", id);
                metrics.inc_translation_errors();
                TranslationResult::PassThrough(id, body)
            }
        };

        let send_bytes = match result {
            TranslationResult::Packet(new_id, data) => {
                let mut out = Vec::new();
                write_varint(new_id, &mut out);
                out.extend_from_slice(&data);
                out
            }
            TranslationResult::PassThrough(_, data) => {
                let mut out = Vec::new();
                write_varint(id, &mut out);
                out.extend_from_slice(&data);
                out
            }
            TranslationResult::Skip => continue,
        };

        {
            let mut b = backend.lock().await;
            if b.send(send_bytes).await.is_err() {
                metrics.inc_errors();
                break;
            }
        }
    }
    Ok(())
}

// ========================================================================
// ВСЕ КОМАНДЫ (BungeeCord стиль, кроме /reply /vanish /message /spy)
// ========================================================================

async fn handle_all_commands(
    client: &ClientLink,
    proxy: &Arc<Proxy>,
    username: &str,
    uuid: &Uuid,
    cmd: &str,
    peer_ip: IpAddr,
    abort_tx: &mut Option<mpsc::UnboundedSender<()>>,
    current_server: &str,
    client_protocol: i32,
) -> Result<()> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let command = parts[0].to_lowercase();

    match command.as_str() {
        // ═══ Авторизация ═══
        "/reg" | "/register" => {
            if !proxy.permissions.has(username, Permission::CommandRegister) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("help_cmd_register", &[])).await.ok();
                return Ok(());
            }
            let password = parts[1];
            match proxy.auth.register(username, password) {
                Ok(_) => {
                    proxy.permissions.grant_default(username);
                    send_hex_chat(client, &proxy.config.t("registered", &[])).await.ok();
                    info!(%username, "registered new account");
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/login" | "/l" => {
            if !proxy.permissions.has(username, Permission::CommandLogin) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("help_cmd_login", &[])).await.ok();
                return Ok(());
            }
            let password = parts[1];
            match proxy.auth.login(username, password, *uuid, peer_ip) {
                Ok(()) => {
                    let account = proxy.auth.get_account(username);
                    let tfa_enabled = account.map(|a| a.tfa_enabled).unwrap_or(false);
                    let is_linked = proxy.tfa.lock().await.is_linked(username);

                    if tfa_enabled && is_linked && proxy.config.tfa.enabled {
                        if let Some(acc) = account {
                            if let Some(chat_id) = acc.tg_chat_id.or(proxy.tfa.lock().await.get_chat_id(username)) {
                                let _ = proxy.tfa.lock().await.request_login_confirm(*uuid, username, peer_ip, chat_id).await;
                                send_hex_chat(client, &proxy.config.t("tfa_confirm_sent", &[])).await.ok();
                            } else {
                                send_hex_chat(client, &proxy.config.t("tfa_not_linked", &[])).await.ok();
                            }
                        }
                    } else {
                        if let Some(mut entry) = proxy.players.get_mut(uuid) {
                            let sess = Arc::make_mut(&mut entry);
                            sess.authenticated = true;
                            sess.login_ip = Some(peer_ip);
                        }
                        send_hex_chat(client, &proxy.config.t("login_success", &[("player", username)])).await.ok();

                        if proxy.config.captcha.enabled
                            && !proxy.captcha.lock().await.is_exempt(uuid, peer_ip)
                        {
                            let cs = proxy.captcha.lock().await.create_session(*uuid);
                            send_hex_chat(client, &proxy.captcha.lock().await.captcha_message(&cs)).await.ok();
                        }
                    }
                    info!(%username, "logged in");
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/logout" => {
            if !proxy.permissions.has(username, Permission::CommandLogin) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if let Some(mut entry) = proxy.players.get_mut(uuid) {
                let sess = Arc::make_mut(&mut entry);
                sess.authenticated = false;
                sess.login_ip = None;
            }
            send_hex_chat(client, &proxy.config.t("logged_out", &[])).await.ok();
            info!(%username, "logged out");
        }
        "/tfa" => {
            if !proxy.permissions.has(username, Permission::CommandTfa) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            match parts.get(1) {
                Some("on") => {
                    if proxy.tfa.lock().await.is_linked(username) {
                        let _ = proxy.tfa.lock().await.toggle_tfa(username, true);
                        send_hex_chat(client, &proxy.config.t("tfa_on", &[])).await.ok();
                    } else {
                        send_hex_chat(client, &proxy.config.t("tfa_link_first", &[])).await.ok();
                    }
                }
                Some("off") => {
                    let _ = proxy.tfa.lock().await.toggle_tfa(username, false);
                    send_hex_chat(client, &proxy.config.t("tfa_off", &[])).await.ok();
                }
                Some("status") => {
                    let linked = proxy.tfa.lock().await.is_linked(username);
                    let enabled = proxy.auth.get_account(username)
                        .map(|a| a.tfa_enabled).unwrap_or(false);
                    send_hex_chat(client, &proxy.config.t("tfa_status", &[
                        ("linked", if linked { "&aДа" } else { "&cНет" }),
                        ("enabled", if enabled { "&aВкл" } else { "&cВыкл" }),
                    ])).await.ok();
                }
                _ => {
                    send_hex_chat(client, &proxy.config.t("tfa_help", &[])).await.ok();
                }
            }
        }
        // ═══ TFA /link ═══
        "/link" => {
            if !proxy.permissions.has(username, Permission::CommandLink) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() >= 2 {
                let code = parts[1];
                match proxy.tfa.lock().await.verify_link(code, *uuid, username) {
                    Ok(chat_id) => {
                        send_hex_chat(client, &proxy.config.t("link_success", &[("chat_id", &chat_id.to_string())])).await.ok();
                        info!(%username, "TG linked to {}", chat_id);
                    }
                    Err(e) => {
                        send_hex_chat(client, &format!("&c{}", e)).await.ok();
                    }
                }
            } else {
                let chat_id_opt = proxy.tfa.lock().await.get_chat_id(username);
                if let Some(chat_id) = chat_id_opt {
                    match proxy.tfa.lock().await.request_link(chat_id, username.to_string()).await {
                        Ok(_) => {
                            send_hex_chat(client, &proxy.config.t("link_code_sent", &[])).await.ok();
                        }
                        Err(e) => {
                            send_hex_chat(client, &format!("&cОшибка отправки кода: {}", e)).await.ok();
                        }
                    }
                } else {
                    send_hex_chat(client, &proxy.config.t("link_not_linked", &[])).await.ok();
                }
            }
        }
        // ═══ CAPTCHA ═══
        "/captcha" => {
            if !proxy.permissions.has(username, Permission::CommandCaptcha) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("captcha_usage", &[])).await.ok();
                return Ok(());
            }
            let answer = parts[1];
            match proxy.captcha.lock().await.check_answer(uuid, answer, peer_ip) {
                Ok(true) => {
                    if let Some(mut entry) = proxy.players.get_mut(uuid) {
                        let sess = Arc::make_mut(&mut entry);
                        sess.captcha_verified = true;
                    }
                    send_hex_chat(client, &proxy.config.t("captcha_passed", &[])).await.ok();
                    info!(%username, "CAPTCHA passed");
                }
                Ok(false) => {
                    send_hex_chat(client, &proxy.config.t("captcha_wrong", &[])).await.ok();
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        // ═══ Auth команды (tiAuth / baronessauth стиль) ═══
        "/auth" => {
            if !proxy.permissions.has(username, Permission::CommandAdmin) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("auth_usage", &[])).await.ok();
                return Ok(());
            }
            match parts[1] {
                "player" => {
                    if parts.len() < 3 {
                        send_hex_chat(client, "&cУкажите ник: &f/auth player <ник> <действие>").await.ok();
                        return Ok(());
                    }
                    let target = parts[2];
                    match parts.get(3) {
                        Some("delete") => {
                            match proxy.auth.reset_account(target) {
                                Ok(()) => {
                                    send_hex_chat(client, &proxy.config.t("account_deleted", &[("target", target)])).await.ok();
                                    info!(%username, "deleted account {}", target);
                                }
                                Err(e) => {
                                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                                }
                            }
                        }
                        Some("password") => {
                            if parts.len() < 5 {
                                send_hex_chat(client, "&cИспользование: &f/auth player <ник> password <пароль>").await.ok();
                                return Ok(());
                            }
                            let new_password = parts[4];
                            match proxy.auth.set_password(target, new_password) {
                                Ok(()) => {
                                    send_hex_chat(client, &proxy.config.t("password_changed", &[("target", target)])).await.ok();
                                    info!(%username, "set password for {}", target);
                                }
                                Err(e) => {
                                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                                }
                            }
                        }
                        _ => {
                            send_hex_chat(client, "&7Действия: &fdelete &7| &fpassword <пароль>").await.ok();
                        }
                    }
                }
                _ => {
                    send_hex_chat(client, "&7Использование: &f/auth player <ник> <действие>").await.ok();
                }
            }
        }
        // ═══ BungeeCord команды ═══
        "/server" => {
            if !proxy.permissions.has(username, Permission::CommandServer) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_server_list_message(client, proxy);
                return Ok(());
            }
            do_server_switch(
                client, proxy, username, uuid, parts[1],
                client_protocol, server_protocol, abort_tx,
            ).await?;
        }
        "/hub" | "/lobby" => {
            if !proxy.permissions.has(username, Permission::CommandHub) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            do_server_switch(
                client, proxy, username, uuid, "lobby",
                client_protocol, server_protocol, abort_tx,
            ).await?;
        }
        "/find" => {
            if !proxy.permissions.has(username, Permission::CommandFind) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("help_cmd_find", &[])).await.ok();
                return Ok(());
            }
            let target = parts[1];
            let mut found = Vec::new();
            for entry in proxy.players.iter() {
                if entry.value().username == target {
                    found.push(entry.value().username.clone());
                }
            }
            if found.is_empty() {
                send_hex_chat(client, &format!("&cИгрок &f{} &cне найден на серверах.", target)).await.ok();
            } else {
                send_hex_chat(client, &format!("&7Игрок &f{} &7на сервере: &a{}", target, found.join(", "))).await.ok();
            }
        }
        "/serverlist" => {
            if !proxy.permissions.has(username, Permission::CommandServerList) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            send_server_list_message(client, proxy);
        }
        "/ping" => {
            if !proxy.permissions.has(username, Permission::CommandPing) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            let count = proxy.players.len();
            let monitor = &proxy.monitor;
            send_hex_chat(client, &format!(
                "&7Прокси: &f{} &7игроков | &7TPS: &a{:.1} &7| &7Серверов: &a{}/{}",
                count,
                monitor.average_tps(),
                monitor.online_count(),
                monitor.all().len()
            )).await.ok();
        }
        "/help" => {
            if !proxy.permissions.has(username, Permission::CommandHelp) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            send_hex_chat(client, &proxy.config.t("help_header", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_login", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_register", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_logout", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_link", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_tfa", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_captcha", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_server", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_hub", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_find", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_serverlist", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_ping", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_cmd_help", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_admin_header", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_auth_delete", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_auth_password", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_perm_grant", &[])).await.ok();
                send_hex_chat(client, &proxy.config.t("help_perm_revoke", &[])).await.ok();
        }
        // ═══ Админ-команды (права доступа) ═══
        "/perm" => {
            if !proxy.permissions.has(username, Permission::CommandPerm) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 4 {
                send_hex_chat(client, &proxy.config.t("perm_usage", &[])).await.ok();
                send_hex_chat(client, "&7Права: &fcommand.server command.hub command.login command.register command.link command.tfa command.captcha command.ping command.help command.find command.serverlist command.proxy command.alert command.admin command.perm").await.ok();
                return Ok(());
            }
            let target = parts[1];
            if target != "user" {
                send_hex_chat(client, "&cИспользование: &f/perm user <ник> <право>").await.ok();
                return Ok(());
            }
            let nick = parts[2];
            let perm_str = parts[3];
            let (grant, perm_name) = if perm_str.starts_with('-') {
                (false, &perm_str[1..])
            } else {
                (true, perm_str)
            };
            match Permission::from_str(perm_name) {
                Some(perm) => {
                    if grant {
                        proxy.permissions.grant(nick, perm);
                        send_hex_chat(client, &proxy.config.t("perm_granted", &[("perm", perm.as_str()), ("nick", nick)])).await.ok();
                    } else {
                        proxy.permissions.revoke(nick, perm);
                        send_hex_chat(client, &proxy.config.t("perm_revoked", &[("perm", perm.as_str()), ("nick", nick)])).await.ok();
                    }
                }
                None => {
                    send_hex_chat(client, &proxy.config.t("perm_unknown", &[])).await.ok();
                }
            }
        }
        "/alert" => {
            if !proxy.permissions.has(username, Permission::CommandAlert) {
                send_hex_chat(client, &proxy.config.t("no_permission", &[])).await.ok();
                return Ok(());
            }
            if parts.len() < 2 {
                send_hex_chat(client, &proxy.config.t("alert_usage", &[])).await.ok();
                return Ok(());
            }
            let message = parts[1..].join(" ");
            let payload = serde_json::json!({"text": "", "extra": [
                serde_json::json!({"text": "&c&lАЛЕРТ &f» &f", "color": "reset"}),
                serde_json::json!({"text": convert_to_minecraft(&message), "color": "reset"}),
            ]}).to_string();
            let pkt = packet_bytes(PLAY_CHAT_MESSAGE_CLIENTBOUND, payload.as_bytes());
            for entry in proxy.players.iter() {
                let _ = entry.value().client.lock().await.send(pkt.clone()).await;
            }
            send_hex_chat(client, &proxy.config.t("alert_sent", &[])).await.ok();
        }
        // Исключены пользователем: /reply /vanish /message /spy
        _ => {
            send_hex_chat(client, &proxy.config.t("unknown_command", &[])).await.ok();
        }
    }
    Ok(())
}

/// Переключение сервера (/server, /hub, /lobby).
async fn do_server_switch(
    client: &ClientLink,
    proxy: &Arc<Proxy>,
    username: &str,
    uuid: &Uuid,
    name: &str,
    client_protocol: i32,
    server_protocol: i32,
    abort_tx: &mut Option<mpsc::UnboundedSender<()>>,
) -> Result<()> {
    info!(%username, target = %name, "server switch requested");
    proxy.metrics.inc_server_switches();

    let new_link = proxy.connect_to_server(name, client_protocol, &LoginStart {
        uuid: *uuid,
        username: username.to_string(),
    }).await?;
    let new_server_protocol = new_link.protocol;
    let mut framed = new_link.framed;

    {
        let mut c = client.lock().await;
        relay_login_phase(&mut c, &mut framed, proxy, &LoginStart {
            uuid: *uuid,
            username: username.to_string(),
        }).await?;
    }

    if let Some(mut entry) = proxy.players.get_mut(uuid) {
        let sess = Arc::make_mut(&mut entry);
        sess.server_protocol = new_server_protocol;
    }

    // Только после успешного переключения заменяем abort-канал (старые задачи прерываются)
    let (abort_tx2, abort_rx2) = mpsc::unbounded_channel::<()>();
    let _old = std::mem::replace(abort_tx, Some(abort_tx2));
    let _ = _old; // старый канал больше не нужен, его задача уже должна завершиться
    let b_client = Arc::clone(client);
    let b_backend = Arc::new(tokio::sync::Mutex::new(framed));
    let m = Arc::clone(&proxy.metrics);
    let p = Arc::clone(proxy);
    let sn = name.to_string();
    let un = username.to_string();
    let uid = *uuid;
    let rt = proxy.config.proxy.read_timeout_secs;
    let cp = client_protocol;
    let sp = new_server_protocol;
    tokio::spawn(async move {
        backend_to_client_loop(
            b_backend, b_client, abort_rx2, un, rt, sp, cp, m, p, sn, uid,
        ).await;
    });

    send_hex_chat(client, &proxy.config.t("server_switch", &[("server", name)])).await.ok();
    Ok(())
}

/// Сообщение со списком серверов с кликабельными [connect].
fn send_server_list_message(client: &ClientLink, proxy: &Arc<Proxy>) {
    let proxy_arc = Arc::clone(proxy);
    let client_arc = client.clone();
    let header = proxy.config.t("server_list_header", &[]);
    let footer = proxy.config.t("server_list_footer", &[]);
    let online_str = proxy.config.t("server_online", &[]);
    let offline_str = proxy.config.t("server_offline", &[]);
    tokio::spawn(async move {
        let mut extra: Vec<serde_json::Value> = Vec::new();
        extra.push(serde_json::json!({"text": header, "color": "reset"}));

        for entry in proxy_arc.servers.iter() {
            let s = entry.value();
            let online = s.online.load(std::sync::atomic::Ordering::Relaxed);
            let players = s.players.load(std::sync::atomic::Ordering::Relaxed);
            let max = s.max;
            let status = if online { online_str.as_str() } else { offline_str.as_str() };
            let motd = s.motd.read().await.clone();
            let line = format!(
                "{} {} &f{}/{} &7{}",
                status, s.name, players, max, motd
            );
            extra.push(serde_json::json!({
                "text": convert_to_minecraft(&line),
                "color": "reset"
            }));
            extra.push(serde_json::json!({
                "text": "  [connect] ",
                "color": "a",
                "clickEvent": {"action": "run_command", "value": format!("/server {}", s.name)}
            }));
            extra.push(serde_json::json!({"text": "\\n", "color": "reset"}));
        }

        extra.push(serde_json::json!({"text": footer, "color": "reset"}));

        let payload = serde_json::json!({"text": "", "extra": extra}).to_string();
        let _ = client_arc.lock().await.send(packet_bytes(
            PLAY_CHAT_MESSAGE_CLIENTBOUND,
            payload.as_bytes(),
        )).await;
    });
}

/// Сообщение: требуется авторизация (перевод из конфига).
fn build_auth_required_message(config: &crate::config::ProxyConfig, username: &str) -> String {
    config.t("auth_required", &[("player", username)])
}

/// Приветственное сообщение (после авторизации, перевод из конфига).
fn build_welcome_message(config: &crate::config::ProxyConfig, username: &str) -> String {
    config.t("welcome", &[("player", username)])
}

// ========================================================================
// Вспомогательное
// ========================================================================

fn is_nbt_packet(id: i32) -> bool {
    matches!(id, 0x11 | 0x12 | 0x18 | 0x2D | 0x2E)
}

pub async fn send_hex_chat_to_link(link: &ClientLink, text: &str) -> Result<()> {
    let formatted = format_message(text);
    let mut c = link.lock().await;
    c.send(packet_bytes(PLAY_CHAT_MESSAGE_CLIENTBOUND, formatted.as_bytes())).await
}

async fn send_hex_chat(client: &ClientLink, text: &str) -> Result<()> {
    let formatted = format_message(text);
    let mut c = client.lock().await;
    c.send(packet_bytes(
        PLAY_CHAT_MESSAGE_CLIENTBOUND,
        formatted.as_bytes(),
    ))
    .await
}

async fn send_login_disconnect(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    reason: &str,
) -> Result<()> {
    let component = serde_json::json!({"text": convert_to_minecraft(reason), "color": "reset"}).to_string();
    client
        .send(packet_bytes(LOGIN_DISCONNECT, component.as_bytes()))
        .await?;
    Ok(())
}

async fn read_next_with_timeout(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    timeout_secs: u64,
) -> Result<Option<Vec<u8>>> {
    match time::timeout(Duration::from_secs(timeout_secs), client.next()).await {
        Ok(Some(Ok(pkt))) => Ok(Some(pkt)),
        Ok(Some(Err(e))) => Err(e.into()),
        Ok(None) => Ok(None),
        Err(_) => bail!("read timeout after {timeout_secs}s"),
    }
}

fn parse_proxy_command(pkt: &[u8]) -> Option<String> {
    let (id, body) = split_packet(pkt).ok()?;
    if id != PLAY_CHAT_MESSAGE {
        return None;
    }
    let (_, msg) = read_string(body).map(|(_, s)| s)?;
    if msg.starts_with('/') {
        Some(msg)
    } else {
        None
    }
}

use std::sync::atomic::Ordering;
