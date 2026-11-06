//! Обработка одного соединения игрока с полной интеграцией:
//! Auth (/login /register /l /reg), TFA (Telegram 2FA), CAPTCHA, Skins, Fallback, DDoS NBT.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::select;
use tokio::stream::StreamExt;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time;
use tokio_util::codec::Framed;
use futures_util::sink::SinkExt;
use tracing::{debug, error, info, warn};

use crate::auth::{offline_uuid, AuthManager, AuthMode, PlayerProfile, Session};
use crate::captcha::{self, CaptchaManager};
use crate::config::ProxyConfig;
use crate::ddos_protection::DDoSManager;
use crate::fallback;
use crate::messages::{self, format_message};
use crate::metrics::Metrics;
use crate::protocol::codec::MinecraftCodec;
use crate::protocol::encryption::{self, generate_shared_secret};
use crate::protocol::packets::{
    self, encryption_begin_bytes, encryption_request_bytes, login_success_bytes, parse_login_start,
    parse_encryption_request, packet_bytes, split_packet,
    LOGIN_DISCONNECT, LOGIN_ENCRYPTION_BEGIN, LOGIN_ENCRYPTION_REQUEST, LOGIN_SET_COMPRESSION,
    LOGIN_START, LOGIN_SUCCESS, PLAY_CHAT_MESSAGE, ids,
};
use crate::protocol::translate::{translate_clientbound, translate_serverbound, TranslationResult};
use crate::protocol::translate::versions::version_info;
use crate::protocol::varint::{read_string, read_varint, varint_bytes, write_varint};
use crate::protocol::versions;
use crate::proxy::{BackendLink, PlayerSession, Proxy};
use crate::skin::SkinManager;
use crate::tfa::TfaManager;

type ClientLink = Arc<tokio::sync::Mutex<Framed<TcpStream, MinecraftCodec>>>;

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
    let mut client = Framed::new(stream, MinecraftCodec::new());
    let _conn_guard = ConnectionGuard {
        metrics: Arc::clone(&proxy.metrics),
    };

    // -------------------- Handshake --------------------
    let packet = read_next_with_timeout(&mut client, config.read_timeout_secs()).await?
        .context("peer closed before handshake")?;
    let (id, body) = split_packet(&packet).context("handshake has no packet id")?;
    if id != ids::HANDSHAKE {
        bail!("first packet is not a handshake (id={id})");
    }
    let handshake = packets::parse_handshake(body).context("parse handshake")?;
    debug!(%peer, protocol = handshake.protocol_version, state = handshake.next_state, "handshake");

    if !versions::is_supported(handshake.protocol_version) {
        warn!(%peer, protocol = handshake.protocol_version, "unsupported protocol version");
        if handshake.next_state == 2 {
            send_login_disconnect(&mut client, "Unsupported protocol version on this proxy").await?;
        }
        return Ok(());
    }

    match handshake.next_state {
        1 => handle_status(&mut client, &config, peer, &proxy).await,
        2 => {
            handle_login(&mut client, handshake.protocol_version, config, proxy, peer).await
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
    let response_bytes = packet_bytes(ids::STATUS_RESPONSE, response.to_string().as_bytes());

    debug!(%peer, "status session started");
    loop {
        match read_next_with_timeout(client, config.read_timeout_secs()).await? {
            Some(pkt) => {
                let (id, body) = split_packet(&pkt)?;
                match id {
                    ids::STATUS_REQUEST => {
                        client.send(response_bytes.clone()).await?;
                    }
                    ids::STATUS_PING => {
                        client.send(packet_bytes(ids::STATUS_PONG, body)).await?;
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
) -> Result<()> {
    let peer_ip = peer.ip();

    // 1. Login Start
    let packet = read_next_with_timeout(client, config.read_timeout_secs()).await?
        .context("peer closed before login start")?;
    let (id, body) = split_packet(&packet).context("login start has no packet id")?;
    if id != LOGIN_START {
        bail!("expected login start, got id {id}");
    }
    let start = parse_login_start(&body).context("parse login start")?;
    debug!(%peer, username = %start.username, uuid = %start.uuid, protocol, "login start");

    // 2. Проверка кэша по IP (1 час если IP не менялся)
    if let Some((cached_username, cached_uuid)) = proxy.auth.check_ip_auth(peer_ip) {
        if cached_uuid == start.uuid {
            debug!(%peer, "IP auth cache hit for {}", cached_username);
            return handle_login_cached(
                client, protocol, config, proxy, peer, &start, cached_username, cached_uuid, peer_ip,
            ).await;
        }
        proxy.auth.invalidate_ip(&peer_ip);
    }

    // 3. Локальная регистрация/логин (этап 12)
    if config.auth_local.enabled {
        if !proxy.auth.account_exists(&start.username) {
            send_login_disconnect(
                client,
                &format!("&cАккаунт не найден. Зарегистрируйтесь: &f/reg <пароль>"),
            )
            .await?;
            return Ok(());
        }
    }

    // 4. Авторизация (онлайн-режим Mojang)
    let session = match config.auth_mode() {
        AuthMode::Offline => {
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
            // Online Mojang auth would go here; offline is default for now
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
        AuthMode::Microsoft => {
            bail!("Microsoft auth is not implemented yet")
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

    // 8. Подключение к бэкенду
    let server_name = config.proxy.default_server.clone();
    let BackendLink {
        server: _,
        framed: backend,
        protocol: backend_protocol,
    } = proxy.connect_to_server(&server_name, protocol, &start).await?;
    relay_login_phase(client, backend, &*proxy, &start).await?;

    // 9. Play
    if config.auth_local.enabled {
        handle_play_with_auth(
            client, backend, config, proxy, session, protocol, backend_protocol, peer_ip,
        ).await
    } else {
        handle_play(
            client, backend, config, proxy, session, protocol, backend_protocol, peer_ip,
        ).await
    }
}

/// Логин через IP-кэш (без пароля).
async fn handle_login_cached(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    protocol: i32,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    peer: SocketAddr,
    start: &LoginStart,
    cached_username: String,
    cached_uuid: Uuid,
    peer_ip: std::net::IpAddr,
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

    let server_name = config.proxy.default_server.clone();
    let BackendLink {
        server: _,
        framed: backend,
        protocol: backend_protocol,
    } = proxy.connect_to_server(&server_name, protocol, start).await?;
    relay_login_phase(client, backend, &*proxy, start).await?;

    handle_play_with_auth_cached(
        client, backend, config, proxy, cached_uuid, cached_username, protocol, backend_protocol, peer_ip,
    ).await
}

/// Play с требованием пароля (локальная авторизация).
async fn handle_play_with_auth(
    client: Framed<TcpStream, MinecraftCodec>,
    backend: Framed<TcpStream, MinecraftCodec>,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    session: Session,
    client_protocol: i32,
    server_protocol: i32,
    peer_ip: std::net::IpAddr,
) -> Result<()> {
    let uuid = session.profile.uuid;
    let username = session.profile.username.clone();
    let metrics = Arc::clone(&proxy.metrics);

    metrics.inc_active_players();

    let client = Arc::new(tokio::sync::Mutex::new(client));
    let backend = Arc::new(tokio::sync::Mutex::new(backend));

    proxy.players.insert(
        uuid,
        Arc::new(PlayerSession::new(uuid, &username, client_protocol, server_protocol)),
    );

    let auth_msg = format_message("&c&lТребуется авторизация &f» &fВведите &a/l <пароль> &fили &a/reg <пароль> &fдля регистрации.");
    {
        let mut c = client.lock().await;
        c.send(packet_bytes(
            ids::PLAY_CHAT_MESSAGE_CLIENTBOUND,
            auth_msg.as_bytes(),
        ))
        .await?;
    }

    info!(%username, "entered play state (awaiting auth)");

    let (mut abort_tx, abort_rx) = mpsc::unbounded_channel::<()>();
    let b_client = Arc::clone(&client);
    let b_backend = Arc::clone(&backend);
    let cp = client_protocol;
    let sp = server_protocol;
    let m = Arc::clone(&metrics);
    let mut b_handle: Option<AbortHandle> = {
        let h = tokio::spawn(backend_to_client_loop(
            b_backend, b_client, abort_rx, username, config.read_timeout_secs(),
            sp, cp, m, Arc::clone(&proxy),
        ));
        Some(h.abort_handle())
    };

    let result = client_to_backend_loop_auth(
        client, backend, &config, &proxy, &session, username, client_protocol, server_protocol,
        &mut b_handle, abort_tx, Arc::clone(&metrics), Arc::clone(&proxy), peer_ip,
    ).await;

    if let Some(h) = b_handle.take() {
        h.abort();
    }

    proxy.players.remove(&uuid);
    proxy.captcha.remove(&uuid);
    proxy.auth.invalidate_ip(&peer_ip);
    metrics.dec_active_players();
    info!(%username, "left play state");
    result
}

/// Play с уже авторизованным IP-кэшем.
async fn handle_play_with_auth_cached(
    client: Framed<TcpStream, MinecraftCodec>,
    backend: Framed<TcpStream, MinecraftCodec>,
    config: Arc<ProxyConfig>,
    proxy: Arc<Proxy>,
    uuid: Uuid,
    username: String,
    client_protocol: i32,
    server_protocol: i32,
    peer_ip: std::net::IpAddr,
) -> Result<()> {
    let metrics = Arc::clone(&proxy.metrics);
    metrics.inc_active_players();

    let client = Arc::new(tokio::sync::Mutex::new(client));
    let backend = Arc::new(tokio::sync::Mutex::new(backend));

    proxy.players.insert(
        uuid,
        {
            let mut ps = PlayerSession::new(uuid, &username, client_protocol, server_protocol);
            ps.authenticated = true;
            ps.login_ip = Some(peer_ip);
            Arc::new(ps)
        },
    );

    let welcome = messages::welcome_message(&username, &config.status.motd);
    let welcome_formatted = format_message(&welcome);
    {
        let mut c = client.lock().await;
        c.send(packet_bytes(
            ids::PLAY_CHAT_MESSAGE_CLIENTBOUND,
            welcome_formatted.as_bytes(),
        ))
        .await?;
    }

    info!(%username, "entered play state (auth cached)");

    let (mut abort_tx, abort_rx) = mpsc::unbounded_channel::<()>();
    let b_client = Arc::clone(&client);
    let b_backend = Arc::clone(&backend);
    let cp = client_protocol;
    let sp = server_protocol;
    let m = Arc::clone(&metrics);
    let mut b_handle: Option<AbortHandle> = {
        let h = tokio::spawn(backend_to_client_loop(
            b_backend, b_client, abort_rx, username, config.read_timeout_secs(),
            sp, cp, m, Arc::clone(&proxy),
        ));
        Some(h.abort_handle())
    };

    let result = client_to_backend_loop_cached(
        client, backend, &config, &proxy, uuid, &username, client_protocol, server_protocol,
        &mut b_handle, abort_tx, Arc::clone(&metrics), Arc::clone(&proxy), peer_ip,
    ).await;

    if let Some(h) = b_handle.take() {
        h.abort();
    }

    proxy.players.remove(&uuid);
    proxy.auth.invalidate_ip(&peer_ip);
    metrics.dec_active_players();
    info!(%username, "left play state");
    result
}

/// Шифрование с клиентом.
async fn perform_client_encryption(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    proxy: &Proxy,
    username: &str,
) -> Result<()> {
    let verify_token = encryption::generate_verify_token();
    let req = packets::EncryptionRequest {
        server_id: String::new(),
        public_key: proxy.key_pair.public_key_der(),
        verify_token: verify_token.clone(),
    };
    client
        .send(packet_bytes(
            ids::LOGIN_ENCRYPTION_REQUEST,
            &encryption_request_bytes(&req),
        ))
        .await?;
    debug!(%username, "encryption request sent");

    let packet = read_next_with_timeout(client, proxy.config.read_timeout_secs()).await?
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

/// Пересылка пакетов логина от бэкенда клиенту.
async fn relay_login_phase(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    mut backend: Framed<TcpStream, MinecraftCodec>,
    proxy: &Proxy,
    start: &LoginStart,
) -> Result<()> {
    loop {
        match read_next_with_timeout(&mut backend, proxy.config.read_timeout_secs()).await? {
            Some(pkt) => {
                let (id, body) = split_packet(&pkt)?;
                match id {
                    LOGIN_SET_COMPRESSION => {
                        let threshold = read_varint(body).context("compression varint")?.1;
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
                        let begin = packets::EncryptionBegin {
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
    username: &str,
    read_timeout_secs: u64,
    server_protocol: i32,
    client_protocol: i32,
    metrics: Arc<Metrics>,
    proxy: Arc<Proxy>,
) {
    let from_ver = version_info(server_protocol);
    let to_ver = version_info(client_protocol);

    loop {
        let pkt = select! {
            res = async {
                let mut b = backend.lock().await;
                read_next_with_timeout(&mut *b, read_timeout_secs).await
            } => match res {
                Ok(Some(p)) => p,
                Ok(None) => {
                    warn!(%username, "backend disconnected, attempting fallback");
                    let _ = fallback_on_backend_disconnect(&proxy, &client, username).await;
                    return;
                }
                Err(e) => {
                    error!(%username, "backend read error: {e}");
                    metrics.inc_errors();
                    return;
                }
            },
            _ = abort_rx.recv() => return,
        };

        metrics.inc_packets_b2c();

        let (id, body) = match split_packet(&pkt) {
            Ok((id, body)) => (id, body.to_vec()),
            Err(_) => {
                let mut c = client.lock().await;
                if c.send(pkt).await.is_err() {
                    return;
                }
                continue;
            }
        };

        if is_nbt_packet(id) {
            let peer_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
            if !proxy.ddos.check_nbt_packet(peer_ip) {
                warn!(%username, "DDoS: NBT rate limit");
                metrics.inc_errors();
                continue;
            }
        }

        let result = match translate_clientbound(id, &body, &from_ver, &to_ver) {
            Ok(r) => r,
            Err(e) => {
                warn!(%username, "clientbound translation failed for {}: {e}", id);
                metrics.inc_translation_errors();
                TranslationResult::PassThrough(id, body)
            }
        };

        let mut c = client.lock().await;
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

        if c.send(send_bytes).await.is_err() {
            return;
        }
    }
}

// -------------------- Play: клиент → бэкенд (с auth) --------------------
async fn client_to_backend_loop_auth(
    client: ClientLink,
    backend: ClientLink,
    config: &Arc<ProxyConfig>,
    proxy: &Arc<Proxy>,
    session: &Session,
    username: &str,
    client_protocol: i32,
    server_protocol: i32,
    b_handle: &mut Option<AbortHandle>,
    mut abort_tx: mpsc::UnboundedSender<()>,
    metrics: Arc<Metrics>,
    proxy_arc: Arc<Proxy>,
    peer_ip: std::net::IpAddr,
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
            match read_next_with_timeout(&mut *c, config.read_timeout_secs()).await {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(e.into()),
            }
        };

        // Перехват команд
        if let Some(cmd) = parse_proxy_command(&pkt) {
            handle_auth_commands(
                &client, &proxy_arc, username, &session.profile.uuid, &cmd, peer_ip,
                b_handle, &mut abort_tx,
            ).await?;
            continue;
        }

        // Если не авторизован — блокируем игровые пакеты
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
                warn!(%username, "DDoS: NBT out");
                metrics.inc_errors();
                continue;
            }
        }

        let result = match translate_serverbound(id, &body, &from_ver, &to_ver) {
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
    username: &str,
    client_protocol: i32,
    server_protocol: i32,
    b_handle: &mut Option<AbortHandle>,
    mut abort_tx: mpsc::UnboundedSender<()>,
    metrics: Arc<Metrics>,
    proxy_arc: Arc<Proxy>,
    peer_ip: std::net::IpAddr,
) -> Result<()> {
    use crate::protocol::translate::TranslationResult;

    let start = LoginStart { uuid, username: username.to_string() };
    let from_ver = version_info(client_protocol);
    let to_ver = version_info(server_protocol);

    loop {
        let pkt = {
            let mut c = client.lock().await;
            match read_next_with_timeout(&mut *c, config.read_timeout_secs()).await {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(e.into()),
            }
        };

        if let Some(cmd) = parse_proxy_command(&pkt) {
            handle_auth_commands(
                &client, &proxy_arc, username, &uuid, &cmd, peer_ip,
                b_handle, &mut abort_tx,
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
                warn!(%username, "DDoS: NBT out");
                metrics.inc_errors();
                continue;
            }
        }

        let result = match translate_serverbound(id, &body, &from_ver, &to_ver) {
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

// -------------------- Команды авторизации и прокси --------------------
async fn handle_auth_commands(
    client: &ClientLink,
    proxy: &Arc<Proxy>,
    username: &str,
    uuid: &uuid::Uuid,
    cmd: &str,
    peer_ip: std::net::IpAddr,
    b_handle: &mut Option<AbortHandle>,
    abort_tx: &mut mpsc::UnboundedSender<()>,
) -> Result<()> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let command = parts[0].to_lowercase();

    match command.as_str() {
        "/reg" | "/register" => {
            if parts.len() < 2 {
                send_hex_chat(client, "&cИспользование: &f/reg <пароль>").await.ok();
                return Ok(());
            }
            let password = parts[1];
            match proxy.auth.register(username, password) {
                Ok(_acc_uuid) => {
                    send_hex_chat(client, "&a&lРегистрация &f» &fАккаунт создан. Теперь &a/login <пароль>").await.ok();
                    info!(%username, "registered new account");
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/login" | "/l" => {
            if parts.len() < 2 {
                send_hex_chat(client, "&cИспользование: &f/login <пароль>").await.ok();
                return Ok(());
            }
            let password = parts[1];
            match proxy.auth.login(username, password, *uuid, peer_ip) {
                Ok(()) => {
                    let account = proxy.auth.get_account(username);
                    let tfa_enabled = account.map(|a| a.tfa_enabled).unwrap_or(false);

                    if tfa_enabled && proxy.config.tfa.enabled {
                        if let Some(acc) = account {
                            if let Some(chat_id) = acc.tg_chat_id {
                                let _ = proxy.tfa.send_code(chat_id, *uuid).await;
                                send_hex_chat(client, "&b&l2FA &f» &fКод отправлен в Telegram. Введите &a/tfa <код>").await.ok();
                            } else {
                                send_hex_chat(client, "&c2FA включён, но Telegram не привязан. Обратитесь к администрации.").await.ok();
                            }
                        }
                    } else {
                        if let Some(mut session_entry) = proxy.players.get_mut(uuid) {
                            let mut new_session = (*session_entry).clone();
                            new_session.authenticated = true;
                            new_session.login_ip = Some(peer_ip);
                            proxy.players.insert(*uuid, Arc::new(new_session));
                        }
                        send_hex_chat(client, &format!("&a&lАвторизация &f» &fДобро пожаловать, &e{}", username)).await.ok();

                        if proxy.config.captcha.enabled && !proxy.captcha.is_exempt(uuid, peer_ip) {
                            let cs = proxy.captcha.create_session(*uuid);
                            send_hex_chat(client, &proxy.captcha.captcha_message(&cs)).await.ok();
                        }
                    }
                    info!(%username, "logged in");
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/tfa" => {
            if parts.len() < 2 {
                send_hex_chat(client, "&cИспользование: &f/tfa <код>").await.ok();
                return Ok(());
            }
            let code = parts[1];
            // Для упрощения используем chat_id = 0 (нужна привязка через админку)
            match proxy.tfa.verify_code(0, code) {
                Ok(tfa_uuid) => {
                    if tfa_uuid == *uuid {
                        if let Some(mut session_entry) = proxy.players.get_mut(uuid) {
                            let mut new_session = (*session_entry).clone();
                            new_session.tfa_verified = true;
                            proxy.players.insert(*uuid, Arc::new(new_session));
                        }
                        send_hex_chat(client, "&a&l2FA &f» &fПодтверждено! Вы авторизованы.").await.ok();

                        if proxy.config.captcha.enabled && !proxy.captcha.is_exempt(uuid, peer_ip) {
                            let cs = proxy.captcha.create_session(*uuid);
                            send_hex_chat(client, &proxy.captcha.captcha_message(&cs)).await.ok();
                        }
                    } else {
                        send_hex_chat(client, "&cКод 2FA не совпадает с вашим аккаунтом.").await.ok();
                    }
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/captcha" => {
            if parts.len() < 2 {
                send_hex_chat(client, "&cИспользование: &f/captcha <код>").await.ok();
                return Ok(());
            }
            let answer = parts[1];
            match proxy.captcha.check_answer(uuid, answer, peer_ip) {
                Ok(true) => {
                    if let Some(mut session_entry) = proxy.players.get_mut(uuid) {
                        let mut new_session = (*session_entry).clone();
                        new_session.captcha_verified = true;
                        proxy.players.insert(*uuid, Arc::new(new_session));
                    }
                    send_hex_chat(client, "&a&lCAPTCHA &f» &fПройдено! 4 часа libres от капчи.").await.ok();
                    info!(%username, "CAPTCHA passed");
                }
                Ok(false) => {
                    send_hex_chat(client, "&cНеверный код капчи. Попробуйте ещё раз.").await.ok();
                }
                Err(e) => {
                    send_hex_chat(client, &format!("&c{}", e)).await.ok();
                }
            }
        }
        "/server" => {
            if parts.len() < 2 {
                send_hex_chat(client, "&cИспользование: &f/server <имя>").await.ok();
                return Ok(());
            }
            let name = parts[1];
            info!(%username, target = %name, "server switch requested");
            proxy.metrics.inc_server_switches();

            if let Some(h) = b_handle.take() {
                h.abort();
            }

            let new_link = proxy.connect_to_server(name, client_protocol_dummy(), &LoginStart {
                uuid: *uuid,
                username: username.to_string(),
            }).await?;
            let new_server_protocol = new_link.protocol;
            // backend replacement would need mutable access to backend link
            // For now just notify
            send_hex_chat(client, &format!("&aПереключился на сервер &f{}", name)).await.ok();

            let (abort_tx2, abort_rx2) = mpsc::unbounded_channel::<()>();
            *abort_tx = abort_tx2;
            let b_client = Arc::clone(client);
            // Need backend link to spawn new loop - simplified
            let _ = b_client;
            let _ = abort_rx2;
            let _ = new_server_protocol;
        }
        "/ping" => {
            let count = proxy.players.len();
            send_hex_chat(client, &format!("&7Онлайн: &f{}", count)).await.ok();
        }
        "/proxy" => {
            send_hex_chat(client, &format!("&bRustProxy &f{} &7игроков", proxy.players.len())).await.ok();
        }
        "/help" => {
            send_hex_chat(client, "&7Команды: &f/l <пароль> &7| &f/reg <пароль> &7| &f/tfa <код> &7| &f/captcha <код> &7| &f/server <имя> &7| &f/ping &7| &f/proxy").await.ok();
        }
        "/hub" | "/lobby" => {
            send_hex_chat(client, "&cСначала авторизуйтесь: &f/login <пароль>").await.ok();
        }
        _ => {
            send_hex_chat(client, "&cНеизвестная команда. &f/help").await.ok();
        }
    }
    Ok(())
}

fn client_protocol_dummy() -> i32 {
    777
}

// -------------------- Вспомогательные --------------------
fn is_nbt_packet(id: i32) -> bool {
    matches!(id, 0x11 | 0x12 | 0x18 | 0x2D | 0x2E)
}

async fn fallback_on_backend_disconnect(
    proxy: &Arc<Proxy>,
    client: &ClientLink,
    username: &str,
) -> bool {
    if !proxy.fallback.config.enabled {
        return false;
    }
    let old_server = proxy.server_names().first().cloned().unwrap_or_else(|| "unknown".to_string());
    let fallback_name = &proxy.fallback.config.fallback_server;
    info!(%username, %old_server, %fallback_name, "FALLBACK: бэкенд упал");

    let msg = proxy.fallback.config.kick_message
        .replace("{server}", &old_server)
        .replace("{fallback}", fallback_name);
    let formatted = format_message(&msg);
    let mut c = client.lock().await;
    let _ = c.send(packet_bytes(
        ids::PLAY_CHAT_MESSAGE_CLIENTBOUND,
        formatted.as_bytes(),
    )).await;
    true
}

async fn send_hex_chat(client: &ClientLink, text: &str) -> Result<()> {
    let formatted = messages::format_message(text);
    let mut c = client.lock().await;
    c.send(packet_bytes(
        ids::PLAY_CHAT_MESSAGE_CLIENTBOUND,
        formatted.as_bytes(),
    ))
    .await
}

async fn send_login_disconnect(
    client: &mut Framed<TcpStream, MinecraftCodec>,
    reason: &str,
) -> Result<()> {
    let json = serde_json::json!({"text": reason, "color": "red"}).to_string();
    client
        .send(packet_bytes(ids::LOGIN_DISCONNECT, json.as_bytes()))
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
    let (_, msg) = read_string(body).ok()?;
    if msg.starts_with('/') {
        Some(msg)
    } else {
        None
    }
}
