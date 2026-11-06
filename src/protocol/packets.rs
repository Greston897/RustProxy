//! Пакеты протокола: идентификаторы и структуры для Handshaking, Status, Login.
//! Play-пакеты ходят сквозь прокси в сыром виде (RawPacket); таблица идентификаторов
//! по версиям будет заполнена на этапе 4 (ViaVersion-перевод).

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use serde_json;
use uuid::Uuid;

use crate::protocol::varint::{read_string, write_string, varint_bytes, read_varint, write_varint};

// ┌─────────────────────────────────────────────────────────────┐
// │ Идентификаторы пакетов (754+, актуальны для большинства версий)│
// └─────────────────────────────────────────────────────────────┘
pub mod ids {
    // Handshaking (serverbound)
    pub const HANDSHAKE: i32 = 0x00;

    // Status
    pub const STATUS_REQUEST: i32 = 0x00;
    pub const STATUS_PING: i32 = 0x01;
    pub const STATUS_RESPONSE: i32 = 0x00; // clientbound
    pub const STATUS_PONG: i32 = 0x01;     // clientbound

    // Login (serverbound)
    pub const LOGIN_START: i32 = 0x00;
    pub const LOGIN_ENCRYPTION_BEGIN: i32 = 0x01; // этап 5 (шифрование)

    // Login (clientbound)
    pub const LOGIN_DISCONNECT: i32 = 0x00;
    pub const LOGIN_ENCRYPTION_REQUEST: i32 = 0x01; // этап 5
    pub const LOGIN_SUCCESS: i32 = 0x02;
    pub const LOGIN_SET_COMPRESSION: i32 = 0x03;
    pub const LOGIN_PLUGIN_REQUEST: i32 = 0x04;

    // Play (serverbound) — чат/команды (0x01 для 754+; уточняется на этапе 4)
    pub const PLAY_CHAT_MESSAGE: i32 = 0x01;
    // Play (clientbound) — чат от системы (0x0F в большинстве версий 1.16–1.21)
    pub const PLAY_CHAT_MESSAGE_CLIENTBOUND: i32 = 0x0F;
}

/// Собранные байты пакета: VarInt id + тело.
pub fn packet_bytes(id: i32, body: &[u8]) -> Vec<u8> {
    let mut out = varint_bytes(id);
    out.extend_from_slice(body);
    out
}

/// Разбивает сырые байты пакета на (id, тело).
pub fn split_packet(packet: &[u8]) -> Result<(i32, &[u8])> {
    let (n, id) = read_varint(packet).context("failed to read packet id varint")?;
    Ok((id, &packet[n..]))
}

/// Тело пакета Set Compression (VarInt threshold).
pub fn compression_bytes(threshold: i32) -> Vec<u8> {
    varint_bytes(threshold)
}

#[derive(Debug, Clone)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub port: u16,
    pub next_state: i32,
}

#[derive(Debug, Clone)]
pub struct LoginStart {
    pub uuid: Uuid,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct LoginSuccess {
    pub uuid: Uuid,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct SetCompression {
    pub threshold: i32,
}

/// Переэкспорт идентификаторов на верхний уровень модуля packets.
pub use ids::{
    HANDSHAKE, STATUS_REQUEST, STATUS_PING, STATUS_RESPONSE, STATUS_PONG,
    LOGIN_START, LOGIN_ENCRYPTION_BEGIN, LOGIN_DISCONNECT, LOGIN_ENCRYPTION_REQUEST,
    LOGIN_SUCCESS, LOGIN_SET_COMPRESSION, LOGIN_PLUGIN_REQUEST,
    PLAY_CHAT_MESSAGE, PLAY_CHAT_MESSAGE_CLIENTBOUND,
};

/// Snapshot "сырого" Play-пакета для проброса между версиями.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub id: i32,
    pub data: Bytes,
}

/// Ручная сериализация Handshake (проброс на бэкенд).
pub fn handshake_bytes(h: &Handshake) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(h.protocol_version, &mut out);
    write_string(&h.server_address, &mut out);
    out.extend_from_slice(&h.port.to_be_bytes());
    write_varint(h.next_state, &mut out);
    out
}

/// Логин-старт клиента: UUID (16 байт) + строка имени.
pub fn login_start_bytes(s: &LoginStart) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(s.uuid.as_bytes());
    write_string(&s.username, &mut out);
    out
}

/// Login Success клиенту: UUID + имя.
pub fn login_success_bytes(s: &LoginSuccess) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(s.uuid.as_bytes());
    write_string(&s.username, &mut out);
    out
}

/// Парсинг Handshake из тела пакета.
pub fn parse_handshake(body: &[u8]) -> Result<Handshake> {
    let (n, protocol) = read_varint(body).context("handshake: protocol varint")?;
    let (m, address) = read_string(&body[n..]).context("handshake: address string")?;
    let pos = n + m;
    if body.len() < pos + 2 {
        bail!("handshake: truncated before port");
    }
    let port = u16::from_be_bytes([body[pos], body[pos + 1]]);
    let (_, next_state) = read_varint(&body[pos + 2..]).context("handshake: next state varint")?;
    Ok(Handshake {
        protocol_version: protocol,
        server_address: address,
        port,
        next_state,
    })
}

/// Парсинг Login Start из тела пакета.
pub fn parse_login_start(body: &[u8]) -> Result<LoginStart> {
    if body.len() < 16 {
        bail!("login start: too short for UUID");
    }
    let uuid = Uuid::from_bytes(
        body[0..16]
            .try_into()
            .map_err(|_| anyhow::anyhow!("login start: invalid UUID slice"))?,
    );
    let (_, username) = read_string(&body[16..]).context("login start: username string")?;
    Ok(LoginStart { uuid, username })
}

// ┌─────────────────────────────────────────────────────────────┐
// │ Пакеты шифрования логина (Online mode)                      │
// └─────────────────────────────────────────────────────────────┘

/// Login Encryption Request (клиент → сервер? нет — сервер → клиент).
/// serverId = "" (прокси не использует сервер-ID аутентификации),
/// publicKey — DER SPKI открытого ключа прокси,
/// verifyToken — случайный токен для защиты от подмены.
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}

/// Login Encryption Begin (клиент → сервер).
/// shared_secret — общий секрет, зашифрованный открытым ключом сервера (RSA PKCS#1 v1.5).
/// verify_token — тот же токен, что сервер прислал в запросе.
#[derive(Debug, Clone)]
pub struct EncryptionBegin {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

/// Сериализация EncryptionRequest (сервер → клиент).
pub fn encryption_request_bytes(req: &EncryptionRequest) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&req.server_id, &mut out);
    write_varint(req.public_key.len() as i32, &mut out);
    out.extend_from_slice(&req.public_key);
    write_varint(req.verify_token.len() as i32, &mut out);
    out.extend_from_slice(&req.verify_token);
    out
}

/// Парсинг EncryptionBegin из тела пакета.
pub fn parse_encryption_begin(body: &[u8]) -> Result<EncryptionBegin> {
    let (n, secret_len) = read_varint(body).context("encryption begin: shared secret length")?;
    let secret_len = secret_len as usize;
    let pos = n;
    if body.len() < pos + secret_len {
        bail!("encryption begin: truncated shared secret");
    }
    let shared_secret = body[pos..pos + secret_len].to_vec();
    let pos = pos + secret_len;

    let (_, token_len) =
        read_varint(&body[pos..]).context("encryption begin: verify token length")?;
    let token_len = token_len as usize;
    let pos = pos + read_varint_len(&body[pos..]).context("encryption begin: token length varint")?;
    if body.len() < pos + token_len {
        bail!("encryption begin: truncated verify token");
    }
    let verify_token = body[pos..pos + token_len].to_vec();

    Ok(EncryptionBegin {
        shared_secret,
        verify_token,
    })
}

/// Вспомогательно: длина VarInt в байтах (без чтения значения).
fn read_varint_len(buf: &[u8]) -> Result<usize> {
    let mut len = 0;
    for &byte in buf.iter().take(5) {
        len += 1;
        if byte & 0x80 == 0 {
            return Ok(len);
        }
    }
    bail!("varint too long")
}

/// Парсинг Encryption Request из тела пакета (сервер → клиент).
pub fn parse_encryption_request(body: &[u8]) -> Result<EncryptionRequest> {
    let (n, server_id) = read_string(body).context("encryption request: server id")?;
    let pos = n;
    let (m, key_len) = read_varint(&body[pos..]).context("encryption request: key length")?;
    let key_len = key_len as usize;
    let pos = pos + m;
    if body.len() < pos + key_len {
        bail!("encryption request: truncated public key");
    }
    let public_key = body[pos..pos + key_len].to_vec();
    let pos = pos + key_len;
    let (k, token_len) = read_varint(&body[pos..]).context("encryption request: token length")?;
    let token_len = token_len as usize;
    let pos = pos + k;
    if body.len() < pos + token_len {
        bail!("encryption request: truncated verify token");
    }
    let verify_token = body[pos..pos + token_len].to_vec();

    Ok(EncryptionRequest {
        server_id,
        public_key,
        verify_token,
    })
}

/// Сериализация EncryptionBegin (клиент → сервер).
pub fn encryption_begin_bytes(begin: &EncryptionBegin) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(begin.shared_secret.len() as i32, &mut out);
    out.extend_from_slice(&begin.shared_secret);
    write_varint(begin.verify_token.len() as i32, &mut out);
    out.extend_from_slice(&begin.verify_token);
    out
}

/// Пакет Disconnect (login stage) — уже есть как LOGIN_DISCONNECT, но оставим
/// удобный конструктор для कारण в виде JSON-текста.
pub fn disconnect_bytes(reason: &str) -> Vec<u8> {
    let json = serde_json::json!({"text": reason, "color": "red"}).to_string();
    packet_bytes(ids::LOGIN_DISCONNECT, json.as_bytes())
}

