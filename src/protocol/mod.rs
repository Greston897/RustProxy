//! Minecraft protocol core.
//!
//! Покрывает протоколы 754 (1.16.5) → 777 (26.3, 2026).
//! Пакетыhandshake/status/login парсятся явно; игровые пакеты (Play) проходят
//! сквозь прокси в сыром виде (pass-through) — перевод между версиями (ViaVersion-стиль)
//! запланирован на этап 4.

pub mod codec;
pub mod encryption;
pub mod packets;
pub mod translate;
pub mod varint;
pub mod versions;

pub use codec::MinecraftCodec;
pub use packets::{
    split_packet, packet_bytes, parse_handshake, parse_login_start, handshake_bytes,
    login_start_bytes, login_success_bytes, compression_bytes, disconnect_bytes,
    encryption_request_bytes, parse_encryption_begin, parse_encryption_request,
    encryption_begin_bytes,
    EncryptionRequest, EncryptionBegin, Handshake, LoginStart, LoginSuccess,
    SetCompression, ids,
};
pub use varint::{read_varint, write_varint, read_string, write_string, varint_bytes};
pub use versions::{all_supported, is_supported, version_name, MAX_PROTOCOL, MIN_PROTOCOL};
