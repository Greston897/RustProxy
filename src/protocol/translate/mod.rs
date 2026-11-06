//! ViaVersion-перевод пакетов между версиями Minecraft.
//!
//! Позволяет клиенту с версией X подключиться к серверу с версией Y.
//! Промежуточное представление (IR) унифицирует пакеты, а переводчики
//! конвертируют IR → конкретная версия и обратно.

pub mod versions;
pub mod ir;
pub mod clientbound;
pub mod serverbound;

pub use versions::{ProtocolVersion, version_info, ProtocolVersionId};
pub use ir::PacketIR;

/// Результат перевода пакета.
#[derive(Debug, Clone)]
pub enum TranslationResult {
    /// Переведённый пакет (ID, сырые байты)
    Packet(i32, Vec<u8>),
    /// Пакет пропускается (не нужно отправлять)
    Skip,
    /// Пробрасывается без изменений (версии совпадают)
    PassThrough(i32, Vec<u8>),
}

pub use clientbound::translate_clientbound;
pub use serverbound::translate_serverbound;
pub use clientbound::parse_clientbound as parse_clientbound_cb;
pub use serverbound::parse_serverbound as parse_serverbound_sb;
pub use clientbound::serialize_clientbound as serialize_clientbound_cb;
pub use serverbound::serialize_serverbound as serialize_serverbound_sb;
