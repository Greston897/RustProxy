//! Промежуточное представление (IR) пакетов Minecraft.
//! Унифицирует структуры пакетов разных версий для перевода между ними.

use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Промежуточное представление любого пакета.
#[derive(Debug, Clone)]
pub enum PacketIR {
    // ━━━ Handshaking ━━━
    Handshake {
        protocol_version: i32,
        server_address: String,
        port: u16,
        next_state: i32,
    },

    // ━━━ Status ━━━
    StatusRequest,
    StatusResponse { json: Value },
    StatusPing { payload: Vec<u8> },
    StatusPong { payload: Vec<u8> },

    // ━━━ Login ━━━
    LoginStart { uuid: Uuid, username: String },
    LoginEncryptionRequest {
        server_id: String,
        public_key: Vec<u8>,
        verify_token: Vec<u8>,
    },
    LoginEncryptionBegin {
        shared_secret: Vec<u8>,
        verify_token: Vec<u8>,
    },
    LoginSuccess { uuid: Uuid, username: String },
    LoginSetCompression { threshold: i32 },
    LoginDisconnect { reason: String },

    // ━━━ Play (serverbound — клиент → сервер) ━━━
    PlayChatMessage { message: String },
    PlayPlayerPosition { x: f64, y: f64, z: f64, on_ground: bool },
    PlayPlayerLook { yaw: f32, pitch: f32, on_ground: bool },
    PlayPlayerPositionAndLook {
        x: f64,
        y: f64,
        z: f64,
        yaw: f32,
        pitch: f32,
        on_ground: bool,
    },
    PlayPlayerOnGround { on_ground: bool },
    PlayKeepAlive { id: i32 },
    PlayTeleportConfirm { id: i32 },
    PlayPluginMessage { channel: String, data: Vec<u8> },
    PlayCustomPayload { channel: String, data: Vec<u8> },

    // ━━━ Play (clientbound — сервер → клиент) ━━━
    PlayJoinGame {
        entity_id: i32,
        is_hardcore: bool,
        gamemode: i32,
        previous_gamemode: i32,
        world_names: Vec<String>,
        dimension_codec: Value, // NBT Compound как JSON
        dimension: Value,
        world_name: String,
        hashed_seed: i64,
        max_players: i32,
        view_distance: i32,
        simulation_distance: i32,
        reduced_debug_info: bool,
        enable_respawn_screen: bool,
        is_debug: bool,
        is_flat: bool,
        death_location: Option<Value>,
        portal_cooldown: i32,
        enchanted_seeds: bool,
    },
    PlaySpawnPosition { x: i32, y: i32, z: i32 },
    PlayPlayerPositionAndLookCB {
        x: f64,
        y: f64,
        z: f64,
        yaw: f32,
        pitch: f32,
        flags: u8,
        teleport_id: i32,
        dismount_vehicle: bool,
    },
    PlayChatMessageCB { json: Value },
    PlayDisconnect { reason: String },
    PlayKeepAliveCB { id: i32 },
    PlaySpawnObject {
        entity_id: i32,
        uuid: Uuid,
        object_type: i32,
        x: f64,
        y: f64,
        z: f64,
        pitch: i8,
        yaw: i8,
        data: i32,
    },
    PlaySpawnMob {
        entity_id: i32,
        uuid: Uuid,
        mob_type: i32,
        x: f64,
        y: f64,
        z: f64,
        yaw: i8,
        pitch: i8,
        head_pitch: i8,
        velocity_x: i16,
        velocity_y: i16,
        velocity_z: i16,
    },
    PlaySpawnPlayer {
        entity_id: i32,
        uuid: Uuid,
        x: f64,
        y: f64,
        z: f64,
        yaw: i8,
        pitch: i8,
    },
    PlayEntityMetadata {
        entity_id: i32,
        metadata: Vec<MetadataEntry>,
    },
    PlayEntityVelocity {
        entity_id: i32,
        velocity_x: i16,
        velocity_y: i16,
        velocity_z: i16,
    },
    PlayEntityPosition {
        entity_id: i32,
        x: f64,
        y: f64,
        z: f64,
        on_ground: bool,
    },
    PlayEntityLook {
        entity_id: i32,
        yaw: i8,
        pitch: i8,
        on_ground: bool,
    },
    PlayEntityPositionAndLook {
        entity_id: i32,
        x: f64,
        y: f64,
        z: f64,
        yaw: i8,
        pitch: i8,
        on_ground: bool,
    },
    PlayEntityTeleport {
        entity_id: i32,
        x: f64,
        y: f64,
        z: f64,
        yaw: i8,
        pitch: i8,
        on_ground: bool,
    },
    PlayDestroyEntities { entity_ids: Vec<i32> },
    PlayChunkData {
        chunk_x: i32,
        chunk_z: i32,
        data: Vec<u8>,
    },
    PlayMapChunkBulk {
        chunks: Vec<(i32, i32, Vec<u8>)>,
    },
    PlayBlockChange {
        x: i32,
        y: i32,
        z: i32,
        block_id: i32,
    },
    PlayMultiBlockChange {
        chunk_x: i32,
        chunk_z: i32,
        records: Vec<(i32, i32)>, // (position, block_id)
    },
    PlayPluginMessageCB { channel: String, data: Vec<u8> },
    PlayCustomPayloadCB { channel: String, data: Vec<u8> },

    /// Неизвестный пакет — пробрасывается как есть с оригинальными байтами.
    Raw { id: i32, data: Vec<u8> },
}

/// Entry метаданных сущности (упрощённый формат).
#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub index: u8,
    pub value: MetadataValue,
}

#[derive(Debug, Clone)]
pub enum MetadataValue {
    Byte(i8),
    VarInt(i32),
    Float(f32),
    String(String),
    Chat(Value),
    OptBoolean(bool),
    Position(i32, i32, i32),
    OptPosition(Option<(i32, i32, i32)>),
    Direction(Vec<i32>),
    OptUUID(Option<Uuid>),
    BlockId(i32),
    NBT(Value),
    Particle(Value),
    Pose(i32),
}

impl PacketIR {
    /// Пакет нужно переводить или можно пробросить как есть?
    pub fn needs_translation(&self) -> bool {
        match self {
            PacketIR::Raw { .. } => false,
            _ => true,
        }
    }

    /// Получить логический ID пакета (для отладки).
    pub fn logical_id(&self) -> &'static str {
        match self {
            PacketIR::Handshake { .. } => "Handshake",
            PacketIR::StatusRequest => "StatusRequest",
            PacketIR::StatusResponse { .. } => "StatusResponse",
            PacketIR::StatusPing { .. } => "StatusPing",
            PacketIR::StatusPong { .. } => "StatusPong",
            PacketIR::LoginStart { .. } => "LoginStart",
            PacketIR::LoginEncryptionRequest { .. } => "LoginEncryptionRequest",
            PacketIR::LoginEncryptionBegin { .. } => "LoginEncryptionBegin",
            PacketIR::LoginSuccess { .. } => "LoginSuccess",
            PacketIR::LoginSetCompression { .. } => "LoginSetCompression",
            PacketIR::LoginDisconnect { .. } => "LoginDisconnect",
            PacketIR::PlayChatMessage { .. } => "PlayChatMessage",
            PacketIR::PlayPlayerPosition { .. } => "PlayPlayerPosition",
            PacketIR::PlayPlayerLook { .. } => "PlayPlayerLook",
            PacketIR::PlayPlayerPositionAndLook { .. } => "PlayPlayerPositionAndLook",
            PacketIR::PlayPlayerOnGround { .. } => "PlayPlayerOnGround",
            PacketIR::PlayKeepAlive { .. } => "PlayKeepAlive",
            PacketIR::PlayTeleportConfirm { .. } => "PlayTeleportConfirm",
            PacketIR::PlayPluginMessage { .. } => "PlayPluginMessage",
            PacketIR::PlayCustomPayload { .. } => "PlayCustomPayload",
            PacketIR::PlayJoinGame { .. } => "PlayJoinGame",
            PacketIR::PlaySpawnPosition { .. } => "PlaySpawnPosition",
            PacketIR::PlayPlayerPositionAndLookCB { .. } => "PlayPlayerPositionAndLookCB",
            PacketIR::PlayChatMessageCB { .. } => "PlayChatMessageCB",
            PacketIR::PlayDisconnect { .. } => "PlayDisconnect",
            PacketIR::PlayKeepAliveCB { .. } => "PlayKeepAliveCB",
            PacketIR::PlaySpawnObject { .. } => "PlaySpawnObject",
            PacketIR::PlaySpawnMob { .. } => "PlaySpawnMob",
            PacketIR::PlaySpawnPlayer { .. } => "PlaySpawnPlayer",
            PacketIR::PlayEntityMetadata { .. } => "PlayEntityMetadata",
            PacketIR::PlayEntityVelocity { .. } => "PlayEntityVelocity",
            PacketIR::PlayEntityPosition { .. } => "PlayEntityPosition",
            PacketIR::PlayEntityLook { .. } => "PlayEntityLook",
            PacketIR::PlayEntityPositionAndLook { .. } => "PlayEntityPositionAndLook",
            PacketIR::PlayEntityTeleport { .. } => "PlayEntityTeleport",
            PacketIR::PlayDestroyEntities { .. } => "PlayDestroyEntities",
            PacketIR::PlayChunkData { .. } => "PlayChunkData",
            PacketIR::PlayMapChunkBulk { .. } => "PlayMapChunkBulk",
            PacketIR::PlayBlockChange { .. } => "PlayBlockChange",
            PacketIR::PlayMultiBlockChange { .. } => "PlayMultiBlockChange",
            PacketIR::PlayPluginMessageCB { .. } => "PlayPluginMessageCB",
            PacketIR::PlayCustomPayloadCB { .. } => "PlayCustomPayloadCB",
            PacketIR::Raw { .. } => "Raw",
        }
    }
}
