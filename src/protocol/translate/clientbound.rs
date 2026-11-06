//! Перевод clientbound пакетов (сервер → клиент) между версиями.
//!
//! Сервер шлёт пакет своей версией → парсим в IR → сериализуем под версию клиента.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use uuid::Uuid;

use crate::protocol::translate::ir::{
    self, MetadataEntry, MetadataValue, PacketIR,
};
use crate::protocol::translate::versions::ProtocolVersion;
use crate::protocol::varint::{read_string, read_varint, varint_bytes, write_string, write_varint};

/// Читатель байтов с позицией.
struct Rdr<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Rdr<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("unexpected end of data");
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("unexpected end of data (need {n} bytes)");
        }
        let b = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    fn read_varint(&mut self) -> Result<i32> {
        let (n, val) = read_varint(&self.data[self.pos..])
            .ok_or_else(|| anyhow::anyhow!("incomplete varint"))?;
        self.pos += n;
        Ok(val)
    }

    fn read_string(&mut self) -> Result<String> {
        let (n, s) = read_string(&self.data[self.pos..])
            .ok_or_else(|| anyhow::anyhow!("incomplete string"))?;
        self.pos += n;
        Ok(s)
    }

    fn read_f64(&mut self) -> Result<f64> {
        let b = self.read_bytes(8)?;
        Ok(f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_f32(&mut self) -> Result<f32> {
        let b = self.read_bytes(4)?;
        Ok(f32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_byte()? as i8)
    }

    fn read_i16(&mut self) -> Result<i16> {
        let b = self.read_bytes(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    fn read_i32(&mut self) -> Result<i32> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i64(&mut self) -> Result<i64> {
        let b = self.read_bytes(8)?;
        Ok(i64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.read_byte()
    }

    fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_byte()? != 0)
    }

    fn read_uuid(&mut self) -> Result<Uuid> {
        let b = self.read_bytes(16)?;
        Ok(Uuid::from_bytes(
            b.try_into()
                .map_err(|_| anyhow::anyhow!("invalid UUID slice"))?,
        ))
    }
}

/// Писатель байтов.
struct Wtr {
    out: Vec<u8>,
}

impl Wtr {
    fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn write_byte(&mut self, b: u8) {
        self.out.push(b);
    }

    fn write_bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    fn write_varint(&mut self, v: i32) {
        write_varint(v, &mut self.out);
    }

    fn write_string(&mut self, s: &str) {
        write_string(s, &mut self.out);
    }

    fn write_f64(&mut self, v: f64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn write_f32(&mut self, v: f32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn write_i8(&mut self, v: i8) {
        self.out.push(v as u8);
    }

    fn write_i16(&mut self, v: i16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn write_i32(&mut self, v: i32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn write_i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn write_bool(&mut self, v: bool) {
        self.out.push(if v { 1 } else { 0 });
    }

    fn write_uuid(&mut self, u: &Uuid) {
        self.out.extend_from_slice(u.as_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

// ━━━ ПARSING: версия → IR ━━━

/// Распарсить clientbound пакет из сырых байт конкретной версии в IR.
pub fn parse_clientbound(id: i32, data: &[u8], version: &ProtocolVersion) -> Result<PacketIR> {
    match id {
        v if id == version.play_join_game_id => parse_join_game(data, version),
        v if id == version.play_spawn_position_id => parse_spawn_position(data),
        v if id == version.play_player_position_and_look_cb_id => {
            parse_player_position_and_look_cb(data)
        }
        v if id == version.play_chat_message_cb_id => parse_chat_message_cb(data),
        v if id == version.play_disconnect_id => parse_disconnect(data),
        v if id == version.play_keep_alive_cb_id => parse_keep_alive_cb(data),
        v if id == version.play_entity_metadata_id => parse_entity_metadata(data),
        v if id == version.play_entity_velocity_id => parse_entity_velocity(data),
        v if id == version.play_entity_position_id => parse_entity_position(data),
        v if id == version.play_entity_look_id => parse_entity_look(data),
        v if id == version.play_entity_position_and_look_id => {
            parse_entity_position_and_look(data)
        }
        v if id == version.play_entity_teleport_id => parse_entity_teleport(data),
        v if id == version.play_destroy_entities_id => parse_destroy_entities(data),
        v if id == version.play_block_change_id => parse_block_change(data),
        v if id == version.play_chunk_data_id => parse_chunk_data(data),
        v if id == version.play_spawn_object_id => parse_spawn_object(data),
        v if id == version.play_spawn_mob_id => parse_spawn_mob(data),
        v if id == version.play_spawn_player_id => parse_spawn_player(data),
        v if id == version.play_multi_block_change_id => parse_multi_block_change(data),
        v if id == version.play_plugin_message_id => parse_plugin_message(data),
        v if id == version.play_custom_payload_id => parse_custom_payload(data),
        _ => Ok(PacketIR::Raw { id, data: data.to_vec() }),
    }
}

/// Сериализовать IR в clientbound пакет конкретной версии.
pub fn serialize_clientbound(ir: &PacketIR, version: &ProtocolVersion) -> Result<(i32, Vec<u8>)> {
    match ir {
        PacketIR::PlayJoinGame { .. } => {
            let data = serialize_join_game(ir)?;
            Ok((version.play_join_game_id, data))
        }
        PacketIR::PlaySpawnPosition { .. } => {
            let data = serialize_spawn_position(ir)?;
            Ok((version.play_spawn_position_id, data))
        }
        PacketIR::PlayPlayerPositionAndLookCB { .. } => {
            let data = serialize_player_position_and_look_cb(ir)?;
            Ok((version.play_player_position_and_look_cb_id, data))
        }
        PacketIR::PlayChatMessageCB { .. } => {
            let data = serialize_chat_message_cb(ir)?;
            Ok((version.play_chat_message_cb_id, data))
        }
        PacketIR::PlayDisconnect { .. } => {
            let data = serialize_disconnect(ir)?;
            Ok((version.play_disconnect_id, data))
        }
        PacketIR::PlayKeepAliveCB { .. } => {
            let data = serialize_keep_alive_cb(ir)?;
            Ok((version.play_keep_alive_cb_id, data))
        }
        PacketIR::PlayEntityMetadata { .. } => {
            let data = serialize_entity_metadata(ir)?;
            Ok((version.play_entity_metadata_id, data))
        }
        PacketIR::PlayEntityVelocity { .. } => {
            let data = serialize_entity_velocity(ir)?;
            Ok((version.play_entity_velocity_id, data))
        }
        PacketIR::PlayEntityPosition { .. } => {
            let data = serialize_entity_position(ir)?;
            Ok((version.play_entity_position_id, data))
        }
        PacketIR::PlayEntityLook { .. } => {
            let data = serialize_entity_look(ir)?;
            Ok((version.play_entity_look_id, data))
        }
        PacketIR::PlayEntityPositionAndLook { .. } => {
            let data = serialize_entity_position_and_look(ir)?;
            Ok((version.play_entity_position_and_look_id, data))
        }
        PacketIR::PlayEntityTeleport { .. } => {
            let data = serialize_entity_teleport(ir)?;
            Ok((version.play_entity_teleport_id, data))
        }
        PacketIR::PlayDestroyEntities { .. } => {
            let data = serialize_destroy_entities(ir)?;
            Ok((version.play_destroy_entities_id, data))
        }
        PacketIR::PlayBlockChange { .. } => {
            let data = serialize_block_change(ir)?;
            Ok((version.play_block_change_id, data))
        }
        PacketIR::PlayChunkData { .. } => {
            let data = serialize_chunk_data(ir)?;
            Ok((version.play_chunk_data_id, data))
        }
        PacketIR::PlaySpawnObject { .. } => {
            let data = serialize_spawn_object(ir)?;
            Ok((version.play_spawn_object_id, data))
        }
        PacketIR::PlaySpawnMob { .. } => {
            let data = serialize_spawn_mob(ir)?;
            Ok((version.play_spawn_mob_id, data))
        }
        PacketIR::PlaySpawnPlayer { .. } => {
            let data = serialize_spawn_player(ir)?;
            Ok((version.play_spawn_player_id, data))
        }
        PacketIR::PlayMultiBlockChange { .. } => {
            let data = serialize_multi_block_change(ir)?;
            Ok((version.play_multi_block_change_id, data))
        }
        PacketIR::PlayPluginMessageCB { .. } => {
            let data = serialize_plugin_message(ir)?;
            Ok((version.play_plugin_message_id, data))
        }
        PacketIR::PlayCustomPayloadCB { .. } => {
            let data = serialize_custom_payload(ir)?;
            Ok((version.play_custom_payload_id, data))
        }
        PacketIR::Raw { id, data } => Ok((*id, data.clone())),
        _ => bail!("cannot serialize clientbound IR variant: {}", ir.logical_id()),
    }
}

// ━━━ Join Game ━━━

fn parse_join_game(data: &[u8], version: &ProtocolVersion) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_i32()?;
    let is_hardcore = r.read_bool()?;
    let gamemode = r.read_varint()?;
    let previous_gamemode = r.read_varint()?;
    let world_names_count = r.read_varint()?;
    let mut world_names = Vec::new();
    for _ in 0..world_names_count {
        world_names.push(r.read_string()?);
    }
    // dimension_codec (NBT Compound) — 1.18+
    let dimension_codec = if version.id.0 >= 757 {
        let len = r.read_varint()? as usize;
        let codec_bytes = r.read_bytes(len)?;
        serde_json::from_slice(codec_bytes).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    // dimension (NBT) — 1.18+, строка до 1.18
    let dimension = if version.id.0 >= 757 {
        let len = r.read_varint()? as usize;
        let dim_bytes = r.read_bytes(len)?;
        serde_json::from_slice(dim_bytes).unwrap_or(Value::Null)
    } else {
        Value::String(r.read_string()?)
    };
    let world_name = r.read_string()?;
    let hashed_seed = r.read_i64()?;
    let max_players = r.read_varint()?;
    let view_distance = r.read_varint()?;
    let simulation_distance = if version.id.0 >= 757 {
        r.read_varint()?
    } else {
        0
    };
    let reduced_debug_info = r.read_bool()?;
    let enable_respawn_screen = if version.id.0 >= 757 {
        r.read_bool()?
    } else {
        true
    };
    let is_debug = if version.id.0 >= 757 {
        r.read_bool()?
    } else {
        false
    };
    let is_flat = if version.id.0 >= 757 {
        r.read_bool()?
    } else {
        false
    };
    let death_location = if version.id.0 >= 757 && r.read_bool()? {
        let len = r.read_varint()? as usize;
        let dl_bytes = r.read_bytes(len)?;
        Some(serde_json::from_slice(dl_bytes).unwrap_or(Value::Null))
    } else {
        None
    };
    let portal_cooldown = if version.id.0 >= 757 {
        r.read_varint()?
    } else {
        0
    };
    let enchanted_seeds = if version.id.0 >= 757 {
        r.read_bool()?
    } else {
        false
    };

    Ok(PacketIR::PlayJoinGame {
        entity_id,
        is_hardcore,
        gamemode,
        previous_gamemode,
        world_names,
        dimension_codec,
        dimension,
        world_name,
        hashed_seed,
        max_players,
        view_distance,
        simulation_distance,
        reduced_debug_info,
        enable_respawn_screen,
        is_debug,
        is_flat,
        death_location,
        portal_cooldown,
        enchanted_seeds,
    })
}

fn serialize_join_game(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayJoinGame {
        entity_id,
        is_hardcore,
        gamemode,
        previous_gamemode,
        world_names,
        dimension_codec,
        dimension,
        world_name,
        hashed_seed,
        max_players,
        view_distance,
        simulation_distance,
        reduced_debug_info,
        enable_respawn_screen,
        is_debug,
        is_flat,
        death_location,
        portal_cooldown,
        enchanted_seeds,
    } = ir
    {
        let mut w = Wtr::new();
        w.write_i32(*entity_id);
        w.write_bool(*is_hardcore);
        w.write_varint(*gamemode);
        w.write_varint(*previous_gamemode);
        w.write_varint(world_names.len() as i32);
        for name in world_names {
            w.write_string(name);
        }
        // dimension_codec
        let codec_bytes = serde_json::to_vec(dimension_codec)?;
        w.write_varint(codec_bytes.len() as i32);
        w.write_bytes(&codec_bytes);
        // dimension
        let dim_bytes = serde_json::to_vec(dimension)?;
        w.write_varint(dim_bytes.len() as i32);
        w.write_bytes(&dim_bytes);
        w.write_string(world_name);
        w.write_i64(*hashed_seed);
        w.write_varint(*max_players);
        w.write_varint(*view_distance);
        w.write_varint(*simulation_distance);
        w.write_bool(*reduced_debug_info);
        w.write_bool(*enable_respawn_screen);
        w.write_bool(*is_debug);
        w.write_bool(*is_flat);
        match death_location {
            Some(dl) => {
                w.write_bool(true);
                let dl_bytes = serde_json::to_vec(dl)?;
                w.write_varint(dl_bytes.len() as i32);
                w.write_bytes(&dl_bytes);
            }
            None => w.write_bool(false),
        }
        w.write_varint(*portal_cooldown);
        w.write_bool(*enchanted_seeds);
        Ok(w.finish())
    } else {
        bail!("expected PlayJoinGame IR")
    }
}

// ━━━ Spawn Position ━━━

fn parse_spawn_position(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let x = r.read_i32()?;
    let y = r.read_i32()?;
    let z = r.read_i32()?;
    Ok(PacketIR::PlaySpawnPosition { x, y, z })
}

fn serialize_spawn_position(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlaySpawnPosition { x, y, z } = ir {
        let mut w = Wtr::new();
        w.write_i32(*x);
        w.write_i32(*y);
        w.write_i32(*z);
        Ok(w.finish())
    } else {
        bail!("expected PlaySpawnPosition IR")
    }
}

// ━━━ Player Position And Look (clientbound) ━━━

fn parse_player_position_and_look_cb(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_f32()?;
    let pitch = r.read_f32()?;
    let flags = r.read_u8()?;
    let teleport_id = r.read_varint()?;
    let dismount_vehicle = if r.remaining() > 0 {
        r.read_bool()?
    } else {
        false
    };
    Ok(PacketIR::PlayPlayerPositionAndLookCB {
        x, y, z, yaw, pitch, flags, teleport_id, dismount_vehicle,
    })
}

fn serialize_player_position_and_look_cb(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPlayerPositionAndLookCB {
        x, y, z, yaw, pitch, flags, teleport_id, dismount_vehicle,
    } = ir
    {
        let mut w = Wtr::new();
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_f32(*yaw);
        w.write_f32(*pitch);
        w.write_byte(*flags);
        w.write_varint(*teleport_id);
        w.write_bool(*dismount_vehicle);
        Ok(w.finish())
    } else {
        bail!("expected PlayPlayerPositionAndLookCB IR")
    }
}

// ━━━ Chat Message (clientbound) ━━━

fn parse_chat_message_cb(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let json_str = r.read_string()?;
    let json: Value = serde_json::from_str(&json_str).unwrap_or(Value::Null);
    Ok(PacketIR::PlayChatMessageCB { json })
}

fn serialize_chat_message_cb(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayChatMessageCB { json } = ir {
        let mut w = Wtr::new();
        w.write_string(&json.to_string());
        Ok(w.finish())
    } else {
        bail!("expected PlayChatMessageCB IR")
    }
}

// ━━━ Disconnect ━━━

fn parse_disconnect(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let json_str = r.read_string()?;
    let json: Value = serde_json::from_str(&json_str).unwrap_or(Value::Null);
    let reason = json.get("text").and_then(|t| t.as_str()).unwrap_or("Disconnected").to_string();
    Ok(PacketIR::PlayDisconnect { reason })
}

fn serialize_disconnect(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayDisconnect { reason } = ir {
        let json = serde_json::json!({"text": reason, "color": "red"});
        let mut w = Wtr::new();
        w.write_string(&json.to_string());
        Ok(w.finish())
    } else {
        bail!("expected PlayDisconnect IR")
    }
}

// ━━━ Keep Alive (clientbound) ━━━

fn parse_keep_alive_cb(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let id = r.read_varint()?;
    Ok(PacketIR::PlayKeepAliveCB { id })
}

fn serialize_keep_alive_cb(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayKeepAliveCB { id } = ir {
        let mut w = Wtr::new();
        w.write_varint(*id);
        Ok(w.finish())
    } else {
        bail!("expected PlayKeepAliveCB IR")
    }
}

// ━━━ Entity Metadata ━━━

fn parse_entity_metadata(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let mut metadata = Vec::new();
    loop {
        let index = r.read_byte()?;
        if index == 0xFF {
            break;
        }
        let value_type = index >> 5;
        let value = match value_type {
            0 => MetadataValue::Byte(r.read_i8()?),
            1 => MetadataValue::VarInt(r.read_varint()?),
            2 => MetadataValue::Float(r.read_f32()?),
            3 => MetadataValue::String(r.read_string()?),
            4 => {
                let s = r.read_string()?;
                MetadataValue::Chat(serde_json::from_str(&s).unwrap_or(Value::Null))
            }
            5 => MetadataValue::OptBoolean(r.read_bool()?),
            6 => {
                let x = r.read_varint()?;
                let y = r.read_varint()?;
                let z = r.read_varint()?;
                MetadataValue::Position(x, y, z)
            }
            7 => {
                let present = r.read_bool()?;
                let val = if present {
                    Some((r.read_varint()?, r.read_varint()?, r.read_varint()?))
                } else {
                    None
                };
                MetadataValue::OptPosition(val)
            }
            8 => {
                let count = r.read_varint()?;
                let mut dirs = Vec::new();
                for _ in 0..count {
                    dirs.push(r.read_varint()?);
                }
                MetadataValue::Direction(dirs)
            }
            9 => {
                let present = r.read_bool()?;
                let val = if present { Some(r.read_uuid()?) } else { None };
                MetadataValue::OptUUID(val)
            }
            10 => MetadataValue::BlockId(r.read_varint()?),
            11 => {
                let s = r.read_string()?;
                MetadataValue::NBT(serde_json::from_str(&s).unwrap_or(Value::Null))
            }
            12 => {
                let s = r.read_string()?;
                MetadataValue::Particle(serde_json::from_str(&s).unwrap_or(Value::Null))
            }
            13 => MetadataValue::Pose(r.read_varint()?),
            _ => bail!("unknown metadata type {value_type}"),
        };
        metadata.push(MetadataEntry { index, value });
    }
    Ok(PacketIR::PlayEntityMetadata { entity_id, metadata })
}

fn serialize_entity_metadata(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityMetadata { entity_id, metadata } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        for entry in metadata {
            let index_and_type = match &entry.value {
                MetadataValue::Byte(_) => entry.index,
                MetadataValue::VarInt(_) => entry.index | (1 << 5),
                MetadataValue::Float(_) => entry.index | (2 << 5),
                MetadataValue::String(_) => entry.index | (3 << 5),
                MetadataValue::Chat(_) => entry.index | (4 << 5),
                MetadataValue::OptBoolean(_) => entry.index | (5 << 5),
                MetadataValue::Position(_, _, _) => entry.index | (6 << 5),
                MetadataValue::OptPosition(_) => entry.index | (7 << 5),
                MetadataValue::Direction(_) => entry.index | (8 << 5),
                MetadataValue::OptUUID(_) => entry.index | (9 << 5),
                MetadataValue::BlockId(_) => entry.index | (10 << 5),
                MetadataValue::NBT(_) => entry.index | (11 << 5),
                MetadataValue::Particle(_) => entry.index | (12 << 5),
                MetadataValue::Pose(_) => entry.index | (13 << 5),
            };
            w.write_byte(index_and_type);
            match &entry.value {
                MetadataValue::Byte(v) => w.write_i8(*v),
                MetadataValue::VarInt(v) => w.write_varint(*v),
                MetadataValue::Float(v) => w.write_f32(*v),
                MetadataValue::String(v) => w.write_string(v),
                MetadataValue::Chat(v) => w.write_string(&v.to_string()),
                MetadataValue::OptBoolean(v) => w.write_bool(*v),
                MetadataValue::Position(x, y, z) => {
                    w.write_varint(*x);
                    w.write_varint(*y);
                    w.write_varint(*z);
                }
                MetadataValue::OptPosition(opt) => {
                    match opt {
                        Some((x, y, z)) => {
                            w.write_bool(true);
                            w.write_varint(*x);
                            w.write_varint(*y);
                            w.write_varint(*z);
                        }
                        None => w.write_bool(false),
                    }
                }
                MetadataValue::Direction(dirs) => {
                    w.write_varint(dirs.len() as i32);
                    for d in dirs {
                        w.write_varint(*d);
                    }
                }
                MetadataValue::OptUUID(opt) => {
                    match opt {
                        Some(u) => {
                            w.write_bool(true);
                            w.write_uuid(u);
                        }
                        None => w.write_bool(false),
                    }
                }
                MetadataValue::BlockId(v) => w.write_varint(*v),
                MetadataValue::NBT(v) => w.write_string(&v.to_string()),
                MetadataValue::Particle(v) => w.write_string(&v.to_string()),
                MetadataValue::Pose(v) => w.write_varint(*v),
            }
        }
        w.write_byte(0xFF);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityMetadata IR")
    }
}

// ━━━ Entity Velocity ━━━

fn parse_entity_velocity(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let vx = r.read_i16()?;
    let vy = r.read_i16()?;
    let vz = r.read_i16()?;
    Ok(PacketIR::PlayEntityVelocity { entity_id, velocity_x: vx, velocity_y: vy, velocity_z: vz })
}

fn serialize_entity_velocity(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityVelocity { entity_id, velocity_x, velocity_y, velocity_z } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_i16(*velocity_x);
        w.write_i16(*velocity_y);
        w.write_i16(*velocity_z);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityVelocity IR")
    }
}

// ━━━ Entity Position ━━━

fn parse_entity_position(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayEntityPosition { entity_id, x, y, z, on_ground })
}

fn serialize_entity_position(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityPosition { entity_id, x, y, z, on_ground } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityPosition IR")
    }
}

// ━━━ Entity Look ━━━

fn parse_entity_look(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let yaw = r.read_i8()?;
    let pitch = r.read_i8()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayEntityLook { entity_id, yaw, pitch, on_ground })
}

fn serialize_entity_look(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityLook { entity_id, yaw, pitch, on_ground } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_i8(*yaw);
        w.write_i8(*pitch);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityLook IR")
    }
}

// ━━━ Entity Position And Look ━━━

fn parse_entity_position_and_look(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_i8()?;
    let pitch = r.read_i8()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayEntityPositionAndLook {
        entity_id, x, y, z, yaw, pitch, on_ground,
    })
}

fn serialize_entity_position_and_look(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityPositionAndLook {
        entity_id, x, y, z, yaw, pitch, on_ground,
    } = ir
    {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_i8(*yaw);
        w.write_i8(*pitch);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityPositionAndLook IR")
    }
}

// ━━━ Entity Teleport ━━━

fn parse_entity_teleport(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_i8()?;
    let pitch = r.read_i8()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayEntityTeleport {
        entity_id, x, y, z, yaw, pitch, on_ground,
    })
}

fn serialize_entity_teleport(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayEntityTeleport {
        entity_id, x, y, z, yaw, pitch, on_ground,
    } = ir
    {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_i8(*yaw);
        w.write_i8(*pitch);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayEntityTeleport IR")
    }
}

// ━━━ Destroy Entities ━━━

fn parse_destroy_entities(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let count = r.read_varint()?;
    let mut ids = Vec::new();
    for _ in 0..count {
        ids.push(r.read_varint()?);
    }
    Ok(PacketIR::PlayDestroyEntities { entity_ids: ids })
}

fn serialize_destroy_entities(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayDestroyEntities { entity_ids } = ir {
        let mut w = Wtr::new();
        w.write_varint(entity_ids.len() as i32);
        for id in entity_ids {
            w.write_varint(*id);
        }
        Ok(w.finish())
    } else {
        bail!("expected PlayDestroyEntities IR")
    }
}

// ━━━ Block Change ━━━

fn parse_block_change(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let x = r.read_i32()?;
    let y = r.read_i32()?;
    let z = r.read_i32()?;
    let block_id = r.read_varint()?;
    Ok(PacketIR::PlayBlockChange { x, y, z, block_id })
}

fn serialize_block_change(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayBlockChange { x, y, z, block_id } = ir {
        let mut w = Wtr::new();
        w.write_i32(*x);
        w.write_i32(*y);
        w.write_i32(*z);
        w.write_varint(*block_id);
        Ok(w.finish())
    } else {
        bail!("expected PlayBlockChange IR")
    }
}

// ━━━ Chunk Data ━━━

fn parse_chunk_data(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let chunk_x = r.read_i32()?;
    let chunk_z = r.read_i32()?;
    let data_bytes = r.read_bytes(r.remaining())?.to_vec();
    Ok(PacketIR::PlayChunkData { chunk_x, chunk_z, data: data_bytes })
}

fn serialize_chunk_data(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayChunkData { chunk_x, chunk_z, data } = ir {
        let mut w = Wtr::new();
        w.write_i32(*chunk_x);
        w.write_i32(*chunk_z);
        w.write_bytes(data);
        Ok(w.finish())
    } else {
        bail!("expected PlayChunkData IR")
    }
}

// ━━━ Spawn Object ━━━

fn parse_spawn_object(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let uuid = r.read_uuid()?;
    let object_type = r.read_varint()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let pitch = r.read_i8()?;
    let yaw = r.read_i8()?;
    let data_field = r.read_i32()?;
    Ok(PacketIR::PlaySpawnObject {
        entity_id, uuid, object_type, x, y, z, pitch, yaw, data: data_field,
    })
}

fn serialize_spawn_object(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlaySpawnObject { entity_id, uuid, object_type, x, y, z, pitch, yaw, data } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_uuid(uuid);
        w.write_varint(*object_type);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_i8(*pitch);
        w.write_i8(*yaw);
        w.write_i32(*data);
        Ok(w.finish())
    } else {
        bail!("expected PlaySpawnObject IR")
    }
}

// ━━━ Spawn Mob ━━━

fn parse_spawn_mob(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let uuid = r.read_uuid()?;
    let mob_type = r.read_varint()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_i8()?;
    let pitch = r.read_i8()?;
    let head_pitch = r.read_i8()?;
    let vx = r.read_i16()?;
    let vy = r.read_i16()?;
    let vz = r.read_i16()?;
    Ok(PacketIR::PlaySpawnMob {
        entity_id, uuid, mob_type, x, y, z, yaw, pitch, head_pitch, velocity_x: vx, velocity_y: vy, velocity_z: vz,
    })
}

fn serialize_spawn_mob(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlaySpawnMob { entity_id, uuid, mob_type, x, y, z, yaw, pitch, head_pitch, velocity_x, velocity_y, velocity_z } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_uuid(uuid);
        w.write_varint(*mob_type);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_i8(*yaw);
        w.write_i8(*pitch);
        w.write_i8(*head_pitch);
        w.write_i16(*velocity_x);
        w.write_i16(*velocity_y);
        w.write_i16(*velocity_z);
        Ok(w.finish())
    } else {
        bail!("expected PlaySpawnMob IR")
    }
}

// ━━━ Spawn Player ━━━

fn parse_spawn_player(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let entity_id = r.read_varint()?;
    let uuid = r.read_uuid()?;
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_i8()?;
    let pitch = r.read_i8()?;
    Ok(PacketIR::PlaySpawnPlayer { entity_id, uuid, x, y, z, yaw, pitch })
}

fn serialize_spawn_player(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlaySpawnPlayer { entity_id, uuid, x, y, z, yaw, pitch } = ir {
        let mut w = Wtr::new();
        w.write_varint(*entity_id);
        w.write_uuid(uuid);
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_i8(*yaw);
        w.write_i8(*pitch);
        Ok(w.finish())
    } else {
        bail!("expected PlaySpawnPlayer IR")
    }
}

// ━━━ Multi Block Change ━━━

fn parse_multi_block_change(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let chunk_x = r.read_i32()?;
    let chunk_z = r.read_i32()?;
    let count = r.read_varint()?;
    let mut records = Vec::new();
    for _ in 0..count {
        let pos = r.read_varint()?;
        let block_id = r.read_varint()?;
        records.push((pos, block_id));
    }
    Ok(PacketIR::PlayMultiBlockChange { chunk_x, chunk_z, records })
}

fn serialize_multi_block_change(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayMultiBlockChange { chunk_x, chunk_z, records } = ir {
        let mut w = Wtr::new();
        w.write_i32(*chunk_x);
        w.write_i32(*chunk_z);
        w.write_varint(records.len() as i32);
        for (pos, block_id) in records {
            w.write_varint(*pos);
            w.write_varint(*block_id);
        }
        Ok(w.finish())
    } else {
        bail!("expected PlayMultiBlockChange IR")
    }
}

// ━━━ Plugin Message / Custom Payload ━━━

fn parse_plugin_message(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let channel = r.read_string()?;
    let len = r.read_varint()? as usize;
    let payload = r.read_bytes(len)?.to_vec();
    Ok(PacketIR::PlayPluginMessageCB { channel, data: payload })
}

fn serialize_plugin_message(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPluginMessageCB { channel, data } = ir {
        let mut w = Wtr::new();
        w.write_string(channel);
        w.write_varint(data.len() as i32);
        w.write_bytes(data);
        Ok(w.finish())
    } else {
        bail!("expected PlayPluginMessageCB IR")
    }
}

fn parse_custom_payload(data: &[u8]) -> Result<PacketIR> {
    parse_plugin_message(data) // та же структура
}

fn serialize_custom_payload(ir: &PacketIR) -> Result<Vec<u8>> {
    serialize_plugin_message(ir) // та же структура
}

/// Главная функция перевода clientbound пакета.
/// data — сырые байты пакета (без ID) от сервера с версией from_version.
/// Возвращает TranslationResult для отправки клиенту с версией to_version.
pub fn translate_clientbound(
    id: i32,
    data: &[u8],
    from_version: &ProtocolVersion,
    to_version: &ProtocolVersion,
) -> Result<super::TranslationResult> {
    if from_version.id == to_version.id {
        // Версии совпадают — проброс без изменений
        return Ok(super::TranslationResult::PassThrough(id, data.to_vec()));
    }

    let ir = parse_clientbound(id, data, from_version)?;
    if !ir.needs_translation() {
        return Ok(super::TranslationResult::PassThrough(id, data.to_vec()));
    }

    let (new_id, new_data) = serialize_clientbound(&ir, to_version)?;
    Ok(super::TranslationResult::Packet(new_id, new_data))
}
