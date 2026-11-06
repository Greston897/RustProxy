//! Перевод serverbound пакетов (клиент → сервер) между версиями.
//!
//! Клиент шлёт пакет своей версией → парсим в IR → сериализуем под версию сервера.

use anyhow::{bail, Result};
use uuid::Uuid;

use crate::protocol::translate::ir::{self, PacketIR};
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

/// Распарсить serverbound пакет из сырых байт конкретной версии в IR.
pub fn parse_serverbound(id: i32, data: &[u8], version: &ProtocolVersion) -> Result<PacketIR> {
    match id {
        v if id == version.play_chat_message_id => parse_chat_message(data),
        v if id == version.play_player_position_id => parse_player_position(data),
        v if id == version.play_player_look_id => parse_player_look(data),
        v if id == version.play_player_position_and_look_id => {
            parse_player_position_and_look(data)
        }
        v if id == version.play_player_on_ground_id => parse_player_on_ground(data),
        v if id == version.play_keep_alive_id => parse_keep_alive(data),
        v if id == version.play_teleport_confirm_id => parse_teleport_confirm(data),
        v if id == version.play_plugin_message_id => parse_plugin_message(data),
        v if id == version.play_custom_payload_id => parse_custom_payload(data),
        _ => Ok(PacketIR::Raw { id, data: data.to_vec() }),
    }
}

/// Сериализовать IR в serverbound пакет конкретной версии.
pub fn serialize_serverbound(ir: &PacketIR, version: &ProtocolVersion) -> Result<(i32, Vec<u8>)> {
    match ir {
        PacketIR::PlayChatMessage { .. } => {
            let data = serialize_chat_message(ir)?;
            Ok((version.play_chat_message_id, data))
        }
        PacketIR::PlayPlayerPosition { .. } => {
            let data = serialize_player_position(ir)?;
            Ok((version.play_player_position_id, data))
        }
        PacketIR::PlayPlayerLook { .. } => {
            let data = serialize_player_look(ir)?;
            Ok((version.play_player_look_id, data))
        }
        PacketIR::PlayPlayerPositionAndLook { .. } => {
            let data = serialize_player_position_and_look(ir)?;
            Ok((version.play_player_position_and_look_id, data))
        }
        PacketIR::PlayPlayerOnGround { .. } => {
            let data = serialize_player_on_ground(ir)?;
            Ok((version.play_player_on_ground_id, data))
        }
        PacketIR::PlayKeepAlive { .. } => {
            let data = serialize_keep_alive(ir)?;
            Ok((version.play_keep_alive_id, data))
        }
        PacketIR::PlayTeleportConfirm { .. } => {
            let data = serialize_teleport_confirm(ir)?;
            Ok((version.play_teleport_confirm_id, data))
        }
        PacketIR::PlayPluginMessage { .. } => {
            let data = serialize_plugin_message(ir)?;
            Ok((version.play_plugin_message_id, data))
        }
        PacketIR::PlayCustomPayload { .. } => {
            let data = serialize_custom_payload(ir)?;
            Ok((version.play_custom_payload_id, data))
        }
        PacketIR::Raw { id, data } => Ok((*id, data.clone())),
        _ => bail!("cannot serialize serverbound IR variant: {}", ir.logical_id()),
    }
}

// ━━━ Chat Message ━━━

fn parse_chat_message(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let message = r.read_string()?;
    Ok(PacketIR::PlayChatMessage { message })
}

fn serialize_chat_message(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayChatMessage { message } = ir {
        let mut w = Wtr::new();
        w.write_string(message);
        Ok(w.finish())
    } else {
        bail!("expected PlayChatMessage IR")
    }
}

// ━━━ Player Position ━━━

fn parse_player_position(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayPlayerPosition { x, y, z, on_ground })
}

fn serialize_player_position(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPlayerPosition { x, y, z, on_ground } = ir {
        let mut w = Wtr::new();
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayPlayerPosition IR")
    }
}

// ━━━ Player Look ━━━

fn parse_player_look(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let yaw = r.read_f32()?;
    let pitch = r.read_f32()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayPlayerLook { yaw, pitch, on_ground })
}

fn serialize_player_look(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPlayerLook { yaw, pitch, on_ground } = ir {
        let mut w = Wtr::new();
        w.write_f32(*yaw);
        w.write_f32(*pitch);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayPlayerLook IR")
    }
}

// ━━━ Player Position And Look ━━━

fn parse_player_position_and_look(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let x = r.read_f64()?;
    let y = r.read_f64()?;
    let z = r.read_f64()?;
    let yaw = r.read_f32()?;
    let pitch = r.read_f32()?;
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayPlayerPositionAndLook { x, y, z, yaw, pitch, on_ground })
}

fn serialize_player_position_and_look(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPlayerPositionAndLook { x, y, z, yaw, pitch, on_ground } = ir {
        let mut w = Wtr::new();
        w.write_f64(*x);
        w.write_f64(*y);
        w.write_f64(*z);
        w.write_f32(*yaw);
        w.write_f32(*pitch);
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayPlayerPositionAndLook IR")
    }
}

// ━━━ Player On Ground ━━━

fn parse_player_on_ground(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let on_ground = r.read_bool()?;
    Ok(PacketIR::PlayPlayerOnGround { on_ground })
}

fn serialize_player_on_ground(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPlayerOnGround { on_ground } = ir {
        let mut w = Wtr::new();
        w.write_bool(*on_ground);
        Ok(w.finish())
    } else {
        bail!("expected PlayPlayerOnGround IR")
    }
}

// ━━━ Keep Alive ━━━

fn parse_keep_alive(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let id = r.read_varint()?;
    Ok(PacketIR::PlayKeepAlive { id })
}

fn serialize_keep_alive(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayKeepAlive { id } = ir {
        let mut w = Wtr::new();
        w.write_varint(*id);
        Ok(w.finish())
    } else {
        bail!("expected PlayKeepAlive IR")
    }
}

// ━━━ Teleport Confirm ━━━

fn parse_teleport_confirm(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let id = r.read_varint()?;
    Ok(PacketIR::PlayTeleportConfirm { id })
}

fn serialize_teleport_confirm(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayTeleportConfirm { id } = ir {
        let mut w = Wtr::new();
        w.write_varint(*id);
        Ok(w.finish())
    } else {
        bail!("expected PlayTeleportConfirm IR")
    }
}

// ━━━ Plugin Message / Custom Payload ━━━

fn parse_plugin_message(data: &[u8]) -> Result<PacketIR> {
    let mut r = Rdr::new(data);
    let channel = r.read_string()?;
    let len = r.read_varint()? as usize;
    let payload = r.read_bytes(len)?.to_vec();
    Ok(PacketIR::PlayPluginMessage { channel, data: payload })
}

fn serialize_plugin_message(ir: &PacketIR) -> Result<Vec<u8>> {
    if let PacketIR::PlayPluginMessage { channel, data } = ir {
        let mut w = Wtr::new();
        w.write_string(channel);
        w.write_varint(data.len() as i32);
        w.write_bytes(data);
        Ok(w.finish())
    } else {
        bail!("expected PlayPluginMessage IR")
    }
}

fn parse_custom_payload(data: &[u8]) -> Result<PacketIR> {
    parse_plugin_message(data)
}

fn serialize_custom_payload(ir: &PacketIR) -> Result<Vec<u8>> {
    serialize_plugin_message(ir)
}

/// Главная функция перевода serverbound пакета.
/// data — сырые байты пакета (без ID) от клиента с версией from_version.
/// Возвращает TranslationResult для отправки серверу с версией to_version.
pub fn translate_serverbound(
    id: i32,
    data: &[u8],
    from_version: &ProtocolVersion,
    to_version: &ProtocolVersion,
) -> Result<super::TranslationResult> {
    if from_version.id == to_version.id {
        return Ok(super::TranslationResult::PassThrough(id, data.to_vec()));
    }

    let ir = parse_serverbound(id, data, from_version)?;
    if !ir.needs_translation() {
        return Ok(super::TranslationResult::PassThrough(id, data.to_vec()));
    }

    let (new_id, new_data) = serialize_serverbound(&ir, to_version)?;
    Ok(super::TranslationResult::Packet(new_id, new_data))
}
