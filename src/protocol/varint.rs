//! VarInt кодирование/декодирование по спецификации Minecraft.
//! Максимум 5 байт, значение знаковое i32 (отрицательные — 5 байт).

pub const VARINT_MAX_BYTES: usize = 5;

/// Читает VarInt из начала буфера. Возвращает None, если буфера не хватает
/// (нужно дождаться большего количества данных).
pub fn read_varint(buf: &[u8]) -> Option<(usize, i32)> {
    let mut result: i32 = 0;
    for (i, &byte) in buf.iter().enumerate().take(VARINT_MAX_BYTES) {
        result |= ((byte & 0x7f) as i32) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((i + 1, result));
        }
    }
    None
}

/// Пишет VarInt в конец вектора.
pub fn write_varint(mut value: i32, out: &mut Vec<u8>) {
    loop {
        if (value & !0x7f) == 0 {
            out.push(value as u8);
            return;
        }
        out.push((value & 0x7f | 0x80) as u8);
        value >>= 7;
    }
}

/// Готовый вектор с одним VarInt.
pub fn varint_bytes(value: i32) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(value, &mut out);
    out
}

/// Читает строку (VarInt длина + UTF-8 байты).
pub fn read_string(buf: &[u8]) -> Option<(usize, String)> {
    let (len_n, length) = read_varint(buf)?;
    let length = length as usize;
    let total = len_n + length;
    if buf.len() < total {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[len_n..total]).into_owned();
    Some((total, s))
}

/// Пишет строку (VarInt длина + UTF-8 байты).
pub fn write_string(s: &str, out: &mut Vec<u8>) {
    write_varint(s.len() as i32, out);
    out.extend_from_slice(s.as_bytes());
}
