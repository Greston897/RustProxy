//! Minecraft фрейм-кодек: длина пакета (VarInt) + опциональное zlib-сжатие + опциональное шифрование.
//!
//! Стек обработки потока:
//!   Входящий:  TCP-байты → [RSA/AES дешифровка] → буфер расшифрованных байт → фреймы (VarInt длина) → [zlib распаковка] → пакеты
//!   Исходящий: пакеты → [zlib упаковка] → фреймы (VarInt длина) → [AES шифрование] → TCP-байты
//!
//! Шифрование включается пакетом Login Encryption Begin в фазе логина и остаётся
//! активным до конца соединения (включая игровую фазу Play).

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Read;
use tokio_util::codec::{Decoder, Encoder};

use crate::protocol::encryption::{EncryptionState, AesCfb8};
use crate::protocol::varint::{read_varint, read_string, write_string, write_varint, varint_bytes};

/// Абсолютный лимит размера одного кадра (защита от памяти).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

pub struct MinecraftCodec {
    compression_threshold: Option<i32>,
    encryption: Option<EncryptionState>,
    /// Расшифрованные, но ещё не разобранные на фреймы байты.
    pending: BytesMut,
}

impl MinecraftCodec {
    pub fn new() -> Self {
        Self {
            compression_threshold: None,
            encryption: None,
            pending: BytesMut::new(),
        }
    }

    pub fn set_compression(&mut self, threshold: i32) {
        self.compression_threshold = Some(threshold);
    }

    pub fn compression_threshold(&self) -> Option<i32> {
        self.compression_threshold
    }

    /// Включает AES/CFB8 шифрование на обоих направлениях.
    /// Ключ и IV = общий секрет (16 байт), как в протоколе Minecraft.
    pub fn enable_encryption(&mut self, shared_secret: &[u8; 16]) {
        self.encryption = Some(EncryptionState::new(shared_secret));
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }
}

impl Decoder for MinecraftCodec {
    type Item = Vec<u8>; // сырые байты пакета: VarInt id + тело
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // 1. Декодируем новые байты из src в pending (с расшифровкой если включено шифрование)
        if let Some(ref enc) = self.encryption {
            let decrypted = enc.decrypt.update(src);
            self.pending.extend_from_slice(&decrypted);
            src.clear();
        } else {
            self.pending.extend_from_slice(src);
            src.clear();
        }

        // 2. Пытаемся вытащить один полный фрейм из pending
        loop {
            if self.pending.is_empty() {
                return Ok(None);
            }

            let Some((len_n, packet_len)) = read_varint(&self.pending) else {
                return Ok(None); // не пришла полная длина — ждём данные
            };
            let packet_len = packet_len as usize;
            if packet_len > MAX_FRAME_SIZE {
                bail!("frame too large: {packet_len} bytes");
            }
            let total = len_n + packet_len;
            if self.pending.len() < total {
                return Ok(None); // фрейм не дошёл полностью
            }
            let frame = self.pending.split_to(total);
            let payload = &frame[len_n..];

            // 3. Тело с учётом сжатия
            let packet = match self.compression_threshold {
                None => payload.to_vec(),
                Some(threshold) => {
                    let Some((dlen_n, data_len)) = read_varint(payload) else {
                        bail!("incomplete data length varint");
                    };
                    let data_len = data_len as usize;
                    let body = if data_len == 0 {
                        // несжатый пакет
                        &payload[dlen_n..]
                    } else {
                        // zlib-разжатие
                        let compressed = &payload[dlen_n..];
                        let mut decoder = ZlibDecoder::new(compressed);
                        let mut out = Vec::new();
                        decoder
                            .read_to_end(&mut out)
                            .context("zlib decompress failed")?;
                        out
                    };
                    body.to_vec()
                }
            };

            return Ok(Some(packet));
        }
    }
}

impl Encoder<Vec<u8>> for MinecraftCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, packet: Vec<u8>, dst: &mut BytesMut) -> Result<()> {
        // 1. Собираем фрейм: VarInt длина + [zlib-префикс + полезная нагрузка]
        let (prefix, payload) = match self.compression_threshold {
            None => (Vec::new(), packet),
            Some(threshold) => {
                if packet.len() < threshold as usize {
                    let mut dlen = Vec::new();
                    write_varint(0, &mut dlen);
                    (dlen, packet)
                } else {
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    std::io::Write::write_all(&mut encoder, &packet)
                        .context("zlib compress write failed")?;
                    let compressed = encoder.finish().context("zlib compress finish failed")?;
                    let mut dlen = Vec::new();
                    write_varint(compressed.len() as i32, &mut dlen);
                    (dlen, compressed)
                }
            }
        };

        let frame_len = prefix.len() + payload.len();
        let mut frame = Vec::with_capacity(frame_len + 8);
        write_varint(frame_len as i32, &mut frame);
        frame.extend_from_slice(&prefix);
        frame.extend_from_slice(&payload);

        // 2. Шифруем весь фрейм, если шифрование включено
        if let Some(ref enc) = self.encryption {
            let encrypted = enc.encrypt.update(&frame);
            dst.extend_from_slice(&encrypted);
        } else {
            dst.extend_from_slice(&frame);
        }
        Ok(())
    }
}
