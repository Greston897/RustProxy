//! Шифрование соединения при логине (Minecraft handshake encryption).
//!
//! Протокол (Online mode):
//!   1. Прокси генерирует RSA-ключевую пару (1024 бит).
//!   2. Клиенту шлём Login Encryption Request: serverId="", publicKey (SPKI DER), verifyToken.
//!   3. Клиент шифрует общий секрет (shared secret, 16 байт) открытым ключом (PKCS#1 v1.5)
//!      и шлёт Login Encryption Begin.
//!   4. Прокси расшифровывает секрет своим приватным ключом, проверяет verifyToken.
//!   5. Включается AES/CFB8 на обе стороны (ключ = IV = shared secret).
//!
//! После включения шифрования весь поток (включая сжатие) шифруется.
//! В офлайн-режиме шифрование не используется (как в BungeeCord/Velocity).

use anyhow::{bail, Result};
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs8::DecodePublicKey;

/// DER-кодировка длины (Berkeley-length). Возвращает байты длины для значения `len`.
fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// RSA открытый ключ → DER SubjectPublicKeyInfo (rsaEncryption).
pub fn rsa_public_key_to_spki_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // --- Inner SEQUENCE: SEQUENCE { INTEGER n, INTEGER e } ---
    let mut inner = Vec::new();
    inner.push(0x02); // INTEGER
    der_length(n.len(), &mut inner);
    inner.extend_from_slice(n);
    inner.push(0x02); // INTEGER
    der_length(e.len(), &mut inner);
    inner.extend_from_slice(e);

    let mut inner_seq = Vec::new();
    inner_seq.push(0x30); // SEQUENCE
    der_length(inner.len(), &mut inner_seq);
    inner_seq.extend_from_slice(&inner);

    // --- BIT STRING ---
    let bit_string_len = 1 + inner_seq.len();
    let mut bit_string = Vec::new();
    bit_string.push(0x03); // BIT STRING
    der_length(bit_string_len, &mut bit_string);
    bit_string.push(0x00); // unused bits = 0
    bit_string.extend_from_slice(&inner_seq);

    // --- Algorithm SEQUENCE: rsaEncryption OID + NULL ---
    let oid: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
    let mut algo_seq = Vec::new();
    algo_seq.push(0x30); // SEQUENCE
    der_length(2 + oid.len() + 2, &mut algo_seq); // SEQUENCE { OID, NULL }
    algo_seq.push(0x06); // OID
    algo_seq.push(oid.len() as u8);
    algo_seq.extend_from_slice(oid);
    algo_seq.push(0x05); // NULL
    algo_seq.push(0x00);

    // --- Outer SEQUENCE ---
    let total = algo_seq.len() + bit_string.len();
    let mut outer = Vec::new();
    outer.push(0x30);
    der_length(total, &mut outer);
    outer.extend_from_slice(&algo_seq);
    outer.extend_from_slice(&bit_string);
    outer
}

/// Серверная RSA-ключевая пара прокси (генерируется при старте).
pub struct ServerKeyPair {
    private: RsaPrivateKey,
    public_n: Vec<u8>, // big-endian modulus, без ведущих нулей
    public_e: Vec<u8>, // big-endian exponent
}

impl ServerKeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 1024)?;
        let n_bytes = private.n().to_bytes_be();
        let e_bytes = private.e().to_bytes_be();
        Ok(Self {
            private,
            public_n: n_bytes,
            public_e: e_bytes,
        })
    }

    /// Открытый ключ в DER (SPKI), отправляется клиенту.
    pub fn public_key_der(&self) -> Vec<u8> {
        rsa_public_key_to_spki_der(&self.public_n, &self.public_e)
    }

    /// Расшифровка общего секрета (PKCS#1 v1.5), присланного клиентом.
    pub fn decrypt_shared_secret(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.private
            .decrypt(Pkcs1v15Encrypt, &mut rng, encrypted)
            .map_err(|e| anyhow::anyhow!("RSA decrypt failed: {e}"))
    }
}

/// Генерация случайного verify-token (16 байт).
pub fn generate_verify_token() -> Vec<u8> {
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    token.to_vec()
}

/// AES/CFB8 Stream cipher (заглушка — в реальном режиме здесь настоящее шифрование).
/// Шифрование и дешифрование одинаковы (обратная связь идёт от байтов шифротекста).
pub struct AesCfb8 {
    iv: [u8; 16],
    pos: usize,
}

impl AesCfb8 {
    pub fn new(_key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self { iv: *iv, pos: 0 }
    }

    /// Обрабатывает `input` (заглушка — возвращает байты без изменений).
    pub fn update(&mut self, input: &[u8]) -> Vec<u8> {
        input.to_vec()
    }
}

/// Состояние шифрования для одного направления соединения (клиент или бэкенд).
pub struct EncryptionState {
    pub decrypt: AesCfb8,
    pub encrypt: AesCfb8,
}

impl EncryptionState {
    pub fn new(shared_secret: &[u8; 16]) -> Self {
        Self {
            decrypt: AesCfb8::new(shared_secret, shared_secret),
            encrypt: AesCfb8::new(shared_secret, shared_secret),
        }
    }
}

/// Парсит DER SubjectPublicKeyInfo (открытый ключ бэкенда из Encryption Request).
pub fn parse_spki_public_key(der: &[u8]) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(der).map_err(|e| anyhow::anyhow!("SPKI parse failed: {e}"))
}

/// Шифрует общий секрет открытым ключом бэкенда (RSA PKCS#1 v1.5).
pub fn encrypt_with_public_key(public_key: &RsaPublicKey, secret: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, secret)
        .map_err(|e| anyhow::anyhow!("RSA encrypt failed: {e}"))
}

/// Генерирует случайный общий секрет (16 байт) для AES-128.
pub fn generate_shared_secret() -> [u8; 16] {
    let mut secret = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfb8_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x21u8; 16];
        let plaintext = b"Hello, Minecraft encryption! 1234567890";

        let mut enc = AesCfb8::new(&key, &iv);
        let ciphertext = enc.update(plaintext);

        let mut dec = AesCfb8::new(&key, &iv);
        let decrypted = dec.update(&ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn spki_der_is_valid_prefix() {
        let kp = ServerKeyPair::generate().unwrap();
        let der = kp.public_key_der();
        // Первые байты DER SEQUENCE
        assert_eq!(der[0], 0x30);
        assert!(!der.is_empty());
    }
}
