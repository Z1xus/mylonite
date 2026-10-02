use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rand::Rng;

pub fn now_unix() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

pub fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
