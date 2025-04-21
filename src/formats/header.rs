// src/header.rs

use std::convert::TryInto;

pub const HEADER_SIZE: usize = 36;
pub const MAGIC: &[u8; 4] = b"STEG";
pub const VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct StegoHeader {
    pub total_length: u64,
    pub current_offset: u64,
    pub message_hash: [u8; 8],
    pub message_id: u32,
}

impl StegoHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buffer = [0u8; HEADER_SIZE];

        buffer[0..4].copy_from_slice(MAGIC);
        buffer[4] = VERSION;
        buffer[5..13].copy_from_slice(&self.total_length.to_be_bytes());
        buffer[13..21].copy_from_slice(&self.current_offset.to_be_bytes());
        buffer[21..29].copy_from_slice(&self.message_hash);
        buffer[29..33].copy_from_slice(&self.message_id.to_be_bytes());

        buffer
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != HEADER_SIZE {
            return Err("Tamaño de encabezado incorrecto".to_string());
        }
        if &data[0..4] != MAGIC {
            return Err("Firma de encabezado inválida".to_string());
        }
        if data[4] != VERSION {
            return Err(format!("Versión no soportada: {}", data[4]));
        }

        let total_length = u64::from_be_bytes(data[5..13].try_into().unwrap());
        let current_offset = u64::from_be_bytes(data[13..21].try_into().unwrap());
        let mut message_hash = [0u8; 8];
        message_hash.copy_from_slice(&data[21..29]);
        let message_id = u32::from_be_bytes(data[29..33].try_into().unwrap());

        Ok(StegoHeader {
            total_length,
            current_offset,
            message_hash,
            message_id,
        })
    }
}
