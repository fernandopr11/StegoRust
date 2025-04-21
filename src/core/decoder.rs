use image::GenericImageView;
use std::fs;
use std::path::Path;
use log::info;
use std::time::Instant;
use crate::crypto::crypto::{decrypt_message, hash_message};
use crate::formats::header::{StegoHeader, HEADER_SIZE};
use crate::utils::index_db::MessageIndexDB;

pub struct StegoDecoder {
    pub bits_per_channel: u8,
    pub password: Option<String>,
    pub index_path: String,
}

impl StegoDecoder {
    pub fn new(bits_per_channel: u8, password: Option<String>, index_path: String) -> Self {
        if !(1..=3).contains(&bits_per_channel) {
            panic!("bits_per_channel debe estar entre 1 y 3");
        }
        Self { bits_per_channel, password, index_path }
    }

    pub fn decode_all_messages(&self) -> Result<Vec<Vec<u8>>, String> {
        let start = Instant::now();

        // Abrir la base de datos SQLite para el índice
        let db_path = Path::new(&self.index_path).with_extension("db");
        let index_db = MessageIndexDB::new(db_path.as_path())
            .map_err(|e| format!("No se pudo abrir la base de datos: {}", e))?;

        // Obtener información de todos los mensajes
        let all_messages = index_db.get_all_messages()
            .map_err(|e| format!("Error al recuperar mensajes del índice: {}", e))?;

        let mut messages = Vec::new();

        for (message_id, image_path, offset_bytes) in all_messages {
            match self.decode_message_from_location(&image_path, offset_bytes) {
                Ok(message) => messages.push(message),
                Err(e) => info!("Error al decodificar mensaje {}: {}", message_id, e),
            }
        }

        info!("Se recuperaron {} mensajes en {:?} ms", messages.len(), start.elapsed().as_millis());
        Ok(messages)
    }

    pub fn decode_message(&self, message_id: u32) -> Result<Vec<u8>, String> {
        let db_path = Path::new(&self.index_path).with_extension("db");
        let index_db = MessageIndexDB::new(db_path.as_path())
            .map_err(|e| format!("No se pudo abrir la base de datos: {}", e))?;

        // Obtener ubicación exacta del mensaje
        let (image_path, offset_bytes) = index_db.get_message_location(message_id)
            .map_err(|e| format!("Error al buscar mensaje: {}", e))?
            .ok_or_else(|| format!("Mensaje con ID {} no encontrado", message_id))?;

        self.decode_message_from_location(&image_path, offset_bytes)
    }

    fn decode_message_from_location(&self, image_path: &str, offset_bytes: usize) -> Result<Vec<u8>, String> {
        let img = image::open(image_path)
            .map_err(|e| format!("No se pudo abrir la imagen: {}", e))?;
        let img_buf = img.to_rgb8();

        let mut data = Vec::new();
        let mut current_byte = 0u8;
        let mut bit_count = 0;

        let total_channels = 3;
        let pixels_per_row = img_buf.width() as usize;

        let start_pixel_idx = offset_bytes * 8 / total_channels;
        let start_channel = offset_bytes * 8 % total_channels;

        let mut pixel_idx = start_pixel_idx;
        let mut channel_idx = start_channel;

        loop {
            let y = pixel_idx / pixels_per_row;
            let x = pixel_idx % pixels_per_row;

            if y >= img_buf.height() as usize {
                break;
            }

            let pixel = img_buf.get_pixel(x as u32, y as u32);
            let bit = (pixel[channel_idx] >> (self.bits_per_channel - 1)) & 1;

            current_byte = (current_byte << 1) | bit;
            bit_count += 1;

            if bit_count == 8 {
                data.push(current_byte);
                current_byte = 0;
                bit_count = 0;

                if data.len() >= HEADER_SIZE {
                    let header = StegoHeader::from_bytes(&data[0..HEADER_SIZE])?;
                    if data.len() >= HEADER_SIZE + header.total_length as usize {
                        let encrypted = &data[HEADER_SIZE..HEADER_SIZE + header.total_length as usize];
                        let decrypted = if let Some(ref password) = self.password {
                            decrypt_message(encrypted, password)?
                        } else {
                            encrypted.to_vec()
                        };

                        let computed_hash = hash_message(&decrypted);
                        if computed_hash == header.message_hash {
                            return Ok(decrypted);
                        }
                    }
                }
            }

            channel_idx += 1;
            if channel_idx >= total_channels {
                channel_idx = 0;
                pixel_idx += 1;
            }
        }

        Err("No se pudo recuperar un mensaje válido de los datos extraídos".to_string())
    }
}