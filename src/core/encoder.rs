use image::{DynamicImage, GenericImageView, ImageBuffer, RgbImage};
use log::info;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use rand::{random, Rng};
use crate::crypto::crypto::{encrypt_message, hash_message};
use crate::formats::header::StegoHeader;
use crate::utils::index_db::MessageIndexDB;
use std::fs::File;
use std::io::BufWriter;
use png::{Encoder, Compression, FilterType};

pub struct StegoEncoder {
    pub bits_per_channel: u8,
    pub password: Option<String>,
    pub index_path: PathBuf,
}

impl StegoEncoder {
    pub fn new(bits_per_channel: u8, password: Option<String>, index_path: PathBuf) -> Self {
        if !(1..=3).contains(&bits_per_channel) {
            panic!("bits_per_channel debe estar entre 1 y 3");
        }
        Self { bits_per_channel, password, index_path }
    }

    pub fn encode_messages(&self, messages: &[&[u8]], directory: &Path) -> Result<Vec<(PathBuf, u32)>, String> {
        let start = Instant::now();
        let images = fs::read_dir(directory)
            .map_err(|e| format!("No se pudo leer el directorio: {}", e))?
            .filter_map(Result::ok)
            .filter(|f| f.path().extension().map_or(false, |ext| ext == "png"))
            .map(|f| f.path())
            .collect::<Vec<_>>();

        if images.is_empty() {
            return Err("No se encontraron imágenes PNG".to_string());
        }

        // Calcular y mostrar capacidad de todas las imágenes
        let mut image_capacities = Vec::new();
        for path in &images {
            let img = image::open(path).map_err(|e| format!("No se pudo abrir imagen {:?}: {}", path, e))?;
            let (width, height) = img.dimensions();
            let capacity = (width * height * 3 * self.bits_per_channel as u32) / 8;
            println!("Imagen: {:?}, Capacidad: {} bytes", path, capacity);
            image_capacities.push((path.clone(), capacity as usize));
        }

        // Crear la base de datos SQLite para el índice
        let db_path = self.index_path.with_extension("db");
        let index_db = MessageIndexDB::new(&db_path)
            .map_err(|e| format!("No se pudo crear/abrir la base de datos de índices: {}", e))?;

        let mut results = Vec::new();
        let mut usado_por_imagen: std::collections::HashMap<PathBuf, usize> = std::collections::HashMap::new();

        // Contador para hacer un seguimiento de cuál imagen estamos utilizando actualmente
        let mut current_image_index = 0;

        for message in messages {
            let encrypted = if let Some(ref password) = self.password {
                encrypt_message(message, password)?
            } else {
                message.to_vec()
            };

            let hash = hash_message(message);
            let message_id = random::<u32>();
            let header = StegoHeader {
                total_length: encrypted.len() as u64,
                current_offset: 0,
                message_hash: hash,
                message_id,
            }.to_bytes();

            let full_data = [header.as_slice(), encrypted.as_slice()].concat();
            println!("Tamaño del mensaje con ID {}: {} bytes", message_id, full_data.len());

            let mut written = false;
            let initial_image_index = current_image_index; // Guardamos el índice inicial para evitar bucle infinito

            // Intentamos con cada imagen, empezando por la actual y siguiendo hasta encontrar una con espacio
            loop {
                if current_image_index >= images.len() {
                    // Si llegamos al final de las imágenes, volvemos al principio
                    current_image_index = 0;
                }

                let path = &images[current_image_index];

                // Calculamos la capacidad total de la imagen
                let capacity = image_capacities[current_image_index].1;

                // Obtenemos los bytes usados previamente para esta imagen
                let bytes_usados = usado_por_imagen.get(path).cloned().unwrap_or(0);
                let espacio_disponible = capacity - bytes_usados;

                if full_data.len() <= espacio_disponible {
                    // Hay espacio suficiente, escribimos el mensaje
                    let mut img_buf = image::open(path)
                        .map_err(|e| format!("No se pudo abrir imagen {:?}: {}", path, e))?
                        .to_rgb8();

                    self.write_data_from_offset(&mut img_buf, &full_data, bytes_usados)?;
                    img_buf.save(path).map_err(|e| format!("Error al guardar imagen: {}", e))?;

                    // Actualizamos el seguimiento del espacio usado
                    let nuevo_usado = bytes_usados + full_data.len();
                    usado_por_imagen.insert(path.clone(), nuevo_usado);

                    let espacio_restante = capacity - nuevo_usado;
                    println!(
                        "Mensaje con ID {} ocultado en {:?}. Espacio restante: {} bytes",
                        message_id, path, espacio_restante
                    );

                    // Registrar en la base de datos SQLite
                    index_db.register(
                        message_id,
                        path,
                        bytes_usados,
                        &hash
                    ).map_err(|e| format!("Error al registrar mensaje en índice: {}", e))?;

                    results.push((path.clone(), message_id));
                    written = true;

                    // No avanzamos al siguiente índice si hay espacio disponible en la imagen actual
                    if espacio_restante < 1000 { // Umbral mínimo para considerar avanzar
                        current_image_index += 1;
                    }

                    break;
                }

                // No hay suficiente espacio, probamos con la siguiente imagen
                current_image_index += 1;

                // Si hemos probado todas las imágenes y volvemos al punto inicial sin éxito
                if current_image_index % images.len() == initial_image_index % images.len() && !written {
                    return Err(format!("No hay espacio suficiente en ninguna imagen para el mensaje con ID {}", message_id));
                }
            }
        }

        info!("Todos los mensajes fueron ocultados en {:?} ms", start.elapsed().as_millis());
        Ok(results)
    }

    fn write_data_from_offset(&self, img: &mut RgbImage, data: &[u8], offset_bytes: usize) -> Result<(), String> {
        let total_bits = data.len() * 8;
        let mut bit_idx = 0;

        let start_bit = offset_bytes * 8;
        let total_channels = 3; // RGB
        let pixels_per_row = img.width() as usize;

        let mut pixel_idx = start_bit / total_channels;
        let mut channel_idx = start_bit % total_channels;

        while bit_idx < total_bits {
            let y = pixel_idx / pixels_per_row;
            let x = pixel_idx % pixels_per_row;

            if y >= img.height() as usize {
                return Err("No hay suficiente espacio en la imagen".to_string());
            }

            let pixel = img.get_pixel_mut(x as u32, y as u32);
            let byte = data[bit_idx / 8];
            let bit_pos = 7 - (bit_idx % 8);
            let bit = (byte >> bit_pos) & 1;

            let mask = !(1 << (self.bits_per_channel - 1));
            pixel[channel_idx] = (pixel[channel_idx] & mask) | (bit << (self.bits_per_channel - 1));

            bit_idx += 1;
            channel_idx += 1;
            if channel_idx >= total_channels {
                channel_idx = 0;
                pixel_idx += 1;
            }
        }

        Ok(())
    }

}

fn count_used_bytes(img: &RgbImage, bits_per_channel: u8) -> usize {
    let mask = (1 << bits_per_channel) - 1;
    let used_bits = img.pixels()
        .flat_map(|p| p.0.iter())
        .filter(|&&c| (c & mask) != 0)
        .count();
    (used_bits + 7) / 8
}