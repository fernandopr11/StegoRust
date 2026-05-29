use image::RgbImage;
use rand::RngCore;
use uuid::Uuid;

use crate::{
    crypto::{derive_base_key, derive_message_key, encrypt, sha256},
    error::{Result, StegoError},
    formats::{ChunkHeader, CHUNK_HEADER_SIZE},
};

use super::lsb::LsbWriter;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`StegoEncoder`].
pub struct EncoderBuilder {
    bits_per_channel: u8,
}

impl Default for EncoderBuilder {
    fn default() -> Self {
        Self {
            bits_per_channel: 1,
        }
    }
}

impl EncoderBuilder {
    /// Sets the bits-per-channel for payload embedding (default: 1).
    pub fn bits_per_channel(mut self, bpc: u8) -> Self {
        self.bits_per_channel = bpc;
        self
    }

    /// Validates configuration and returns a [`StegoEncoder`].
    pub fn build(self) -> Result<StegoEncoder> {
        if self.bits_per_channel == 0 || self.bits_per_channel > 8 {
            return Err(StegoError::InvalidBitsPerChannel(self.bits_per_channel));
        }
        Ok(StegoEncoder {
            bits_per_channel: self.bits_per_channel,
        })
    }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Encodes a secret message into one or more cover images using LSB steganography.
///
/// Create via [`StegoEncoder::builder()`].
#[derive(Debug)]
pub struct StegoEncoder {
    bits_per_channel: u8,
}

impl StegoEncoder {
    /// Returns a new [`EncoderBuilder`] with default settings.
    pub fn builder() -> EncoderBuilder {
        EncoderBuilder::default()
    }

    /// Splits `message` into chunks that fit within the given images.
    ///
    /// The header (88 bytes) is always written at bpc=1.
    /// The payload (ciphertext + 16-byte GCM tag) is written at `bpc`.
    pub(crate) fn split_message(
        message: &[u8],
        images: &[RgbImage],
        bpc: u8,
    ) -> Result<Vec<Vec<u8>>> {
        if images.is_empty() {
            return Err(StegoError::InvalidConfig("no cover images provided".into()));
        }

        const GCM_TAG: usize = 16;

        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut remaining = message;

        for img in images {
            if remaining.is_empty() {
                break;
            }
            let total_channels = img.width() as usize * img.height() as usize * 3;
            // Header uses bpc=1 → CHUNK_HEADER_SIZE * 8 channel-slots at b=1
            let header_channels = CHUNK_HEADER_SIZE * 8;
            let payload_channels = total_channels.saturating_sub(header_channels);
            let payload_bytes = payload_channels * bpc as usize / 8;
            let plaintext_cap = payload_bytes.saturating_sub(GCM_TAG);

            let take = remaining.len().min(plaintext_cap);
            chunks.push(remaining[..take].to_vec());
            remaining = &remaining[take..];
        }

        if !remaining.is_empty() {
            let total_available: usize = images
                .iter()
                .map(|img| {
                    let total_channels = img.width() as usize * img.height() as usize * 3;
                    let payload_channels = total_channels.saturating_sub(CHUNK_HEADER_SIZE * 8);
                    payload_channels * bpc as usize / 8
                })
                .sum::<usize>()
                .saturating_sub(images.len() * GCM_TAG);
            return Err(StegoError::InsufficientCapacity {
                needed: message.len(),
                available: total_available,
            });
        }

        if chunks.is_empty() {
            chunks.push(Vec::new());
        }

        Ok(chunks)
    }

    /// Encodes `message` into `cover_images` using `password`.
    ///
    /// Returns the stego images (one per chunk). The number of output images
    /// is ≤ `cover_images.len()` and equals the number of chunks required.
    pub fn encode(
        self,
        cover_images: Vec<RgbImage>,
        message: &[u8],
        password: &[u8],
    ) -> Result<Vec<RgbImage>> {
        if cover_images.is_empty() {
            return Err(StegoError::InvalidConfig("no cover images provided".into()));
        }
        if cover_images.len() > 255 {
            return Err(StegoError::InvalidConfig(
                "too many cover images (max 255)".into(),
            ));
        }

        let bpc = self.bits_per_channel;
        let chunks = Self::split_message(message, &cover_images, bpc)?;
        let total_chunks = chunks.len() as u8;

        let message_id: [u8; 16] = *Uuid::new_v4().as_bytes();
        let payload_hash = sha256(message);

        let mut result_images = Vec::with_capacity(chunks.len());

        for (i, chunk) in chunks.iter().enumerate() {
            let cover = &cover_images[i];

            let mut argon2_salt = [0u8; 16];
            let mut aes_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut argon2_salt);
            rand::thread_rng().fill_bytes(&mut aes_nonce);

            let base_key = derive_base_key(password, &argon2_salt)?;
            let aes_key = derive_message_key(&base_key, &message_id)?;

            let ciphertext_len = chunk.len() + 16; // 16-byte GCM tag

            let header = ChunkHeader {
                message_id,
                chunk_index: i as u8,
                total_chunks,
                payload_length: ciphertext_len as u64,
                argon2_salt,
                aes_nonce,
                payload_hash,
                bits_per_channel: bpc,
                reserved: 0,
            };
            let header_bytes = header.to_bytes();

            let ciphertext = encrypt(&aes_key, &aes_nonce, chunk, &header_bytes)?;

            // Final capacity check
            let total_channels = cover.width() as usize * cover.height() as usize * 3;
            let header_channels = CHUNK_HEADER_SIZE * 8; // at bpc=1
            let payload_channels_needed = (ciphertext.len() * 8).div_ceil(bpc as usize);
            if header_channels + payload_channels_needed > total_channels {
                return Err(StegoError::InsufficientCapacity {
                    needed: CHUNK_HEADER_SIZE + ciphertext.len(),
                    available: total_channels * bpc as usize / 8,
                });
            }

            let mut writer = LsbWriter::new(cover.clone());
            writer.write_bits(&header_bytes, 1)?;
            writer.write_bits(&ciphertext, bpc)?;
            result_images.push(writer.into_image());
        }

        Ok(result_images)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::RgbImage;

    fn blank(w: u32, h: u32) -> RgbImage {
        RgbImage::new(w, h)
    }

    #[test]
    fn builder_default_succeeds() {
        assert!(StegoEncoder::builder().build().is_ok());
    }

    #[test]
    fn builder_bpc0_fails() {
        let err = StegoEncoder::builder()
            .bits_per_channel(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, StegoError::InvalidBitsPerChannel(0)));
    }

    #[test]
    fn builder_bpc2_canonical() {
        assert!(StegoEncoder::builder().bits_per_channel(2).build().is_ok());
    }

    #[test]
    fn split_300_bytes_fits_in_one_100x100() {
        let images: Vec<RgbImage> = vec![blank(100, 100)];
        let msg: Vec<u8> = (0..300).map(|b| b as u8).collect();
        let chunks = StegoEncoder::split_message(&msg, &images, 1).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 300);
    }

    #[test]
    fn split_50_bytes_3_images_single_chunk() {
        let images: Vec<RgbImage> = (0..3).map(|_| blank(100, 100)).collect();
        let msg = vec![0u8; 50];
        let chunks = StegoEncoder::split_message(&msg, &images, 1).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 50);
    }

    #[test]
    fn encode_10_bytes_100x100_succeeds() {
        let cover = vec![blank(100, 100)];
        let enc = StegoEncoder::builder().build().unwrap();
        let out = enc.encode(cover, b"hello enc!", b"pass").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].width(), 100);
    }

    #[test]
    fn encode_1mb_into_10x10_insufficient_capacity() {
        let cover = vec![blank(10, 10)];
        let enc = StegoEncoder::builder().build().unwrap();
        let msg = vec![0u8; 1024 * 1024];
        let err = enc.encode(cover, &msg, b"pass").unwrap_err();
        assert!(matches!(err, StegoError::InsufficientCapacity { .. }));
    }
}
