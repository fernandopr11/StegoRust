use image::RgbImage;
use rand::RngCore;
use uuid::Uuid;

use crate::{
    crypto::{derive_base_key, derive_message_key, encrypt, sha256},
    error::{Result, StegoError},
    formats::{ChunkHeader, CHUNK_HEADER_SIZE},
};

use super::lsb::{LsbReader, LsbWriter};

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

/// Scans `img` sequentially reading [`ChunkHeader`]s at bpc=1 to find how many
/// channels are already occupied by existing messages. Stops at the first
/// invalid header. This is O(n_messages), not O(pixels).
pub fn scan_used_channels(img: &RgbImage) -> usize {
    let total = img.width() as usize * img.height() as usize * 3;
    let mut channel_idx = 0;
    loop {
        // Need room for at least one header
        if channel_idx + CHUNK_HEADER_SIZE * 8 > total {
            break;
        }
        let mut reader = LsbReader::new_at(img, channel_idx);
        let Ok(header_bytes) = reader.read_bits(CHUNK_HEADER_SIZE, 1) else {
            break;
        };
        let Ok(header) = ChunkHeader::from_bytes(&header_bytes) else {
            break;
        };
        // Advance past header (bpc=1) + payload (bpc=header.bits_per_channel)
        let header_channels = CHUNK_HEADER_SIZE * 8;
        let payload_channels =
            (header.payload_length as usize * 8).div_ceil(header.bits_per_channel as usize);
        channel_idx += header_channels + payload_channels;
        if channel_idx >= total {
            break;
        }
    }
    channel_idx
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

    /// Encodes multiple independent messages into `cover_images`, packing them
    /// back-to-back. When an image is full, overflow continues into the next image.
    ///
    /// Returns the modified images (every image that was written to at least once).
    /// Returns [`StegoError::InsufficientCapacity`] if no image has room for a message.
    pub fn encode_many(
        self,
        mut cover_images: Vec<RgbImage>,
        messages: &[&[u8]],
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
        let mut modified: Vec<bool> = vec![false; cover_images.len()];

        for message in messages {
            // Each message is encoded as a single chunk (single-image per message for now).
            // Find the first image with enough free space.
            let message_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
            let payload_hash = crate::crypto::sha256(message);

            let mut placed = false;

            for (img_idx, img) in cover_images.iter_mut().enumerate() {
                let start_channel = scan_used_channels(img);
                let total_channels = img.width() as usize * img.height() as usize * 3;

                // Compute available space from start_channel
                let remaining_channels = total_channels.saturating_sub(start_channel);
                let header_channels = CHUNK_HEADER_SIZE * 8; // bpc=1
                if remaining_channels <= header_channels {
                    continue;
                }
                let payload_channels = remaining_channels - header_channels;
                let payload_bytes = payload_channels * bpc as usize / 8;
                let plaintext_cap = payload_bytes.saturating_sub(16); // GCM tag

                if message.len() > plaintext_cap {
                    continue;
                }

                // Encode this message into this image at start_channel
                let mut argon2_salt = [0u8; 16];
                let mut aes_nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut argon2_salt);
                rand::thread_rng().fill_bytes(&mut aes_nonce);

                let base_key = crate::crypto::derive_base_key(password, &argon2_salt)?;
                let aes_key = crate::crypto::derive_message_key(&base_key, &message_id)?;

                let ciphertext_len = message.len() + 16;
                let header = ChunkHeader {
                    message_id,
                    chunk_index: 0,
                    total_chunks: 1,
                    payload_length: ciphertext_len as u64,
                    argon2_salt,
                    aes_nonce,
                    payload_hash,
                    bits_per_channel: bpc,
                    reserved: 0,
                };
                let header_bytes = header.to_bytes();
                let ciphertext =
                    crate::crypto::encrypt(&aes_key, &aes_nonce, message, &header_bytes)?;

                let mut writer = LsbWriter::new_at(img.clone(), start_channel);
                writer.write_bits(&header_bytes, 1)?;
                writer.write_bits(&ciphertext, bpc)?;
                *img = writer.into_image();
                modified[img_idx] = true;
                placed = true;
                break;
            }

            if !placed {
                return Err(StegoError::InsufficientCapacity {
                    needed: message.len(),
                    available: 0,
                });
            }
        }

        Ok(cover_images
            .into_iter()
            .zip(modified.iter())
            .filter_map(|(img, &m)| if m { Some(img) } else { None })
            .collect())
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

    #[test]
    fn scan_used_channels_empty_image_returns_zero() {
        let img = blank(100, 100);
        // Fresh image has no valid headers, scan returns 0
        assert_eq!(scan_used_channels(&img), 0);
    }

    #[test]
    fn scan_used_channels_after_one_encode() {
        let cover = vec![blank(100, 100)];
        let enc = StegoEncoder::builder().build().unwrap();
        let stego = enc.encode(cover, b"hello", b"pass").unwrap();
        let used = scan_used_channels(&stego[0]);
        // Should be header_channels + payload_channels > 0
        assert!(used > CHUNK_HEADER_SIZE * 8);
    }

    #[test]
    fn scan_used_channels_zero_for_tiny_image() {
        // Image too small to fit a header
        let img = blank(1, 1); // 3 channels, header needs 704
        assert_eq!(scan_used_channels(&img), 0);
    }

    #[test]
    fn encode_many_two_messages_one_image() {
        let cover = vec![blank(200, 200)];
        let enc = StegoEncoder::builder().build().unwrap();
        let msgs: &[&[u8]] = &[b"first message", b"second message"];
        let result = enc.encode_many(cover, msgs, b"pass");
        assert!(result.is_ok());
        let imgs = result.unwrap();
        assert_eq!(imgs.len(), 1);
        // Verify two headers are packed
        let used = scan_used_channels(&imgs[0]);
        assert!(used > CHUNK_HEADER_SIZE * 8 * 2);
    }

    #[test]
    fn encode_many_overflow_to_second_image() {
        // 100x100 = 30000 channels at bpc=1; header = 704 channels (88*8);
        // payload capacity = 29296 channels = 29296 bits / 8 = 3662 bytes - 16 GCM = 3646 plaintext
        // A message of 3646 bytes fills image 0 completely; "second" must go to image 1.
        let covers = vec![blank(100, 100), blank(100, 100)];
        let enc = StegoEncoder::builder().build().unwrap();
        let big_msg = vec![0u8; 3646]; // exactly fills first image
        let small_msg = b"second";
        let msgs: &[&[u8]] = &[&big_msg, small_msg];
        let imgs = enc.encode_many(covers, msgs, b"pass").unwrap();
        // Both images should be returned (both modified)
        assert_eq!(imgs.len(), 2);
    }

    #[test]
    fn encode_many_no_space_returns_error() {
        let cover = vec![blank(10, 10)]; // too small
        let enc = StegoEncoder::builder().build().unwrap();
        let msgs: &[&[u8]] = &[b"hello"];
        let err = enc.encode_many(cover, msgs, b"pass").unwrap_err();
        assert!(matches!(err, StegoError::InsufficientCapacity { .. }));
    }
}
