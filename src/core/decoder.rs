use std::collections::HashMap;

use image::RgbImage;

use crate::{
    crypto::{decrypt, derive_base_key, derive_message_key, sha256},
    error::{Result, StegoError},
    formats::{ChunkHeader, CHUNK_HEADER_SIZE},
};

use super::lsb::LsbReader;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`StegoDecoder`].
#[derive(Default)]
pub struct DecoderBuilder {
    _priv: (),
}

impl DecoderBuilder {
    /// Returns a configured [`StegoDecoder`].
    pub fn build(self) -> StegoDecoder {
        StegoDecoder { _priv: () }
    }
}

// ---------------------------------------------------------------------------
// Decoded chunk
// ---------------------------------------------------------------------------

/// Result of decoding a single stego image.
pub struct DecodedChunk {
    /// UUID identifying the logical message this chunk belongs to.
    pub message_id: [u8; 16],
    /// 0-based position of this chunk within the message.
    pub chunk_index: u8,
    /// Total number of chunks in the message.
    pub total_chunks: u8,
    /// Decrypted plaintext payload of this chunk.
    pub payload: Vec<u8>,
    /// SHA-256 of the full reassembled plaintext (from the header).
    pub payload_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Decodes a secret message from one or more stego images.
///
/// Create via [`StegoDecoder::builder()`].
pub struct StegoDecoder {
    _priv: (),
}

impl StegoDecoder {
    /// Returns a new [`DecoderBuilder`].
    pub fn builder() -> DecoderBuilder {
        DecoderBuilder::default()
    }

    /// Decodes a single stego image using `password`.
    ///
    /// The header is always read at bpc=1 (bootstrap convention). If
    /// `header.bits_per_channel != 1` the payload is read at the declared bpc.
    ///
    /// Returns [`StegoError::AuthenticationFailed`] on wrong password or tamper.
    pub fn decode_image(img: &RgbImage, password: &[u8]) -> Result<DecodedChunk> {
        // Step 1: read header at bpc=1
        let mut reader = LsbReader::new(img);
        let header_bytes = reader.read_bits(CHUNK_HEADER_SIZE, 1)?;
        let header = ChunkHeader::from_bytes(&header_bytes)?;

        // Step 2: read payload at header.bits_per_channel
        let bpc = header.bits_per_channel;
        let ct_len = header.payload_length as usize;

        // If bpc != 1 the payload bytes start right after the header in the bpc stream.
        // The header consumed CHUNK_HEADER_SIZE * 8 bit-slots at bpc=1 = CHUNK_HEADER_SIZE*8
        // channels. The payload starts at channel CHUNK_HEADER_SIZE*8 (bpc=1 slots).
        // We need to re-position the reader for bpc > 1.
        let ciphertext = if bpc == 1 {
            reader.read_bits(ct_len, bpc)?
        } else {
            // Payload is at channel_idx = CHUNK_HEADER_SIZE * 8 (each bpc=1 slot = 1 channel).
            // For bpc-based reading we start at that same channel offset.
            let mut pr = LsbReader::new_at(img, CHUNK_HEADER_SIZE * 8);
            pr.read_bits(ct_len, bpc)?
        };

        // Step 3: derive key
        let base_key = derive_base_key(password, &header.argon2_salt)?;
        let aes_key = derive_message_key(&base_key, &header.message_id)?;

        // Step 4: decrypt (header bytes as AAD)
        let plaintext = decrypt(&aes_key, &header.aes_nonce, &ciphertext, &header_bytes)?;

        // Step 5: hash check — verify partial chunk integrity (for single-image decoding)
        // The full-message hash is validated in decode() after reassembly.

        Ok(DecodedChunk {
            message_id: header.message_id,
            chunk_index: header.chunk_index,
            total_chunks: header.total_chunks,
            payload: plaintext,
            payload_hash: header.payload_hash,
        })
    }

    /// Scans `img` for ALL [`ChunkHeader`]s sequentially (at bpc=1 bootstrap).
    /// Tries to decrypt each chunk with `password`. Skips chunks where authentication
    /// fails (wrong password for that message or padding). Stops at the first
    /// structurally invalid header.
    pub fn scan_image(img: &RgbImage, password: &[u8]) -> Vec<DecodedChunk> {
        use rayon::prelude::*;

        let total = img.width() as usize * img.height() as usize * 3;
        let mut channel_idx = 0;

        // Phase 1: scan headers sequentially (fast — just bit reads, no crypto)
        let mut work_items: Vec<(usize, Vec<u8>, ChunkHeader)> = Vec::new();
        loop {
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

            let bpc = header.bits_per_channel;
            let ct_len = header.payload_length as usize;
            let payload_channels = (ct_len * 8).div_ceil(bpc as usize);
            let payload_channel_start = channel_idx + CHUNK_HEADER_SIZE * 8;

            // Read ciphertext bytes (still sequential — pixel reads are not thread-safe)
            let ciphertext = if bpc == 1 {
                reader.read_bits(ct_len, bpc)
            } else {
                LsbReader::new_at(img, payload_channel_start).read_bits(ct_len, bpc)
            };

            channel_idx += CHUNK_HEADER_SIZE * 8 + payload_channels;

            if let Ok(ct) = ciphertext {
                work_items.push((channel_idx, ct, header));
            }
            if channel_idx >= total {
                break;
            }
        }

        // Phase 2: decrypt all chunks in parallel (Argon2id is the bottleneck)
        work_items
            .into_par_iter()
            .filter_map(|(_, ciphertext, header)| {
                let header_bytes = header.to_bytes();
                let base_key =
                    crate::crypto::derive_base_key(password, &header.argon2_salt).ok()?;
                let aes_key =
                    crate::crypto::derive_message_key(&base_key, &header.message_id).ok()?;
                let plaintext =
                    crate::crypto::decrypt(&aes_key, &header.aes_nonce, &ciphertext, &header_bytes)
                        .ok()?;
                Some(DecodedChunk {
                    message_id: header.message_id,
                    chunk_index: header.chunk_index,
                    total_chunks: header.total_chunks,
                    payload: plaintext,
                    payload_hash: header.payload_hash,
                })
            })
            .collect()
    }

    /// Decodes ALL messages from `images` that can be decrypted with `password`.
    ///
    /// Returns a [`Vec`] of recovered plaintexts, one per logical `message_id` found.
    /// Messages whose chunks span multiple images are reassembled automatically.
    /// Use [`decode`] for single-message backward compatibility.
    pub fn decode_many(self, images: Vec<RgbImage>, password: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Collect all decoded chunks across all images, keyed by message_id
        let mut by_id: HashMap<[u8; 16], Vec<DecodedChunk>> = HashMap::new();

        for img in &images {
            for chunk in Self::scan_image(img, password) {
                by_id.entry(chunk.message_id).or_default().push(chunk);
            }
        }

        if by_id.is_empty() {
            return Err(StegoError::AuthenticationFailed);
        }

        let mut messages = Vec::new();

        for (_id, mut chunks) in by_id {
            chunks.sort_by_key(|c| c.chunk_index);
            let total = chunks[0].total_chunks as usize;
            if chunks.len() != total {
                return Err(StegoError::MissingChunks {
                    found: chunks.len(),
                    expected: total,
                });
            }
            let expected_hash = chunks[0].payload_hash;
            let mut message = Vec::new();
            for chunk in chunks {
                message.extend_from_slice(&chunk.payload);
            }
            let hash = crate::crypto::sha256(&message);
            if hash != expected_hash {
                return Err(StegoError::IntegrityCheckFailed);
            }
            messages.push(message);
        }

        Ok(messages)
    }

    /// Decodes all chunks from `images` and reassembles the original message.
    ///
    /// Images may be provided in any order. All chunks must belong to the same
    /// logical message (same `message_id`). For multi-message images, only the
    /// first successfully decrypted message is returned. Use [`decode_many`] to
    /// recover all messages.
    ///
    /// [`decode_many`]: StegoDecoder::decode_many
    pub fn decode(self, images: Vec<RgbImage>, password: &[u8]) -> Result<Vec<u8>> {
        let mut chunks: HashMap<u8, DecodedChunk> = HashMap::new();
        let mut expected_total: Option<u8> = None;
        let mut expected_msg_id: Option<[u8; 16]> = None;
        let mut expected_hash: Option<[u8; 32]> = None;

        for img in &images {
            let chunk = Self::decode_image(img, password)?;

            // Cross-image consistency checks
            if let Some(id) = expected_msg_id {
                if id != chunk.message_id {
                    return Err(StegoError::MixedMessages);
                }
            } else {
                expected_msg_id = Some(chunk.message_id);
            }

            if let Some(t) = expected_total {
                if t != chunk.total_chunks {
                    return Err(StegoError::InvalidHeader);
                }
            } else {
                expected_total = Some(chunk.total_chunks);
            }

            expected_hash = Some(chunk.payload_hash);

            if chunks.contains_key(&chunk.chunk_index) {
                return Err(StegoError::DuplicateChunk(chunk.chunk_index));
            }
            chunks.insert(chunk.chunk_index, chunk);
        }

        let total = expected_total.unwrap_or(0) as usize;
        if chunks.len() != total {
            return Err(StegoError::MissingChunks {
                found: chunks.len(),
                expected: total,
            });
        }

        // Reassemble in order
        let mut message = Vec::new();
        for i in 0..total as u8 {
            let chunk = chunks.remove(&i).ok_or(StegoError::MissingChunks {
                found: chunks.len(),
                expected: total,
            })?;
            message.extend_from_slice(&chunk.payload);
        }

        // Final integrity check
        let hash = sha256(&message);
        if hash != expected_hash.unwrap_or([0u8; 32]) {
            return Err(StegoError::IntegrityCheckFailed);
        }

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::encoder::StegoEncoder;
    use image::RgbImage;

    fn blank(w: u32, h: u32) -> RgbImage {
        RgbImage::new(w, h)
    }

    #[test]
    fn builder_constructs() {
        let _dec = StegoDecoder::builder().build();
    }

    #[test]
    fn scan_image_empty_returns_nothing() {
        let img = blank(100, 100);
        let chunks = StegoDecoder::scan_image(&img, b"any");
        assert!(chunks.is_empty());
    }

    #[test]
    fn scan_image_finds_one_message() {
        let cover = vec![blank(200, 200)];
        let enc = StegoEncoder::builder().build().unwrap();
        let stego = enc.encode(cover, b"hello scan", b"pass").unwrap();
        let chunks = StegoDecoder::scan_image(&stego[0], b"pass");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].payload, b"hello scan");
    }

    #[test]
    fn scan_image_wrong_password_skips_chunk() {
        let cover = vec![blank(200, 200)];
        let enc = StegoEncoder::builder().build().unwrap();
        let stego = enc.encode(cover, b"secret", b"correct").unwrap();
        // Wrong password — chunk is present but auth fails, so scan returns nothing
        let chunks = StegoDecoder::scan_image(&stego[0], b"wrong");
        assert!(chunks.is_empty());
    }

    #[test]
    fn decode_many_two_messages_one_image() {
        let cover = vec![blank(300, 300)];
        let enc = StegoEncoder::builder().build().unwrap();
        let msgs: &[&[u8]] = &[b"message one", b"message two"];
        let stego = enc.encode_many(cover, msgs, b"pass").unwrap();

        let dec = StegoDecoder::builder().build();
        let mut recovered = dec.decode_many(stego, b"pass").unwrap();
        assert_eq!(recovered.len(), 2);
        // Sort for deterministic comparison
        recovered.sort();
        let mut expected = vec![b"message one".to_vec(), b"message two".to_vec()];
        expected.sort();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn decode_many_no_messages_returns_error() {
        let img = blank(100, 100);
        let dec = StegoDecoder::builder().build();
        let err = dec.decode_many(vec![img], b"pass").unwrap_err();
        assert!(matches!(err, StegoError::AuthenticationFailed));
    }

    #[test]
    fn decode_many_wrong_password_returns_error() {
        let cover = vec![blank(200, 200)];
        let enc = StegoEncoder::builder().build().unwrap();
        let stego = enc
            .encode_many(cover, &[b"secret" as &[u8]], b"correct")
            .unwrap();
        let dec = StegoDecoder::builder().build();
        let err = dec.decode_many(stego, b"wrong").unwrap_err();
        assert!(matches!(err, StegoError::AuthenticationFailed));
    }
}
