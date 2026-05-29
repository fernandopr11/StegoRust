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

    /// Decodes all chunks from `images` and reassembles the original message.
    ///
    /// Images may be provided in any order. All chunks must belong to the same
    /// logical message (same `message_id`).
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

    #[test]
    fn builder_constructs() {
        let _dec = StegoDecoder::builder().build();
    }
}
