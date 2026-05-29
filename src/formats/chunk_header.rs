use crate::error::{Result, StegoError};

/// Serialized size of a [`ChunkHeader`] in bytes.
pub const CHUNK_HEADER_SIZE: usize = 88;

/// Per-chunk header embedded at the start of every stego image.
///
/// Serialized as exactly 88 bytes written in the LSBs at bits-per-channel = 1
/// (the bootstrap convention), regardless of the configured `bits_per_channel`
/// for the payload. The header bytes are used as AAD for AES-256-GCM so any
/// bit-flip in the header is detected as [`StegoError::AuthenticationFailed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// UUID v4 shared by all chunks of a single logical message.
    pub message_id: [u8; 16],
    /// 0-based position of this chunk within the message.
    pub chunk_index: u8,
    /// Total number of chunks composing this message (1–255).
    pub total_chunks: u8,
    /// Length in bytes of the encrypted payload (ciphertext + GCM tag).
    pub payload_length: u64,
    /// Per-chunk Argon2id salt for the base-key derivation.
    pub argon2_salt: [u8; 16],
    /// Per-chunk AES-256-GCM nonce (12 bytes).
    pub aes_nonce: [u8; 12],
    /// SHA-256 of the full reassembled plaintext (same in every chunk).
    pub payload_hash: [u8; 32],
    /// LSB bits-per-channel used for the payload following this header.
    pub bits_per_channel: u8,
    /// Reserved byte — must be `0` in v0.2.0.
    pub reserved: u8,
}

impl ChunkHeader {
    /// Serialized size in bytes.
    pub const SIZE: usize = CHUNK_HEADER_SIZE;

    /// Serializes the header to a fixed 88-byte array.
    ///
    /// `payload_length` is encoded as big-endian u64. All other fields are
    /// appended in declaration order.
    pub fn to_bytes(&self) -> [u8; CHUNK_HEADER_SIZE] {
        let mut buf = [0u8; CHUNK_HEADER_SIZE];
        let mut pos = 0;

        buf[pos..pos + 16].copy_from_slice(&self.message_id);
        pos += 16;
        buf[pos] = self.chunk_index;
        pos += 1;
        buf[pos] = self.total_chunks;
        pos += 1;
        buf[pos..pos + 8].copy_from_slice(&self.payload_length.to_be_bytes());
        pos += 8;
        buf[pos..pos + 16].copy_from_slice(&self.argon2_salt);
        pos += 16;
        buf[pos..pos + 12].copy_from_slice(&self.aes_nonce);
        pos += 12;
        buf[pos..pos + 32].copy_from_slice(&self.payload_hash);
        pos += 32;
        buf[pos] = self.bits_per_channel;
        pos += 1;
        buf[pos] = self.reserved;

        buf
    }

    /// Deserializes a [`ChunkHeader`] from `data`.
    ///
    /// Returns [`StegoError::InvalidHeader`] if the slice is shorter than 88 bytes
    /// or if any field fails validation.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(StegoError::InvalidHeader);
        }

        let mut pos = 0;

        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        let chunk_index = data[pos];
        pos += 1;
        let total_chunks = data[pos];
        pos += 1;

        let payload_length = u64::from_be_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| StegoError::InvalidHeader)?,
        );
        pos += 8;

        let mut argon2_salt = [0u8; 16];
        argon2_salt.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        let mut aes_nonce = [0u8; 12];
        aes_nonce.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;

        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let bits_per_channel = data[pos];
        pos += 1;
        let reserved = data[pos];

        // Validate fields
        if total_chunks == 0 {
            return Err(StegoError::InvalidHeader);
        }
        if chunk_index >= total_chunks {
            return Err(StegoError::InvalidHeader);
        }
        if bits_per_channel == 0 || bits_per_channel > 8 {
            return Err(StegoError::InvalidHeader);
        }
        if reserved != 0 {
            return Err(StegoError::InvalidHeader);
        }

        Ok(Self {
            message_id,
            chunk_index,
            total_chunks,
            payload_length,
            argon2_salt,
            aes_nonce,
            payload_hash,
            bits_per_channel,
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> ChunkHeader {
        ChunkHeader {
            message_id: [1u8; 16],
            chunk_index: 0,
            total_chunks: 1,
            payload_length: 1234,
            argon2_salt: [2u8; 16],
            aes_nonce: [3u8; 12],
            payload_hash: [4u8; 32],
            bits_per_channel: 2,
            reserved: 0,
        }
    }

    #[test]
    fn size_is_88() {
        assert_eq!(ChunkHeader::SIZE, 88);
    }

    #[test]
    fn roundtrip() {
        let h = sample_header();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 88);
        let h2 = ChunkHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn from_bytes_short_returns_invalid_header() {
        let err = ChunkHeader::from_bytes(&[0u8; 87]).unwrap_err();
        assert!(matches!(err, StegoError::InvalidHeader));
    }

    #[test]
    fn from_bytes_88_zeroes_fails_validation() {
        // total_chunks == 0 → InvalidHeader
        let err = ChunkHeader::from_bytes(&[0u8; 88]).unwrap_err();
        assert!(matches!(err, StegoError::InvalidHeader));
    }

    #[test]
    fn from_bytes_valid_88_bytes_succeeds() {
        // Build a valid 88-byte buffer manually
        let h = sample_header();
        let bytes = h.to_bytes();
        assert!(ChunkHeader::from_bytes(&bytes).is_ok());
    }
}
