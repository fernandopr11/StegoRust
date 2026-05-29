/// Errors returned by StegoRust operations.
#[derive(Debug, thiserror::Error)]
pub enum StegoError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An image loading or saving error occurred.
    #[error("image error: {0}")]
    Image(#[from] image::ImageError),

    /// Invalid configuration parameter.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The header bytes are corrupt or the image is not a StegoRust carrier.
    #[error("invalid header (corrupt or not a StegoRust image)")]
    InvalidHeader,

    /// Decryption failed — wrong password or tampered image.
    #[error("authentication failed (wrong password or tampered image)")]
    AuthenticationFailed,

    /// The reassembled payload hash does not match the stored hash.
    #[error("integrity check failed: reassembled payload hash mismatch")]
    IntegrityCheckFailed,

    /// Not enough pixel capacity in the cover images for the message.
    #[error("insufficient capacity: need {needed} bytes, available {available}")]
    InsufficientCapacity {
        /// Required bytes.
        needed: usize,
        /// Available bytes.
        available: usize,
    },

    /// The provided images do not supply all required chunks.
    #[error("missing chunks: found {found}, expected {expected}")]
    MissingChunks {
        /// Number of chunks found.
        found: usize,
        /// Number of chunks expected.
        expected: usize,
    },

    /// A duplicate chunk index was encountered.
    #[error("duplicate chunk index {0}")]
    DuplicateChunk(u8),

    /// Images from different messages were mixed together.
    #[error("multiple message_ids in the provided image set")]
    MixedMessages,

    /// `bits_per_channel` was outside the valid range 1–8.
    #[error("bits_per_channel must be 1..=8, got {0}")]
    InvalidBitsPerChannel(u8),

    /// Key derivation (Argon2 / HKDF) error.
    #[error("KDF error: {0}")]
    Kdf(String),

    /// Cipher (AES-GCM) error.
    #[error("cipher error: {0}")]
    Cipher(String),

}

/// Convenience alias for `Result<T, StegoError>`.
pub type Result<T> = std::result::Result<T, StegoError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn error_variants_display_non_empty() {
        let variants: Vec<Box<dyn Error>> = vec![
            Box::new(StegoError::InvalidHeader),
            Box::new(StegoError::AuthenticationFailed),
            Box::new(StegoError::IntegrityCheckFailed),
            Box::new(StegoError::InsufficientCapacity {
                needed: 10,
                available: 5,
            }),
            Box::new(StegoError::MissingChunks {
                found: 1,
                expected: 3,
            }),
            Box::new(StegoError::DuplicateChunk(2)),
            Box::new(StegoError::MixedMessages),
            Box::new(StegoError::InvalidBitsPerChannel(9)),
            Box::new(StegoError::Kdf("test".into())),
            Box::new(StegoError::Cipher("test".into())),
            Box::new(StegoError::InvalidConfig("test".into())),
        ];
        for e in variants {
            assert!(!e.to_string().is_empty(), "empty Display for {e:?}");
        }
    }
}
