/// AES-256-GCM encryption and decryption.
pub mod cipher;
/// SHA-256 hashing.
pub mod hash;
/// Argon2id key derivation and HKDF per-message key expansion.
pub mod kdf;

pub use cipher::{decrypt, encrypt};
pub use hash::sha256;
pub use kdf::{derive_base_key, derive_message_key};
