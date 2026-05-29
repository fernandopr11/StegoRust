use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use crate::error::{Result, StegoError};

/// Length of the AES-256-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Encrypts `plaintext` with AES-256-GCM.
///
/// `aad` (the serialized [`ChunkHeader`]) is authenticated but not encrypted.
/// The returned ciphertext includes the 16-byte GCM tag appended at the end.
///
/// [`ChunkHeader`]: crate::formats::ChunkHeader
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StegoError::Cipher(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| StegoError::Cipher(e.to_string()))
}

/// Decrypts `ciphertext` with AES-256-GCM.
///
/// Returns [`StegoError::AuthenticationFailed`] if the GCM tag does not verify.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StegoError::Cipher(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| StegoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 12] = [0x24u8; 12];
    const AAD: &[u8] = b"header-bytes";

    #[test]
    fn encrypt_ciphertext_length() {
        let pt = b"hello world";
        let ct = encrypt(&KEY, &NONCE, pt, AAD).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let pt = b"secret payload";
        let ct = encrypt(&KEY, &NONCE, pt, AAD).unwrap();
        let recovered = decrypt(&KEY, &NONCE, &ct, AAD).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn decrypt_tampered_returns_auth_failed() {
        let pt = b"secret payload";
        let mut ct = encrypt(&KEY, &NONCE, pt, AAD).unwrap();
        ct[0] ^= 0xFF;
        let err = decrypt(&KEY, &NONCE, &ct, AAD).unwrap_err();
        assert!(matches!(err, StegoError::AuthenticationFailed));
    }
}
