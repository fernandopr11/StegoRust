use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Result, StegoError};

/// Length of an Argon2 salt in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the derived key in bytes.
pub const KEY_LEN: usize = 32;

/// Production Argon2id cost parameters (OWASP minimum: m=19 MiB, t=2, p=1).
#[cfg(not(test))]
const M_COST: u32 = 19 * 1024;
#[cfg(not(test))]
const T_COST: u32 = 2;

/// Reduced cost parameters used in tests to keep the suite fast.
#[cfg(test)]
const M_COST: u32 = 8;
#[cfg(test)]
const T_COST: u32 = 1;

const P_COST: u32 = 1;

/// Derives a 32-byte base key from `password` and `salt` using Argon2id.
///
/// Use [`derive_message_key`] to produce a per-message AES key from the result.
pub fn derive_base_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_LEN))
        .map_err(|e| StegoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| StegoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Derives a per-message AES key from `base_key` and `message_id` using HKDF-SHA256.
///
/// The `info` field is `b"stegorust-msg-v2"` concatenated with `message_id`,
/// ensuring each logical message gets a cryptographically independent key.
pub fn derive_message_key(
    base_key: &[u8; KEY_LEN],
    message_id: &[u8; 16],
) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, base_key.as_slice());
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"stegorust-msg-v2");
    info.extend_from_slice(message_id);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .map_err(|e| StegoError::Kdf(e.to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT_A: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const SALT_B: [u8; 16] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    #[test]
    fn derive_base_key_deterministic() {
        let k1 = derive_base_key(b"password", &SALT_A).unwrap();
        let k2 = derive_base_key(b"password", &SALT_A).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_base_key_salt_sensitivity() {
        let k1 = derive_base_key(b"password", &SALT_A).unwrap();
        let k2 = derive_base_key(b"password", &SALT_B).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_message_key_deterministic() {
        let base = derive_base_key(b"pw", &SALT_A).unwrap();
        let id = [0u8; 16];
        let k1 = derive_message_key(&base, &id).unwrap();
        let k2 = derive_message_key(&base, &id).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_message_key_id_sensitivity() {
        let base = derive_base_key(b"pw", &SALT_A).unwrap();
        let id_a = [0u8; 16];
        let id_b = [1u8; 16];
        let k1 = derive_message_key(&base, &id_a).unwrap();
        let k2 = derive_message_key(&base, &id_b).unwrap();
        assert_ne!(k1, k2);
        // Output must differ from the base key input
        assert_ne!(k1, base);
    }
}
