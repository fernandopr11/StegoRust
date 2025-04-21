// src/crypto.rs

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use sha2::{Sha256, Digest};

pub fn hash_message(data: &[u8]) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash8 = [0u8; 8];
    hash8.copy_from_slice(&result[..8]);
    hash8
}

pub fn encrypt_message(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, data) {
        Ok(ciphertext) => {
            let mut result = Vec::from(nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        },
        Err(_) => Err("Error al encriptar mensaje".to_string())
    }
}

pub fn decrypt_message(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Datos muy cortos para contener nonce".to_string());
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Error al desencriptar mensaje".to_string())
}

fn derive_key(password: &str) -> Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}
