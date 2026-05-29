# StegoRust

[![Crates.io](https://img.shields.io/crates/v/stego_rust.svg)](https://crates.io/crates/stego_rust)
[![Docs.rs](https://docs.rs/stego_rust/badge.svg)](https://docs.rs/stego_rust)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A Rust library for hiding encrypted messages inside PNG images using **LSB (Least Significant Bit) steganography**, backed by AES-256-GCM authenticated encryption and Argon2id key derivation.

---

## Features

- **AES-256-GCM encryption** — every chunk is individually encrypted with a unique nonce
- **Argon2id key derivation** — password-based key stretching (m=19 MiB, t=2, p=1) resistant to GPU and ASIC attacks
- **HKDF-SHA256 per-message keys** — each message gets its own derived AES key from the base key and a unique `message_id`
- **SHA-256 integrity check** — full plaintext hash stored in the header, verified after reassembly
- **Message spanning** — large messages auto-split across multiple images; each chunk is independent and self-describing
- **Configurable bit depth** — 1–8 bits per channel trades invisibility for capacity
- **No external index files** — all metadata embedded directly in image LSBs

---

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
stego_rust = "0.2"
```

### Encode a message

```rust
use stego_rust::core::encoder::StegoEncoder;
use image::DynamicImage;

// Load one or more cover images
let cover_images: Vec<DynamicImage> = vec![
    image::open("cover1.png")?,
    image::open("cover2.png")?,
];

let stego_images = StegoEncoder::builder()
    .bits_per_channel(1)   // 1–8; lower = more invisible, less capacity
    .build()?
    .encode(cover_images, b"secret message", b"my-password")?;

// Save the output images
for (i, img) in stego_images.iter().enumerate() {
    img.save(format!("stego_{}.png", i))?;
}
```

### Decode a message

```rust
use stego_rust::core::decoder::StegoDecoder;
use image::DynamicImage;

let stego_images: Vec<DynamicImage> = vec![
    image::open("stego_0.png")?,
];

let message = StegoDecoder::builder()
    .build()
    .decode(stego_images, b"my-password")?;

println!("{}", String::from_utf8(message)?);
```

---

## Security Model

StegoRust uses a layered cryptographic approach designed so that an attacker with access to the output images cannot recover the message without the password.

### Key Derivation

1. **Argon2id** derives a 32-byte base key from the password and a random 16-byte salt stored in the chunk header.
   Parameters: `m=19456 KiB`, `t=2`, `p=1` — expensive on commodity hardware, usable on embedded targets.

2. **HKDF-SHA256** derives a unique per-message AES key from the base key and the `message_id` (a random UUID generated at encode time).
   Two messages encoded with the same password cannot share key material.

### Encryption

Each chunk payload is encrypted with **AES-256-GCM**. The 88-byte `ChunkHeader` is passed as **AAD** (Additional Authenticated Data) — authenticated by the GCM tag but not encrypted, so the decoder can read routing metadata before decrypting.

### Integrity

A **SHA-256 hash of the full plaintext** is stored in every chunk header. After all chunks are reassembled the hash is re-verified, catching tampering or accidental corruption at the byte level.

### Threat model summary

| Attack | Defence |
|--------|---------|
| Pixel modification | AES-GCM tag verification fails |
| Chunk reordering / swapping | SHA-256 integrity check fails |
| Password brute-force | Argon2id (memory-hard, intentionally slow) |
| Key reuse across messages | HKDF per `message_id` — keys never repeat |

---

## Capacity Guide

Usable bytes per megapixel (1 MP = 1 000 000 pixels × 3 channels), after the 88-byte header is subtracted:

| Bits per channel | 1 MP image | 8 MP image | 12 MP image |
|-----------------|-----------|-----------|------------|
| 1               | ~342 KB   | ~2.7 MB   | ~4.1 MB    |
| 2               | ~685 KB   | ~5.5 MB   | ~8.2 MB    |
| 4               | ~1.4 MB   | ~11 MB    | ~16.8 MB   |
| 8               | ~2.9 MB   | ~22 MB    | ~34.3 MB   |

Use `bpc=1` for maximum stealth. Increase only when the message does not fit across the available images.

---

## Message Spanning

When a message is too large for a single image, `StegoEncoder` automatically splits it into chunks — one chunk per image. Each chunk carries:

- A shared `message_id` (UUID) identifying the original message
- Its `chunk_index` and `total_chunks` for reassembly ordering
- Its own Argon2id salt and AES nonce — independently decryptable

`StegoDecoder` collects all chunks, sorts them by `chunk_index`, verifies the SHA-256 integrity hash, and returns the reassembled plaintext. You must provide at least as many cover images as the encoder produces chunks; otherwise encoding returns an error.

---

## ChunkHeader Format

Each image stores an 88-byte self-describing header at `bpc=1` (independent of the configured bit depth for the payload):

```
message_id(16) | chunk_index(1) | total_chunks(1) | payload_length(8) |
argon2_salt(16) | aes_nonce(12) | payload_hash(32) | bits_per_channel(1) | reserved(1)
```

This design means a decoder only needs the image and the password — no sidecar files.

---

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
