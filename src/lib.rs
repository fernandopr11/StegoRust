//! StegoRust — image steganography with AES-256-GCM and Argon2id.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use stego_rust::{StegoEncoder, StegoDecoder};
//!
//! // Encode
//! let images = vec![image::RgbImage::new(200, 200)];
//! let stego = StegoEncoder::builder()
//!     .bits_per_channel(1)
//!     .build()?
//!     .encode(images, b"secret message", b"hunter2")?;
//!
//! // Decode
//! let recovered = StegoDecoder::builder()
//!     .build()
//!     .decode(stego, b"hunter2")?;
//!
//! assert_eq!(recovered, b"secret message");
//! # Ok::<(), stego_rust::StegoError>(())
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod core;
mod crypto;
mod error;
mod formats;
mod utils;

pub use core::{image_capacity, scan_used_channels, StegoDecoder, StegoEncoder};

/// Returns the number of bytes already used in `img` by embedded messages.
pub fn scan_used_bytes(img: &image::RgbImage) -> usize {
    // channels are bits, divide by 8 to get bytes (bpc=1 → 1 channel = 1 bit)
    scan_used_channels(img) / 8
}
pub use error::{Result, StegoError};
pub use formats::{ChunkHeader, CHUNK_HEADER_SIZE};
