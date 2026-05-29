/// LSB capacity calculation.
pub mod capacity;
/// Stego decoder.
pub mod decoder;
/// Stego encoder.
pub mod encoder;
/// LSB bit-level reader and writer.
pub mod lsb;

pub use capacity::image_capacity;
pub use decoder::StegoDecoder;
pub use encoder::{scan_used_channels, StegoEncoder};
