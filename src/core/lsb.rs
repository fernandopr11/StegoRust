use image::RgbImage;

use crate::error::{Result, StegoError};

// ---------------------------------------------------------------------------
// LsbWriter
// ---------------------------------------------------------------------------

/// Writes bytes into the LSBs of an [`RgbImage`] using MSB-first bit ordering.
///
/// Each RGB channel contributes `bpc` LSBs. Channels are visited in row-major
/// R→G→B order. Alpha channels are never touched.
pub struct LsbWriter {
    img: RgbImage,
    /// Current channel index (0 = first channel of first pixel, etc.).
    channel_idx: usize,
    /// Current bit offset within the current `bpc`-wide LSB slot (0 = LSB of the slot).
    bit_in_slot: u8,
}

impl LsbWriter {
    /// Creates a new writer wrapping `img`.
    pub fn new(img: RgbImage) -> Self {
        Self {
            img,
            channel_idx: 0,
            bit_in_slot: 0,
        }
    }

    /// Creates a new writer starting at a specific channel index.
    ///
    /// Used by the multi-message encoder to append after existing data.
    pub fn new_at(img: RgbImage, channel_idx: usize) -> Self {
        Self {
            img,
            channel_idx,
            bit_in_slot: 0,
        }
    }

    /// Writes `data` bytes MSB-first into the image at `bpc` bits per channel.
    ///
    /// Returns [`StegoError::InsufficientCapacity`] if the image runs out of space.
    pub fn write_bits(&mut self, data: &[u8], bpc: u8) -> Result<()> {
        let total_bits = data.len() * 8;
        let total_channels = self.img.width() as usize * self.img.height() as usize * 3;

        // Check up-front capacity
        let bits_available = (total_channels - self.channel_idx) * bpc as usize;
        if bits_available < total_bits {
            return Err(StegoError::InsufficientCapacity {
                needed: data.len(),
                available: bits_available / 8,
            });
        }

        let width = self.img.width() as usize;
        for k in 0..total_bits {
            let src_byte = k / 8;
            let src_bit_pos = 7 - (k % 8); // MSB first
            let src_bit = (data[src_byte] >> src_bit_pos) & 1;

            // Locate channel byte in the raw image buffer
            let ch = self.channel_idx;
            let pixel_idx = ch / 3;
            let channel_in_pixel = ch % 3;
            let px = pixel_idx % width;
            let py = pixel_idx / width;
            let pixel = self.img.get_pixel_mut(px as u32, py as u32);

            // Write src_bit into bit_in_slot of the bpc-wide slot
            let slot = self.bit_in_slot;
            let mask = 1u8 << slot;
            pixel[channel_in_pixel] = (pixel[channel_in_pixel] & !mask) | (src_bit << slot);

            // Advance bit/channel cursor
            if self.bit_in_slot + 1 < bpc {
                self.bit_in_slot += 1;
            } else {
                self.bit_in_slot = 0;
                self.channel_idx += 1;
            }
        }

        Ok(())
    }

    /// Consumes the writer and returns the modified image.
    pub fn into_image(self) -> RgbImage {
        self.img
    }
}

// ---------------------------------------------------------------------------
// LsbReader
// ---------------------------------------------------------------------------

/// Reads bytes from the LSBs of an [`RgbImage`] using MSB-first bit ordering.
pub struct LsbReader<'a> {
    img: &'a RgbImage,
    channel_idx: usize,
    bit_in_slot: u8,
}

impl<'a> LsbReader<'a> {
    /// Creates a new reader for `img`, starting at channel index 0.
    pub fn new(img: &'a RgbImage) -> Self {
        Self {
            img,
            channel_idx: 0,
            bit_in_slot: 0,
        }
    }

    /// Creates a new reader starting at a specific channel index.
    ///
    /// Used by the decoder to skip past the header channels and read payload
    /// at a different `bpc` than the header.
    pub fn new_at(img: &'a RgbImage, channel_idx: usize) -> Self {
        Self {
            img,
            channel_idx,
            bit_in_slot: 0,
        }
    }

    /// Reads `byte_count` bytes MSB-first from the image at `bpc` bits per channel.
    ///
    /// Returns [`StegoError::InsufficientCapacity`] if there are not enough bits.
    pub fn read_bits(&mut self, byte_count: usize, bpc: u8) -> Result<Vec<u8>> {
        let total_bits = byte_count * 8;
        let total_channels = self.img.width() as usize * self.img.height() as usize * 3;
        let bits_available = (total_channels - self.channel_idx) * bpc as usize;

        if bits_available < total_bits {
            return Err(StegoError::InsufficientCapacity {
                needed: byte_count,
                available: bits_available / 8,
            });
        }

        let width = self.img.width() as usize;
        let mut out = vec![0u8; byte_count];

        for k in 0..total_bits {
            let ch = self.channel_idx;
            let pixel_idx = ch / 3;
            let channel_in_pixel = ch % 3;
            let px = pixel_idx % width;
            let py = pixel_idx / width;
            let pixel = self.img.get_pixel(px as u32, py as u32);

            let slot = self.bit_in_slot;
            let bit = (pixel[channel_in_pixel] >> slot) & 1;

            let dst_byte = k / 8;
            let dst_bit_pos = 7 - (k % 8); // MSB first
            out[dst_byte] |= bit << dst_bit_pos;

            if self.bit_in_slot + 1 < bpc {
                self.bit_in_slot += 1;
            } else {
                self.bit_in_slot = 0;
                self.channel_idx += 1;
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::RgbImage;

    fn blank(w: u32, h: u32) -> RgbImage {
        RgbImage::new(w, h)
    }

    #[test]
    fn writer_constructs_on_1x1() {
        let _w = LsbWriter::new(blank(1, 1));
    }

    #[test]
    fn write_0xff_bpc1_pixel_channels() {
        // 0xFF = 0b11111111 → first 8 bits all 1
        // At bpc=1 each channel gets 1 bit; 8 bits → 8 channels → 2 full pixels + 2 channels of 3rd pixel
        let img = blank(4, 1); // 4 pixels, 3 ch each = 12 channels
        let mut w = LsbWriter::new(img);
        w.write_bits(&[0xFF], 1).unwrap();
        let img = w.into_image();

        // Pixels 0 and 1 (channels 0-5) all have LSB=1
        for px in 0..2u32 {
            let p = img.get_pixel(px, 0);
            for ch in 0..3 {
                assert_eq!(p[ch] & 1, 1, "px={px} ch={ch}");
            }
        }
        // Pixel 2 channels 0 and 1 have LSB=1; channel 2 has LSB=0
        let p2 = img.get_pixel(2, 0);
        assert_eq!(p2[0] & 1, 1);
        assert_eq!(p2[1] & 1, 1);
        assert_eq!(p2[2] & 1, 0);
    }

    #[test]
    fn write_into_image_preserves_dimensions() {
        let img = blank(10, 10);
        let mut w = LsbWriter::new(img);
        w.write_bits(&[0xAB, 0xCD], 1).unwrap();
        let out = w.into_image();
        assert_eq!(out.width(), 10);
        assert_eq!(out.height(), 10);
    }

    #[test]
    fn roundtrip_bpc1() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let img = blank(10, 10);
        let mut w = LsbWriter::new(img);
        w.write_bits(&data, 1).unwrap();
        let img = w.into_image();

        let mut r = LsbReader::new(&img);
        let recovered = r.read_bits(4, 1).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn roundtrip_bpc4() {
        let data: Vec<u8> = (0..16).collect();
        let img = blank(20, 20);
        let mut w = LsbWriter::new(img);
        w.write_bits(&data, 4).unwrap();
        let img = w.into_image();

        let mut r = LsbReader::new(&img);
        let recovered = r.read_bits(16, 4).unwrap();
        assert_eq!(recovered, data);
    }
}
