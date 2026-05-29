use image::RgbImage;

use crate::error::{Result, StegoError};

/// Returns the number of bytes that can be hidden in `img` using `bpc` bits per channel.
///
/// The formula is `width × height × 3 × bpc / 8` (integer division).
/// Returns [`StegoError::InvalidBitsPerChannel`] if `bpc` is 0 or greater than 8.
pub fn image_capacity(img: &RgbImage, bpc: u8) -> Result<usize> {
    if bpc == 0 || bpc > 8 {
        return Err(StegoError::InvalidBitsPerChannel(bpc));
    }
    let pixels = img.width() as usize * img.height() as usize;
    Ok(pixels * 3 * bpc as usize / 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::RgbImage;

    fn blank(w: u32, h: u32) -> RgbImage {
        RgbImage::new(w, h)
    }

    #[test]
    fn capacity_100x100_bpc1() {
        // 100*100*3*1/8 = 3750
        assert_eq!(image_capacity(&blank(100, 100), 1).unwrap(), 3750);
    }

    #[test]
    fn capacity_bpc0_invalid() {
        let err = image_capacity(&blank(100, 100), 0).unwrap_err();
        assert!(matches!(err, StegoError::InvalidBitsPerChannel(0)));
    }

    #[test]
    fn capacity_bpc9_invalid() {
        let err = image_capacity(&blank(100, 100), 9).unwrap_err();
        assert!(matches!(err, StegoError::InvalidBitsPerChannel(9)));
    }
}
