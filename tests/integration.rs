/// Integration tests for StegoRust v0.2.0.
///
/// Each test maps to a scenario from spec.md (T-01 … T-19).
/// All tests use the public API only — no access to internals.
use image::RgbImage;
use stego_rust::{image_capacity, ChunkHeader, StegoDecoder, StegoEncoder, StegoError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn blank(w: u32, h: u32) -> RgbImage {
    RgbImage::new(w, h)
}

fn encoder(bpc: u8) -> stego_rust::StegoEncoder {
    StegoEncoder::builder()
        .bits_per_channel(bpc)
        .build()
        .expect("valid encoder")
}

fn decode(images: Vec<RgbImage>, password: &[u8]) -> Result<Vec<u8>, StegoError> {
    StegoDecoder::builder().build().decode(images, password)
}

// ---------------------------------------------------------------------------
// T-01: Single image, single chunk, 1 bit/channel
// ---------------------------------------------------------------------------

#[test]
fn t01_single_image_single_chunk_bpc1() {
    let cover = vec![blank(100, 100)];
    let msg = b"hello stegorust v2!!hello stegorust";
    let stego = encoder(1).encode(cover, msg, b"password").unwrap();

    assert_eq!(stego.len(), 1);
    assert_eq!(stego[0].width(), 100);
    assert_eq!(stego[0].height(), 100);

    // Read back the header region from the first image (bpc=1, 88 bytes)
    let img = &stego[0];
    let mut header_bits = vec![0u8; 88];
    for (byte_idx, byte) in header_bits.iter_mut().enumerate() {
        let mut val = 0u8;
        for bit in 0..8 {
            let ch_idx = byte_idx * 8 + bit;
            let px = ch_idx / 3 % img.width() as usize;
            let py = ch_idx / 3 / img.width() as usize;
            let ch = ch_idx % 3;
            let b = img.get_pixel(px as u32, py as u32)[ch] & 1;
            val = (val << 1) | b;
        }
        *byte = val;
    }
    let header = ChunkHeader::from_bytes(&header_bits).expect("valid header");
    assert_eq!(header.chunk_index, 0);
    assert_eq!(header.total_chunks, 1);
    assert_eq!(header.bits_per_channel, 1);
}

// ---------------------------------------------------------------------------
// T-02: bits_per_channel = 8 (full channel replacement)
// ---------------------------------------------------------------------------

#[test]
fn t02_bpc8_encode() {
    let cover = vec![blank(20, 20)]; // 20*20*3*8/8 = 1200 bytes capacity
    let msg = vec![0xABu8; 200];
    let result = encoder(8).encode(cover, &msg, b"pw");
    assert!(result.is_ok(), "bpc=8 encode failed: {:?}", result.err());
    let stego = result.unwrap();
    assert_eq!(stego.len(), 1);
}

// ---------------------------------------------------------------------------
// T-03 & T-04: Invalid bits_per_channel
// ---------------------------------------------------------------------------

#[test]
fn t03_invalid_bpc_zero() {
    let err = StegoEncoder::builder()
        .bits_per_channel(0)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, StegoError::InvalidBitsPerChannel(0)),
        "expected InvalidBitsPerChannel(0), got {err:?}"
    );
}

#[test]
fn t04_invalid_bpc_nine() {
    let err = StegoEncoder::builder()
        .bits_per_channel(9)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, StegoError::InvalidBitsPerChannel(9)),
        "expected InvalidBitsPerChannel(9), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-05: InsufficientCapacity
// ---------------------------------------------------------------------------

#[test]
fn t05_insufficient_capacity() {
    let cover = vec![blank(10, 10)]; // 10*10*3/8 = 37 bytes at bpc=1
    let msg = vec![0u8; 1000];
    let err = encoder(1).encode(cover, &msg, b"pw").unwrap_err();
    assert!(
        matches!(err, StegoError::InsufficientCapacity { .. }),
        "expected InsufficientCapacity, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-06: Salt and nonce are unique across two encodes
// ---------------------------------------------------------------------------

#[test]
fn t06_salt_and_nonce_unique_per_encode() {
    let msg = b"same message";
    let pw = b"same password";

    let stego1 = encoder(1)
        .encode(vec![blank(100, 100)], msg, pw)
        .unwrap();
    let stego2 = encoder(1)
        .encode(vec![blank(100, 100)], msg, pw)
        .unwrap();

    // Extract headers from both images
    let read_header = |img: &RgbImage| {
        let mut buf = vec![0u8; 88];
        for (byte_idx, byte) in buf.iter_mut().enumerate() {
            let mut val = 0u8;
            for bit in 0..8usize {
                let ch_idx = byte_idx * 8 + bit;
                let px = ch_idx / 3 % img.width() as usize;
                let py = ch_idx / 3 / img.width() as usize;
                let ch = ch_idx % 3;
                let b = img.get_pixel(px as u32, py as u32)[ch] & 1;
                val = (val << 1) | b;
            }
            *byte = val;
        }
        ChunkHeader::from_bytes(&buf).expect("valid header")
    };

    let h1 = read_header(&stego1[0]);
    let h2 = read_header(&stego2[0]);

    assert_ne!(h1.argon2_salt, h2.argon2_salt, "salts must differ");
    assert_ne!(h1.aes_nonce, h2.aes_nonce, "nonces must differ");
}

// ---------------------------------------------------------------------------
// T-07: payload_hash matches SHA-256 of plaintext
// ---------------------------------------------------------------------------

#[test]
fn t07_payload_hash_matches_sha256_of_plaintext() {
    use sha2::{Digest, Sha256};

    let msg = b"verify my hash please";
    let stego = encoder(1)
        .encode(vec![blank(100, 100)], msg, b"pw")
        .unwrap();

    let img = &stego[0];
    let mut buf = vec![0u8; 88];
    for (byte_idx, byte) in buf.iter_mut().enumerate() {
        let mut val = 0u8;
        for bit in 0..8usize {
            let ch_idx = byte_idx * 8 + bit;
            let px = ch_idx / 3 % img.width() as usize;
            let py = ch_idx / 3 / img.width() as usize;
            let ch = ch_idx % 3;
            let b = img.get_pixel(px as u32, py as u32)[ch] & 1;
            val = (val << 1) | b;
        }
        *byte = val;
    }
    let header = ChunkHeader::from_bytes(&buf).unwrap();

    let expected: [u8; 32] = Sha256::digest(msg).into();
    assert_eq!(header.payload_hash, expected);
}

// ---------------------------------------------------------------------------
// T-08: Encode → decode round-trip (bpc=1)
// ---------------------------------------------------------------------------

#[test]
fn t08_encode_decode_roundtrip_bpc1() {
    let msg = b"round-trip test message for stegorust!";
    let stego = encoder(1)
        .encode(vec![blank(100, 100)], msg, b"secret")
        .unwrap();
    let recovered = decode(stego, b"secret").unwrap();
    assert_eq!(recovered, msg);
}

// ---------------------------------------------------------------------------
// T-09: Encode → decode round-trip (bpc=4)
// ---------------------------------------------------------------------------

#[test]
fn t09_encode_decode_roundtrip_bpc4() {
    let msg = b"testing four bits per channel encoding path";
    let stego = encoder(4)
        .encode(vec![blank(100, 100)], msg, b"pw4")
        .unwrap();
    let recovered = decode(stego, b"pw4").unwrap();
    assert_eq!(recovered, msg);
}

// ---------------------------------------------------------------------------
// T-10: Wrong password returns AuthenticationFailed
// ---------------------------------------------------------------------------

#[test]
fn t10_wrong_password_returns_auth_failed() {
    let stego = encoder(1)
        .encode(vec![blank(100, 100)], b"secret message", b"correct")
        .unwrap();
    let err = decode(stego, b"wrong").unwrap_err();
    assert!(
        matches!(err, StegoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-11: Tampered payload returns AuthenticationFailed
// ---------------------------------------------------------------------------

#[test]
fn t11_tampered_payload_returns_auth_failed() {
    let mut stego = encoder(1)
        .encode(vec![blank(100, 100)], b"tamper me", b"pw")
        .unwrap();

    // Flip a bit in the payload region (past the 88-byte header)
    // Header occupies 88*8 = 704 channels at bpc=1.
    // Flip bit in channel 704+8 (first byte of payload).
    let flip_ch = 704 + 8;
    let img = &mut stego[0];
    let px = (flip_ch / 3) % img.width() as usize;
    let py = (flip_ch / 3) / img.width() as usize;
    let ch = flip_ch % 3;
    let pixel = img.get_pixel_mut(px as u32, py as u32);
    pixel[ch] ^= 1;

    let err = decode(stego, b"pw").unwrap_err();
    assert!(
        matches!(err, StegoError::AuthenticationFailed),
        "expected AuthenticationFailed after payload tamper, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-12: Tampered header returns InvalidHeader or AuthenticationFailed
// ---------------------------------------------------------------------------

#[test]
fn t12_tampered_header_returns_error() {
    let mut stego = encoder(1)
        .encode(vec![blank(100, 100)], b"header tamper", b"pw")
        .unwrap();

    // Flip a bit in channel 8 (second byte of header = chunk_index)
    let img = &mut stego[0];
    let flip_ch = 8;
    let px = (flip_ch / 3) % img.width() as usize;
    let py = (flip_ch / 3) / img.width() as usize;
    let ch = flip_ch % 3;
    let pixel = img.get_pixel_mut(px as u32, py as u32);
    pixel[ch] ^= 1;

    let err = decode(stego, b"pw").unwrap_err();
    assert!(
        matches!(
            err,
            StegoError::InvalidHeader | StegoError::AuthenticationFailed
        ),
        "expected InvalidHeader or AuthenticationFailed, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-14: Plain (unencoded) image returns error (no valid header)
// ---------------------------------------------------------------------------

#[test]
fn t14_plain_image_returns_invalid_header() {
    let plain = vec![blank(50, 50)];
    let err = decode(plain, b"pw").unwrap_err();
    assert!(
        matches!(
            err,
            StegoError::InvalidHeader | StegoError::AuthenticationFailed
        ),
        "expected InvalidHeader or AuthenticationFailed on plain image, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-15: Spanning — message requiring 3 chunks across 3 images
// ---------------------------------------------------------------------------

#[test]
fn t15_spanning_3_chunks_across_3_images() {
    // 50×50 at bpc=1: capacity = 50*50*3/8 = 937 bytes
    // header = 88 bytes, payload cap ≈ 849 bytes net (minus 16 GCM tag = 833 plaintext)
    // 3 images → ~2499 bytes plaintext capacity
    let covers: Vec<RgbImage> = (0..3).map(|_| blank(50, 50)).collect();
    let msg = vec![0xAAu8; 2000];

    let stego = encoder(1).encode(covers, &msg, b"span-pw").unwrap();
    assert_eq!(stego.len(), 3, "expected 3 output images");

    // Verify headers: all share message_id, chunk indices 0/1/2, total_chunks=3
    let read_header = |img: &RgbImage| {
        let mut buf = vec![0u8; 88];
        for (byte_idx, byte) in buf.iter_mut().enumerate() {
            let mut val = 0u8;
            for bit in 0..8usize {
                let ch_idx = byte_idx * 8 + bit;
                let px = ch_idx / 3 % img.width() as usize;
                let py = ch_idx / 3 / img.width() as usize;
                let ch = ch_idx % 3;
                let b = img.get_pixel(px as u32, py as u32)[ch] & 1;
                val = (val << 1) | b;
            }
            *byte = val;
        }
        ChunkHeader::from_bytes(&buf).expect("valid header")
    };

    let headers: Vec<ChunkHeader> = stego.iter().map(read_header).collect();

    // All share the same message_id
    assert!(headers.windows(2).all(|w| w[0].message_id == w[1].message_id));
    // total_chunks = 3 in all headers
    assert!(headers.iter().all(|h| h.total_chunks == 3));
    // chunk indices are {0, 1, 2}
    let mut indices: Vec<u8> = headers.iter().map(|h| h.chunk_index).collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1, 2]);
}

// ---------------------------------------------------------------------------
// T-16: Decode spanning message
// ---------------------------------------------------------------------------

#[test]
fn t16_decode_spanning_message() {
    let covers: Vec<RgbImage> = (0..3).map(|_| blank(50, 50)).collect();
    let msg = vec![0xBBu8; 2000];

    let stego = encoder(1).encode(covers, &msg, b"span-pw").unwrap();
    let recovered = decode(stego, b"span-pw").unwrap();
    assert_eq!(recovered, msg);
}

// ---------------------------------------------------------------------------
// T-17: Missing chunk returns MissingChunks
// ---------------------------------------------------------------------------

#[test]
fn t17_missing_chunk_returns_error() {
    let covers: Vec<RgbImage> = (0..3).map(|_| blank(50, 50)).collect();
    let msg = vec![0xCCu8; 2000];

    let mut stego = encoder(1).encode(covers, &msg, b"pw").unwrap();
    // Drop the last image (chunk 2)
    stego.pop();

    let err = decode(stego, b"pw").unwrap_err();
    assert!(
        matches!(err, StegoError::MissingChunks { .. }),
        "expected MissingChunks, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T-19: Capacity formula correctness
// ---------------------------------------------------------------------------

#[test]
fn t19_capacity_formula() {
    // floor(W * H * 3 * bpc / 8)
    assert_eq!(image_capacity(&blank(100, 100), 1).unwrap(), 3750);
    assert_eq!(image_capacity(&blank(100, 100), 2).unwrap(), 7500);
    assert_eq!(image_capacity(&blank(100, 100), 4).unwrap(), 15000);
    assert_eq!(image_capacity(&blank(100, 100), 8).unwrap(), 30000);
    assert_eq!(image_capacity(&blank(1920, 1080), 1).unwrap(), 777600);
}

// ---------------------------------------------------------------------------
// Extra: large binary message round-trip
// ---------------------------------------------------------------------------

#[test]
fn extra_large_binary_roundtrip() {
    let msg: Vec<u8> = (0u16..512).map(|i| (i % 256) as u8).collect();
    let stego = encoder(2)
        .encode(vec![blank(200, 200)], &msg, b"binary-pw")
        .unwrap();
    let recovered = decode(stego, b"binary-pw").unwrap();
    assert_eq!(recovered, msg);
}

// ---------------------------------------------------------------------------
// Extra: empty message round-trip
// ---------------------------------------------------------------------------

#[test]
fn extra_empty_message_roundtrip() {
    let stego = encoder(1)
        .encode(vec![blank(100, 100)], b"", b"pw")
        .unwrap();
    let recovered = decode(stego, b"pw").unwrap();
    assert_eq!(recovered, b"");
}
