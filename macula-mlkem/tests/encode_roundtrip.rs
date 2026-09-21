//! Structural checks on encoding and compression, ahead of any vector, so
//! a later ACVP red localises here rather than to sampling or the KEM.
use macula_mlkem::encode::{byte_decode, byte_encode, compress, decompress};
use macula_mlkem::poly::Q;

fn lcg(seed: &mut u64, bound: u32) -> i16 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    ((*seed >> 33) % bound as u64) as i16
}

/// ByteEncode and ByteDecode must be exact inverses at every width
/// ML-KEM uses.
#[test]
fn encode_then_decode_is_the_identity() {
    let mut seed = 11u64;
    for d in [1usize, 4, 5, 10, 11, 12] {
        let bound = if d == 12 { Q as u32 } else { 1u32 << d };
        for _ in 0..16 {
            let mut f = [0i16; 256];
            for c in f.iter_mut() {
                *c = lcg(&mut seed, bound);
            }
            let bytes = byte_encode(d, &f);
            assert_eq!(bytes.len(), 32 * d, "ByteEncode_{d} length");
            assert_eq!(byte_decode(d, &bytes), f, "d = {d}");
        }
    }
}

/// Compression is lossy by design, so the round trip must land within
/// the error bound FIPS 203 states rather than return the input.
#[test]
fn decompress_of_compress_stays_within_the_stated_error_bound() {
    for d in [1usize, 4, 5, 10, 11] {
        let bound = (Q as f64 / (1u32 << (d + 1)) as f64).round() as i32;
        for x in 0..Q as i16 {
            let back = decompress(d, compress(d, x)) as i32;
            let mut err = (back - x as i32).abs();
            // The ring wraps: an error of q-1 is an error of 1.
            if err > Q / 2 {
                err = Q - err;
            }
            assert!(
                err <= bound,
                "d = {d}, x = {x}: error {err} exceeds the bound {bound}"
            );
        }
    }
}

/// Compress_d must land in [0, 2^d).
#[test]
fn compress_lands_in_range() {
    for d in [1usize, 4, 5, 10, 11] {
        for x in 0..Q as i16 {
            let c = compress(d, x);
            assert!(
                c >= 0 && (c as u32) < (1u32 << d),
                "d = {d}, x = {x} gave {c}"
            );
        }
    }
}
