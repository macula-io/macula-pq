//! Byte encoding and compression, FIPS 203 sections 4.2.1 and 4.2.2.
//!
//! ⚠ Every function here runs on secret data at least some of the time,
//! so there are no secret-dependent branches or indices: the bit packing
//! is driven by `d`, which is a public parameter, and compression uses
//! arithmetic rounding rather than comparison. That is a statement about
//! the code's shape and NOT a measurement; see the crate docs.

use crate::poly::{Poly, N, Q};

/// FIPS 203 Algorithm 5, ByteEncode_d: pack 256 `d`-bit integers into
/// `32 * d` bytes, little-endian across the bit stream.
pub fn byte_encode(d: usize, f: &Poly) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d];
    let mut bit = 0usize;
    for &coeff in f.iter() {
        let v = coeff as u32;
        for i in 0..d {
            let b = ((v >> i) & 1) as u8;
            out[bit / 8] |= b << (bit % 8);
            bit += 1;
        }
    }
    out
}

/// FIPS 203 Algorithm 6, ByteDecode_d.
///
/// For `d = 12` the values are reduced mod `q`, as the specification
/// requires: a decoded 12-bit value can exceed `q` and must not be
/// carried as an out-of-range coefficient.
pub fn byte_decode(d: usize, bytes: &[u8]) -> Poly {
    assert_eq!(bytes.len(), 32 * d, "ByteDecode_{d} takes {} bytes", 32 * d);
    let mut f = [0i16; N];
    let mut bit = 0usize;
    for coeff in f.iter_mut() {
        let mut v: u32 = 0;
        for i in 0..d {
            let b = (bytes[bit / 8] >> (bit % 8)) & 1;
            v |= (b as u32) << i;
            bit += 1;
        }
        *coeff = if d == 12 {
            (v % Q as u32) as i16
        } else {
            v as i16
        };
    }
    f
}

/// FIPS 203 equation 4.7, Compress_d.
///
/// `round(2^d / q * x) mod 2^d`, computed with integer arithmetic:
/// `(x * 2^d + q/2) / q`. No floating point, and no branch on `x`.
pub fn compress(d: usize, x: i16) -> i16 {
    let num = (x as u64) << d;
    let quotient = (num + (Q as u64) / 2) / Q as u64;
    (quotient & ((1u64 << d) - 1)) as i16
}

/// FIPS 203 equation 4.8, Decompress_d: `round(q / 2^d * y)`.
pub fn decompress(d: usize, y: i16) -> i16 {
    let num = (y as u64) * Q as u64 + (1u64 << (d - 1));
    (num >> d) as i16
}

pub fn compress_poly(d: usize, f: &Poly) -> Poly {
    let mut out = [0i16; N];
    for (o, &c) in out.iter_mut().zip(f.iter()) {
        *o = compress(d, c);
    }
    out
}

pub fn decompress_poly(d: usize, f: &Poly) -> Poly {
    let mut out = [0i16; N];
    for (o, &c) in out.iter_mut().zip(f.iter()) {
        *o = decompress(d, c);
    }
    out
}
