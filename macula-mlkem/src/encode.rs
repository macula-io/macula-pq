//! Byte encoding and compression, FIPS 203 sections 4.2.1 and 4.2.2.
//!
//! ⚠ Every function here runs on secret data at least some of the time,
//! so there are no secret-dependent branches or indices: the bit packing
//! is driven by `d`, which is a public parameter, and compression uses
//! arithmetic rounding rather than comparison. That is a statement about
//! the code's shape and NOT a measurement; see the crate docs.

use crate::poly::{Poly, N, Q};

/// FIPS 203 Algorithm 5, ByteEncode_d: pack 256 `d`-bit integers into
/// the `32 * d` bytes of `out`, little-endian across the bit stream.
///
/// ⚠ Writes into the caller's buffer rather than returning one. Encoding
/// a secret key into a temporary that is then copied and dropped leaves
/// the key on the heap; the caller's buffer is sized once and wiped once.
pub fn byte_encode(d: usize, f: &Poly, out: &mut [u8]) {
    assert_eq!(out.len(), 32 * d, "ByteEncode_{d} writes {} bytes", 32 * d);
    out.fill(0);
    let mut bit = 0usize;
    for &coeff in f.iter() {
        let v = coeff as u32;
        for i in 0..d {
            let b = ((v >> i) & 1) as u8;
            out[bit / 8] |= b << (bit % 8);
            bit += 1;
        }
    }
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
        *coeff = if d == 12 { reduce_12_bit(v) } else { v as i16 };
    }
    f
}

/// `floor(n / q)` by multiplication and shift, for `n < 2^23`.
///
/// No division instruction: `compress` runs on secret-dependent values in
/// both encryption and decryption, and a hardware divide can take a time
/// that depends on its operands. Whether the optimiser would turn `/ q`
/// into a multiply anyway is not something to rely on, because debug
/// builds emit a real `div`.
///
/// With a ceiling magic any shift from 30 up is exact on this domain; 48
/// leaves margin. `compress_equals_the_division_formula_exhaustively`
/// checks every input.
#[inline(always)]
fn div_q(n: u64) -> u64 {
    const SHIFT: u32 = 48;
    // ceil(2^48 / q), evaluated at compile time.
    const MAGIC: u64 = (1u64 << SHIFT).div_ceil(Q as u64);
    (n * MAGIC) >> SHIFT
}

/// A 12-bit value mod q, without `%`: one conditional subtraction, done
/// with a sign mask. `dk` decodes through here, so the value is secret.
#[inline(always)]
fn reduce_12_bit(v: u32) -> i16 {
    let r = v as i32 - Q;
    (r + ((r >> 31) & Q)) as i16
}

/// FIPS 203 equation 4.7, Compress_d: `round(2^d / q * x) mod 2^d`.
///
/// Integer arithmetic, no branch on `x`, no division.
pub fn compress(d: usize, x: i16) -> i16 {
    const HALF_Q: u64 = Q as u64 / 2;
    let quotient = div_q(((x as u64) << d) + HALF_Q);
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
