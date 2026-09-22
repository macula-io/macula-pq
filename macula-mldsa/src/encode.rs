//! FIPS 204 section 7.1 and 7.2: packing polynomials and keys into bytes.
//!
//! Bits go out least significant first, FIPS 204 Algorithms 9 and 12
//! (`IntegerToBits`, `BitsToBytes`): value `i` occupies bits `i * bits`
//! to `i * bits + bits - 1` of the output, little-endian.

use crate::poly::{sub, Poly, N};
use crate::sample::{K_MAX, L_MAX};
use crate::ParameterSet;

/// `bitlen(q - 1) - d`: the bits of each coefficient of `t1`.
pub const T1_BITS: usize = 10;

/// Packs 256 values of `bits` bits each into `out`, which is exactly
/// `32 * bits` bytes.
fn pack(value: impl Fn(usize) -> u32, bits: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * bits);
    let mut acc: u64 = 0;
    let mut held = 0;
    let mut o = 0;
    for i in 0..N {
        acc |= (value(i) as u64) << held;
        held += bits;
        while held >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            held -= 8;
        }
    }
}

/// FIPS 204 Algorithm 16, `SimpleBitPack`, for coefficients in
/// `[0, 2^bits)`.
pub fn simple_bit_pack(w: &Poly, bits: usize, out: &mut [u8]) {
    pack(|i| w[i] as u32, bits, out);
}

/// FIPS 204 Algorithm 17, `BitPack`, for coefficients standing for values
/// in `[-a, b]`: each is packed as `b - w_i`, in `bitlen(a + b)` bits.
/// `w` holds the values mod q, and `b - w_i mod q` is exactly `b - v`
/// because it lands in `[0, a + b]`.
pub fn bit_pack(w: &Poly, b: i32, bits: usize, out: &mut [u8]) {
    pack(|i| sub(b, w[i]) as u32, bits, out);
}

/// FIPS 204 Algorithm 22, `pkEncode`, into `pk` of exactly
/// [`ParameterSet::public_key_len`] bytes.
pub fn pk_encode(pk: &mut [u8], rho: &[u8; 32], t1: &[Poly; K_MAX], p: ParameterSet) {
    pk[..32].copy_from_slice(rho);
    for (chunk, poly) in pk[32..]
        .as_chunks_mut::<{ 32 * T1_BITS }>()
        .0
        .iter_mut()
        .zip(t1)
        .take(p.k)
    {
        simple_bit_pack(poly, T1_BITS, chunk);
    }
}

/// FIPS 204 Algorithm 24, `skEncode`, into `sk` of exactly
/// [`ParameterSet::private_key_len`] bytes.
#[allow(clippy::too_many_arguments)]
pub fn sk_encode(
    sk: &mut [u8],
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly; L_MAX],
    s2: &[Poly; K_MAX],
    t0: &[Poly; K_MAX],
    p: ParameterSet,
) {
    sk[..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(key);
    sk[64..128].copy_from_slice(tr);
    let eb = p.eta_bits();
    let d = crate::D;
    let mut at = 128;
    for poly in s1.iter().take(p.l).chain(s2.iter().take(p.k)) {
        bit_pack(poly, p.eta, eb, &mut sk[at..at + 32 * eb]);
        at += 32 * eb;
    }
    for poly in t0.iter().take(p.k) {
        bit_pack(poly, 1 << (d - 1), d, &mut sk[at..at + 32 * d]);
        at += 32 * d;
    }
    debug_assert_eq!(at, sk.len());
}
