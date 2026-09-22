//! FIPS 204 section 7.3: pseudorandom sampling.
//!
//! ⚠ Rejection sampling branches on what it rejects. For `A` that is
//! public: `rho` is in the public key. For `s1` and `s2` the rejected
//! half-bytes come from the secret seed, are discarded, and say nothing
//! about the coefficients kept; this is the shape FIPS 204 specifies, not
//! a claim that the loop runs in constant time.

use macula_keccak::{Shake128Reader, Shake256};
use zeroize::Zeroize;

use crate::poly::{from_signed, Poly, N};
use crate::{ParameterSet, Q};

/// The largest `k` and `l` of the three parameter sets, ML-DSA-87's.
/// Vectors are fixed arrays of this size, the first `k` or `l` in use, so
/// secrets live on the stack and never in a heap buffer that could be
/// reallocated and left behind.
pub const K_MAX: usize = 8;
/// See [`K_MAX`].
pub const L_MAX: usize = 7;

/// A `k x l` matrix of NTT-domain polynomials.
pub type Matrix = [[Poly; L_MAX]; K_MAX];

/// FIPS 204 Algorithm 30, `RejNTTPoly`, with Algorithm 14,
/// `CoeffFromThreeBytes`: a uniform NTT-domain polynomial from a 34-byte
/// public seed.
///
/// Squeezes a SHAKE128 block at a time rather than three bytes at a time:
/// the bytes are consumed in the same order, and the unused rest of the
/// last block is discarded, so the output is the same.
pub fn rej_ntt_poly(seed: &[u8; 34]) -> Poly {
    let mut xof = Shake128Reader::new(seed);
    let mut a = [0i32; N];
    let mut j = 0;
    let mut block = [0u8; 168];
    while j < N {
        xof.read(&mut block);
        for b in block.as_chunks::<3>().0 {
            if j == N {
                break;
            }
            // Algorithm 14: the top bit of the third byte is cleared.
            let z = b[0] as i32 | (b[1] as i32) << 8 | ((b[2] & 0x7f) as i32) << 16;
            if z < Q {
                a[j] = z;
                j += 1;
            }
        }
    }
    a
}

/// FIPS 204 Algorithm 15, `CoeffFromHalfByte`, for `eta` in `{2, 4}`.
fn coeff_from_half_byte(b: u8, eta: i32) -> Option<i32> {
    match eta {
        2 if b < 15 => Some(2 - (b % 5) as i32),
        4 if b < 9 => Some(4 - b as i32),
        _ => None,
    }
}

/// FIPS 204 Algorithm 31, `RejBoundedPoly`, on the seed
/// `rho' || IntegerToBytes(nonce, 2)`: a polynomial with coefficients in
/// `[-eta, eta]`, held mod q.
///
/// `rho'` is secret. It is absorbed as it is, followed by the nonce, rather
/// than copied into a 66-byte seed that would need wiping, and the result
/// is written into `a`, which the caller wipes, rather than returned as a
/// copy that nobody would.
pub fn rej_bounded_poly(a: &mut Poly, rho_prime: &[u8; 64], nonce: u16, eta: i32) {
    let mut h = Shake256::new();
    h.update(rho_prime);
    h.update(&nonce.to_le_bytes());
    let mut xof = h.finalize_xof();
    let mut j = 0;
    let mut block = [0u8; 136];
    while j < N {
        xof.read(&mut block);
        for &z in block.iter() {
            for half in [z & 15, z >> 4] {
                if j < N {
                    if let Some(v) = coeff_from_half_byte(half, eta) {
                        a[j] = from_signed(v);
                        j += 1;
                    }
                }
            }
            if j == N {
                break;
            }
        }
    }
    block.zeroize();
}

/// FIPS 204 Algorithm 32, `ExpandA`: `A[r][s] = RejNTTPoly(rho || s || r)`.
pub fn expand_a(rho: &[u8; 32], p: ParameterSet) -> Box<Matrix> {
    let mut a = Box::new([[[0i32; N]; L_MAX]; K_MAX]);
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    for r in 0..p.k {
        for s in 0..p.l {
            seed[32] = s as u8;
            seed[33] = r as u8;
            a[r][s] = rej_ntt_poly(&seed);
        }
    }
    a
}

/// FIPS 204 Algorithm 33, `ExpandS`: `s1` from nonces `0..l`, `s2` from
/// `l..l+k`, written into the caller's arrays, which the caller wipes:
/// returning them would move a copy of both secrets.
pub fn expand_s(
    s1: &mut [Poly; L_MAX],
    s2: &mut [Poly; K_MAX],
    rho_prime: &[u8; 64],
    p: ParameterSet,
) {
    for (r, poly) in s1.iter_mut().enumerate().take(p.l) {
        rej_bounded_poly(poly, rho_prime, r as u16, p.eta);
    }
    for (r, poly) in s2.iter_mut().enumerate().take(p.k) {
        rej_bounded_poly(poly, rho_prime, (r + p.l) as u16, p.eta);
    }
}
