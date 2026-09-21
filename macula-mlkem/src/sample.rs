//! Sampling, FIPS 203 sections 4.2.2 and 4.2.3.
//!
//! # ⚠ The two functions here have OPPOSITE timing properties
//!
//! `sample_ntt` REJECTION-SAMPLES, so its running time depends on its
//! input. That is acceptable and is not a leak, because **its input is
//! public**: it expands the matrix `A` from `rho`, which travels in the
//! clear inside the encapsulation key. A branch on public data leaks
//! nothing.
//!
//! `sample_poly_cbd` runs on **secret** data, the noise seed, and has no
//! rejection: it is a fixed number of bit additions over a fixed-length
//! buffer, with no branch or index depending on a value.
//!
//! Getting these the wrong way round is the classic mistake. Writing
//! rejection sampling anywhere near the noise would leak the secret
//! through timing while passing every test vector.
//!
//! ⚠ Still an argument from shape, not a measurement. See the crate docs.

use macula_keccak::{shake256, Shake128Reader};

use crate::poly::{Poly, N, Q};

/// FIPS 203 Algorithm 7, SampleNTT.
///
/// Takes the 34-byte seed `rho || i || j` and produces a polynomial
/// already in the NTT domain by rejection-sampling 12-bit values.
///
/// This is why `macula-keccak` has an incremental reader: the number of
/// bytes needed is not known in advance, because it depends on how many
/// candidates are rejected.
pub fn sample_ntt(seed: &[u8; 34]) -> Poly {
    let mut xof = Shake128Reader::new(seed);
    let mut f = [0i16; N];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < N {
        xof.read(&mut buf);
        let d1 = buf[0] as u32 + 256 * (buf[1] as u32 % 16);
        let d2 = (buf[1] as u32 / 16) + 16 * buf[2] as u32;
        if d1 < Q as u32 {
            f[j] = d1 as i16;
            j += 1;
        }
        if d2 < Q as u32 && j < N {
            f[j] = d2 as i16;
            j += 1;
        }
    }
    f
}

/// FIPS 203 Algorithm 8, SamplePolyCBD_eta.
///
/// The centred binomial distribution: for each coefficient, the number of
/// set bits in one window minus the number in the next.
///
/// Runs on secret material. No rejection, no branch on a value: the loop
/// bounds are `N` and `eta`, both public.
pub fn sample_poly_cbd(eta: usize, bytes: &[u8]) -> Poly {
    assert_eq!(
        bytes.len(),
        64 * eta,
        "SamplePolyCBD_{eta} takes {} bytes",
        64 * eta
    );
    let bit = |i: usize| ((bytes[i / 8] >> (i % 8)) & 1) as i32;
    let mut f = [0i16; N];
    for (i, coeff) in f.iter_mut().enumerate() {
        let base = 2 * i * eta;
        let mut x = 0i32;
        let mut y = 0i32;
        for k in 0..eta {
            x += bit(base + k);
            y += bit(base + eta + k);
        }
        // `x - y` is in [-eta, eta]; fold into [0, q) without a branch.
        let v = x - y;
        *coeff = (v + ((v >> 31) & Q)) as i16;
    }
    f
}

/// FIPS 203 section 4.1: `PRF_eta(s, b) = SHAKE256(s || b, 64 * eta)`.
pub fn prf(eta: usize, s: &[u8; 32], b: u8) -> Vec<u8> {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(s);
    input[32] = b;
    let mut out = vec![0u8; 64 * eta];
    shake256(&input, &mut out);
    out
}
