//! K-PKE, FIPS 203 section 5: the CPA-secure public-key encryption scheme
//! ML-KEM is built from. Not exposed: its keys are only meaningful inside
//! the Fujisaki-Okamoto transform in `lib.rs`.

use crate::encode::byte_encode;
use crate::hash::g;
use crate::poly::{multiply_ntts, ntt, poly_add, Poly, N};
use crate::sample::{prf, sample_ntt, sample_poly_cbd};
use crate::ParameterSet;

/// The matrix `A` in the NTT domain, expanded from `rho`.
///
/// `A[i][j] = SampleNTT(rho || j || i)`: the column index comes FIRST in
/// the seed. Swapping them yields the transpose, which is a valid-looking
/// matrix that no other implementation agrees with.
pub fn matrix(k: usize, rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    (0..k)
        .map(|i| {
            (0..k)
                .map(|j| {
                    let mut seed = [0u8; 34];
                    seed[..32].copy_from_slice(rho);
                    seed[32] = j as u8;
                    seed[33] = i as u8;
                    sample_ntt(&seed)
                })
                .collect()
        })
        .collect()
}

/// `k` noise polynomials from consecutive PRF counters, starting at `*n`.
pub fn noise(eta: usize, k: usize, sigma: &[u8; 32], n: &mut u8) -> Vec<Poly> {
    (0..k)
        .map(|_| {
            let f = sample_poly_cbd(eta, &prf(eta, sigma, *n));
            *n += 1;
            f
        })
        .collect()
}

/// `sum_j a[j] * b[j]` in the NTT domain.
pub fn inner_product(a: &[Poly], b: &[Poly]) -> Poly {
    a.iter().zip(b.iter()).fold([0i16; N], |acc, (x, y)| {
        poly_add(&acc, &multiply_ntts(x, y))
    })
}

/// FIPS 203 Algorithm 13, K-PKE.KeyGen. Returns `(ek_pke, dk_pke)`.
pub fn key_gen(p: ParameterSet, d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // (rho, sigma) = G(d || k). The trailing k byte is FIPS 203's domain
    // separation between parameter sets; without it the same d would give
    // related keys at every security level.
    let mut seed = [0u8; 33];
    seed[..32].copy_from_slice(d);
    seed[32] = p.k as u8;
    let (rho, sigma) = g(&seed);

    let a = matrix(p.k, &rho);
    let mut n = 0u8;
    let mut s = noise(p.eta1, p.k, &sigma, &mut n);
    let mut e = noise(p.eta1, p.k, &sigma, &mut n);
    s.iter_mut().for_each(ntt);
    e.iter_mut().for_each(ntt);

    let t: Vec<Poly> = a
        .iter()
        .zip(e.iter())
        .map(|(row, ei)| poly_add(&inner_product(row, &s), ei))
        .collect();

    let mut ek: Vec<u8> = t.iter().flat_map(|ti| byte_encode(12, ti)).collect();
    ek.extend_from_slice(&rho);
    let dk: Vec<u8> = s.iter().flat_map(|si| byte_encode(12, si)).collect();
    (ek, dk)
}
