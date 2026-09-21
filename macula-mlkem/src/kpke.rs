//! K-PKE, FIPS 203 section 5: the CPA-secure public-key encryption scheme
//! ML-KEM is built from. Not exposed: its keys are only meaningful inside
//! the Fujisaki-Okamoto transform in `lib.rs`.

use crate::encode::{byte_decode, byte_encode, compress_poly, decompress_poly};
use crate::hash::g;
use crate::poly::{intt, multiply_ntts, ntt, poly_add, poly_sub, Poly, N};
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

/// FIPS 203 Algorithm 14, K-PKE.Encrypt.
///
/// `ek` must already have passed the encapsulation key check; callers go
/// through `encaps`, which enforces it.
pub fn encrypt(p: ParameterSet, ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let k = p.k;
    let t: Vec<Poly> = ek[..384 * k]
        .as_chunks::<384>()
        .0
        .iter()
        .map(|chunk| byte_decode(12, chunk))
        .collect();
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * k..384 * k + 32]);
    let a = matrix(k, &rho);

    let mut n = 0u8;
    let mut y = noise(p.eta1, k, r, &mut n);
    let e1 = noise(p.eta2, k, r, &mut n);
    let e2 = sample_poly_cbd(p.eta2, &prf(p.eta2, r, n));
    y.iter_mut().for_each(ntt);

    // u = NTT^-1(A^T * y) + e1. The TRANSPOSE: u[i] takes column i of A,
    // where key generation used row i.
    let u: Vec<Poly> = e1
        .iter()
        .enumerate()
        .map(|(i, e1i)| {
            let column: Vec<Poly> = a.iter().map(|row| row[i]).collect();
            let mut acc = inner_product(&column, &y);
            intt(&mut acc);
            poly_add(&acc, e1i)
        })
        .collect();

    let mu = decompress_poly(1, &byte_decode(1, m));
    let mut v = inner_product(&t, &y);
    intt(&mut v);
    let v = poly_add(&poly_add(&v, &e2), &mu);

    let mut c: Vec<u8> = u
        .iter()
        .flat_map(|ui| byte_encode(p.du, &compress_poly(p.du, ui)))
        .collect();
    c.extend(byte_encode(p.dv, &compress_poly(p.dv, &v)));
    c
}

/// FIPS 203 Algorithm 15, K-PKE.Decrypt. Recovers the 32-byte message.
///
/// Runs on the secret key. Every step is arithmetic over fixed-size
/// buffers; the only data-dependent choices are lengths, which the
/// parameter set fixes.
pub fn decrypt(p: ParameterSet, dk_pke: &[u8], c: &[u8]) -> [u8; 32] {
    let (c1, c2) = c.split_at(32 * p.du * p.k);
    let mut u: Vec<Poly> = c1
        .chunks_exact(32 * p.du)
        .map(|chunk| decompress_poly(p.du, &byte_decode(p.du, chunk)))
        .collect();
    let v = decompress_poly(p.dv, &byte_decode(p.dv, c2));
    let s: Vec<Poly> = dk_pke
        .as_chunks::<384>()
        .0
        .iter()
        .map(|chunk| byte_decode(12, chunk))
        .collect();

    u.iter_mut().for_each(ntt);
    let mut su = inner_product(&s, &u);
    intt(&mut su);
    let w = poly_sub(&v, &su);

    let mut m = [0u8; 32];
    m.copy_from_slice(&byte_encode(1, &compress_poly(1, &w)));
    m
}
