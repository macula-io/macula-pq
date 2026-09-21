//! ML-KEM (FIPS 203), implemented here rather than depended on.
//!
//! ⚠ NOT YET IMPLEMENTED. This crate exists so the workspace shape is
//! visible and the eventual move to `macula-io/macula-pq` is a `git mv`.
//!
//! **It is built second, on `macula-keccak`, deliberately.** FIPS 203 is
//! built on SHA3-256, SHA3-512, SHAKE128 and SHAKE256, so implementing
//! ML-KEM while taking Keccak from a third party would relocate the
//! dependency rather than remove it.
//!
//! Verification will be **byte-exact against NIST's own ACVP vectors**
//! (`usnistgov/ACVP-Server`), covering key generation, encapsulation and
//! decapsulation, **including the implicit-rejection vectors**: FIPS 203
//! returns a deterministic pseudorandom secret for a modified ciphertext
//! rather than an error, and an implementation that errors instead passes
//! every happy-path vector.
//!
//! # ⚠ The timing harness is a GATE on this crate, not a follow-up
//!
//! Unlike Keccak, ML-KEM has real places to leak: rejection sampling, the
//! NTT, compression, any secret-dependent branch or table index. Writing
//! it without those is necessary and is **not evidence that it is free of
//! them**.
//!
//! **Shipping our own ML-KEM with an unverified timing claim would be
//! worse than keeping the dependency it replaces.** aws-lc-rs's
//! implementation has had that analysis; ours would merely look finished.
//! That inverts the reason for doing this at all.
//!
//! So this crate is not done when the ACVP vectors pass. It is done when
//! a harness MEASURES the property and the docs state what was measured
//! rather than what the code avoids. If the harness finds a leak, that is
//! the tool working and the finding gets reported.
//!
//! # Randomness, and why the core API is derandomised
//!
//! Key generation and encapsulation take randomness from the **OS
//! CSPRNG**, trusted as part of the platform. Not `aws-lc-rs`, and not
//! ours: a hand-written CSPRNG is the one piece of this workspace where
//! rolling your own would be unambiguously wrong, because randomness has
//! no test vectors. You cannot test that output is unpredictable, so it is
//! the one place a bug would be invisible to the method everything else
//! here relies on.
//!
//! The consequence for the API: the core operations are **derandomised**,
//! taking their seeds as arguments, with thin wrappers that fill those
//! seeds from the OS. That is not a stylistic choice. **The ACVP vectors
//! supply `d`, `z` and `m` directly**, so a derandomised core is what
//! makes the implementation testable against them at all; an API that
//! only ever drew its own randomness could not be checked byte-exactly
//! against anything.

#![forbid(unsafe_code)]

pub mod encode;
mod hash;
mod kpke;
pub mod poly;
pub mod sample;

/// A FIPS 203 parameter set.
///
/// The fields are the specification's own names, so a reader can check
/// them against Table 2 rather than against this comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterSet {
    /// The name the ACVP vectors use, e.g. `"ML-KEM-1024"`.
    pub name: &'static str,
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: usize,
    pub dv: usize,
}

pub const ML_KEM_512: ParameterSet = ParameterSet {
    name: "ML-KEM-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};
pub const ML_KEM_768: ParameterSet = ParameterSet {
    name: "ML-KEM-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};
pub const ML_KEM_1024: ParameterSet = ParameterSet {
    name: "ML-KEM-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// Why an operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An encapsulation key failed the FIPS 203 section 7.2 check.
    EncapsKeyInvalid,
    /// A decapsulation key failed the FIPS 203 section 7.3 check.
    DecapsKeyInvalid,
    /// A byte string was not the length its parameter set requires.
    WrongLength,
}

/// FIPS 203 Algorithm 16, derandomised: `d` and `z` are supplied rather
/// than drawn.
///
/// ⚠ Derandomised because the ACVP vectors supply `d` and `z` directly,
/// so this is the form that can be checked byte-exactly. The wrapper that
/// draws them from the OS CSPRNG sits on top; see the crate docs.
///
/// Returns `(ek, dk)`.
pub fn key_gen(p: ParameterSet, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = kpke::key_gen(p, d);
    // dk = dk_pke || ek || H(ek) || z, FIPS 203 Algorithm 16.
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&hash::h(&ek));
    dk.extend_from_slice(z);
    (ek, dk)
}

/// FIPS 203 Algorithm 17, derandomised: `m` is supplied rather than drawn.
///
/// Returns `(c, k)`.
pub fn encaps(p: ParameterSet, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), Error> {
    if ek.len() != encaps_key_len(p) {
        return Err(Error::WrongLength);
    }
    if !encaps_key_valid(p, ek) {
        return Err(Error::EncapsKeyInvalid);
    }
    // (K, r) = G(m || H(ek)), FIPS 203 Algorithm 17.
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(m);
    seed[32..].copy_from_slice(&hash::h(ek));
    let (shared, r) = hash::g(&seed);
    Ok((kpke::encrypt(p, ek, m, &r), shared))
}

/// `384k + 32` bytes: `k` polynomials at 12 bits, then `rho`.
fn encaps_key_len(p: ParameterSet) -> usize {
    384 * p.k + 32
}

/// FIPS 203 Algorithm 18.
///
/// ⛔ Returns a DETERMINISTIC PSEUDORANDOM SECRET for a ciphertext that
/// does not re-encrypt, NOT an error. That is the implicit rejection path,
/// and an implementation that returns an error instead passes every
/// happy-path vector while failing half the decapsulation ones.
pub fn decaps(p: ParameterSet, dk: &[u8], c: &[u8]) -> Result<[u8; 32], Error> {
    // FIPS 203 section 7.3 input checks. These inspect lengths and the
    // public half of dk, so early exits here leak nothing secret.
    if c.len() != ciphertext_len(p) || dk.len() != decaps_key_len(p) {
        return Err(Error::WrongLength);
    }
    if !decaps_key_valid(p, dk) {
        return Err(Error::DecapsKeyInvalid);
    }

    let k = p.k;
    let dk_pke = &dk[..384 * k];
    let ek_pke = &dk[384 * k..768 * k + 32];
    let h = &dk[768 * k + 32..768 * k + 64];
    let z = &dk[768 * k + 64..768 * k + 96];

    let m_prime = kpke::decrypt(p, dk_pke, c);
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&m_prime);
    seed[32..].copy_from_slice(h);
    let (k_prime, r_prime) = hash::g(&seed);

    let mut rejection_input = Vec::with_capacity(32 + c.len());
    rejection_input.extend_from_slice(z);
    rejection_input.extend_from_slice(c);
    let k_bar = hash::j(&rejection_input);

    // ⛔ Re-encrypt and compare IN CONSTANT TIME. A `==` on these slices
    // exits at the first differing byte, and how far it got tells an
    // attacker how much of a forged ciphertext decrypted consistently.
    // Then select, also without a branch: implicit rejection returns the
    // pseudorandom k_bar for a bad ciphertext, never an error.
    let c_prime = kpke::encrypt(p, ek_pke, &m_prime, &r_prime);
    Ok(ct_select(ct_eq(c, &c_prime), &k_prime, &k_bar))
}

/// `32 * (du * k + dv)` bytes.
fn ciphertext_len(p: ParameterSet) -> usize {
    32 * (p.du * p.k + p.dv)
}

/// `768k + 96` bytes: dk_pke, ek, H(ek), z.
fn decaps_key_len(p: ParameterSet) -> usize {
    768 * p.k + 96
}

/// `0xFF` if `a == b`, `0x00` otherwise, examining every byte.
///
/// The fold never exits early and the final mapping is arithmetic.
/// `black_box` asks the optimiser not to turn either back into a branch;
/// it is a best effort, not a guarantee, and whether it holds is what the
/// timing harness exists to measure.
fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    let diff = core::hint::black_box(diff) as u16;
    // diff == 0 -> 0xFFFF >> 8 = 0xFF; diff in 1..=255 -> 0.
    (diff.wrapping_sub(1) >> 8) as u8
}

/// `a` where `mask` is `0xFF`, `b` where it is `0x00`, bytewise, with no
/// branch on the mask.
fn ct_select(mask: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mask = core::hint::black_box(mask);
    let mut out = [0u8; 32];
    for ((o, x), y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *o = (x & mask) | (y & !mask);
    }
    out
}

/// FIPS 203 section 7.2: the encapsulation key check.
///
/// The length is right, and every 12-bit coefficient is already reduced:
/// decoding then re-encoding must give back the same bytes. A value in
/// `[q, 4096)` would be silently reduced by decoding, so it shows up as a
/// difference here. `ek` is public, so an early exit is fine.
pub fn encaps_key_valid(p: ParameterSet, ek: &[u8]) -> bool {
    ek.len() == encaps_key_len(p)
        && ek[..384 * p.k].as_chunks::<384>().0.iter().all(|chunk| {
            encode::byte_encode(12, &encode::byte_decode(12, chunk)) == chunk.as_slice()
        })
}

/// FIPS 203 section 7.3: the decapsulation key check.
///
/// The length is right, and the stored `H(ek)` matches the `ek` stored
/// beside it. Both are public, so an early exit is fine.
pub fn decaps_key_valid(p: ParameterSet, dk: &[u8]) -> bool {
    let k = p.k;
    dk.len() == decaps_key_len(p)
        && hash::h(&dk[384 * k..768 * k + 32]) == dk[768 * k + 32..768 * k + 64]
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, ct_select};

    /// A difference anywhere must be seen, including in the LAST byte. The
    /// ACVP rejection cases do not say where their ciphertexts were
    /// modified, so a comparison that stopped partway could pass them all.
    #[test]
    fn ct_eq_sees_a_difference_in_any_position() {
        let a = [7u8; 1568];
        assert_eq!(ct_eq(&a, &a), 0xff);
        for pos in [0usize, 1, 783, 1566, 1567] {
            let mut b = a;
            b[pos] ^= 0x01;
            assert_eq!(ct_eq(&a, &b), 0x00, "difference at byte {pos} not seen");
        }
    }

    /// Every one of the 255 non-zero single-byte differences maps to 0x00.
    /// `(diff - 1) >> 8` is the part that could be off by one.
    #[test]
    fn ct_eq_maps_every_nonzero_difference_to_false() {
        for bit in 1u8..=255 {
            assert_eq!(ct_eq(&[0u8], &[bit]), 0x00, "difference {bit:#04x}");
        }
    }

    #[test]
    fn ct_select_takes_a_on_ff_and_b_on_00() {
        let a = [0xaau8; 32];
        let b = [0x55u8; 32];
        assert_eq!(ct_select(0xff, &a, &b), a);
        assert_eq!(ct_select(0x00, &a, &b), b);
    }
}
