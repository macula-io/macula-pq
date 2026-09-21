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
pub mod poly;

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
pub fn key_gen(_p: ParameterSet, _d: &[u8; 32], _z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    todo!("ML-KEM key generation")
}

/// FIPS 203 Algorithm 17, derandomised: `m` is supplied rather than drawn.
///
/// Returns `(c, k)`.
pub fn encaps(_p: ParameterSet, _ek: &[u8], _m: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), Error> {
    todo!("ML-KEM encapsulation")
}

/// FIPS 203 Algorithm 18.
///
/// ⛔ Returns a DETERMINISTIC PSEUDORANDOM SECRET for a ciphertext that
/// does not re-encrypt, NOT an error. That is the implicit rejection path,
/// and an implementation that returns an error instead passes every
/// happy-path vector while failing half the decapsulation ones.
pub fn decaps(_p: ParameterSet, _dk: &[u8], _c: &[u8]) -> Result<[u8; 32], Error> {
    todo!("ML-KEM decapsulation")
}

/// FIPS 203 section 7.2: the encapsulation key check.
pub fn encaps_key_valid(_p: ParameterSet, _ek: &[u8]) -> bool {
    todo!("encapsulation key check")
}

/// FIPS 203 section 7.3: the decapsulation key check.
pub fn decaps_key_valid(_p: ParameterSet, _dk: &[u8]) -> bool {
    todo!("decapsulation key check")
}
