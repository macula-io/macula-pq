//! ML-DSA (FIPS 204), implemented here rather than depended on.
//!
//! **Built on `macula-keccak`, deliberately.** FIPS 204 is built on SHAKE128
//! and SHAKE256, so implementing ML-DSA while taking Keccak from a third
//! party would relocate the dependency rather than remove it.
//!
//! ⚠ **ML-DSA is not special here, and this crate does not pretend it is.**
//! FIPS 204 has several good implementations, OTP's `crypto` and `aws-lc-rs`
//! among them. This one is written from scratch, to be verified byte-exact
//! against NIST's own ACVP vectors before it is called done: a claim about
//! independence and assurance, not about being first or better.
//!
//! ⚠ **In progress.** Today this crate holds the parameter sets and
//! nothing else: no key generation, signing or verification yet.
//!
//! # Scope: pure ML-DSA
//!
//! FIPS 204 defines two signature schemes: ML-DSA, which signs the message
//! itself, and HashML-DSA (section 5.4), which signs a pre-computed hash of
//! it. **This crate implements ML-DSA only.** TLS 1.3 and macula's identity
//! signatures both use pure ML-DSA, and HashML-DSA would bring SHA-2, which
//! this workspace deliberately does not own. When the tests run NIST's
//! vectors, the HashML-DSA ones are excluded by count, beside that reason.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// A FIPS 204 parameter set.
///
/// The fields are the specification's own names from its Table 1, so a
/// reader can check them against the standard rather than against this
/// comment. The sizes that follow from them are functions, not fields, so
/// they cannot disagree with the values they come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterSet {
    /// The name the ACVP vectors use, e.g. `"ML-DSA-87"`.
    pub name: &'static str,
    /// `tau`: the number of +/-1 coefficients in the challenge polynomial.
    pub tau: usize,
    /// `lambda`: the collision strength of the commitment hash, in bits.
    pub lambda: usize,
    /// `gamma_1`: the coefficient range of the masking vector `y`.
    pub gamma1: i32,
    /// `gamma_2`: the low-order rounding range.
    pub gamma2: i32,
    /// `k`: the rows of the matrix `A`.
    pub k: usize,
    /// `l`: the columns of the matrix `A`.
    pub l: usize,
    /// `eta`: the coefficient range of the secret vectors `s1` and `s2`.
    pub eta: i32,
    /// `omega`: the maximum number of ones in the hint.
    pub omega: usize,
}

/// ML-DSA-44, security category 2.
pub const ML_DSA_44: ParameterSet = ParameterSet {
    name: "ML-DSA-44",
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    k: 4,
    l: 4,
    eta: 2,
    omega: 80,
};

/// ML-DSA-65, security category 3.
pub const ML_DSA_65: ParameterSet = ParameterSet {
    name: "ML-DSA-65",
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    k: 6,
    l: 5,
    eta: 4,
    omega: 55,
};

/// ML-DSA-87, security category 5. The one macula's identities use.
pub const ML_DSA_87: ParameterSet = ParameterSet {
    name: "ML-DSA-87",
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    k: 8,
    l: 7,
    eta: 2,
    omega: 75,
};

/// The modulus, `q = 2^23 - 2^13 + 1`.
pub const Q: i32 = 8_380_417;

/// `d`: the bits dropped from `t` by Power2Round.
pub const D: usize = 13;

impl ParameterSet {
    /// `beta = tau * eta`.
    pub const fn beta(&self) -> i32 {
        self.tau as i32 * self.eta
    }

    /// A public key: `rho`, then `t1` at 10 bits per coefficient.
    pub const fn public_key_len(&self) -> usize {
        32 + 32 * self.k * 10
    }

    /// A private key: `rho`, `K`, `tr`, then `s1` and `s2` at
    /// `bitlen(2 eta)` bits and `t0` at `d` bits per coefficient.
    pub const fn private_key_len(&self) -> usize {
        let eta_bits = if self.eta == 2 { 3 } else { 4 };
        32 + 32 + 64 + 32 * ((self.l + self.k) * eta_bits + D * self.k)
    }

    /// A signature: `c~`, then `z` at `1 + bitlen(gamma_1 - 1)` bits per
    /// coefficient, then the hint.
    pub const fn signature_len(&self) -> usize {
        let z_bits = if self.gamma1 == 1 << 17 { 18 } else { 20 };
        self.lambda / 4 + self.l * 32 * z_bits + self.omega + self.k
    }
}
