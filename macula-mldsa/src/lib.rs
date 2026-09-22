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
//! ⚠ **In progress.** Today this crate generates keys, from the OS
//! ([`key_gen`]), byte-exact against NIST's vectors for all three parameter
//! sets. There is no signing or verification yet.
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

// The seeded algorithms and the arithmetic are public only with the
// `internal` feature, which is for testing: see `internal`'s docs.
#[cfg(feature = "internal")]
pub mod encode;
#[cfg(not(feature = "internal"))]
mod encode;
#[cfg(feature = "internal")]
pub mod internal;
#[cfg(not(feature = "internal"))]
mod internal;
#[cfg(feature = "internal")]
pub mod poly;
#[cfg(not(feature = "internal"))]
mod poly;
#[cfg(feature = "internal")]
pub mod sample;
#[cfg(not(feature = "internal"))]
mod sample;

/// The wrapper every secret output comes in: it wipes its contents when
/// dropped. Re-exported so a caller can name the type.
pub use zeroize::Zeroizing;

/// Why an operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The OS could not supply randomness. FIPS 204 Algorithm 1 returns an
    /// error here rather than build a key from a seed that was not drawn.
    RandomnessUnavailable,
}

/// FIPS 204 Algorithm 1, `ML-DSA.KeyGen`: the seed `xi` is drawn from the
/// OS.
///
/// Returns `(pk, sk)`. `sk` wipes itself when dropped.
pub fn key_gen(p: ParameterSet) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    key_gen_drawing_from(p, os_random)
}

/// [`key_gen`] with its randomness source as a parameter, so the tests can
/// see what is drawn and make the source fail.
fn key_gen_drawing_from(
    p: ParameterSet,
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let mut xi = Zeroizing::new([0u8; 32]);
    random(&mut *xi)?;
    Ok(internal::key_gen(p, &xi))
}

/// The OS CSPRNG, and nothing else.
fn os_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::RandomnessUnavailable)
}

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
        32 + 32 + 64 + 32 * ((self.l + self.k) * self.eta_bits() + D * self.k)
    }

    /// `bitlen(2 eta)`: the bits of each packed coefficient of `s1` and
    /// `s2`, 3 for eta = 2 and 4 for eta = 4.
    pub(crate) const fn eta_bits(&self) -> usize {
        if self.eta == 2 {
            3
        } else {
            4
        }
    }

    /// A signature: `c~`, then `z` at `1 + bitlen(gamma_1 - 1)` bits per
    /// coefficient, then the hint.
    pub const fn signature_len(&self) -> usize {
        let z_bits = if self.gamma1 == 1 << 17 { 18 } else { 20 };
        self.lambda / 4 + self.l * 32 * z_bits + self.omega + self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_source_is_an_error_not_a_key() {
        let got = key_gen_drawing_from(ML_DSA_87, |_| Err(Error::RandomnessUnavailable));
        assert_eq!(got.err(), Some(Error::RandomnessUnavailable));
    }

    /// Exactly one 32-byte seed is drawn, and the key is the one
    /// `KeyGen_internal` makes from it: the OS path adds nothing and drops
    /// nothing.
    #[test]
    fn the_key_is_keygen_internal_of_the_drawn_seed() {
        let mut drawn = Vec::new();
        let (pk, sk) = key_gen_drawing_from(ML_DSA_87, |buf| {
            buf.fill(0x5a);
            drawn.push(buf.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(drawn, vec![32]);
        let (want_pk, want_sk) = internal::key_gen(ML_DSA_87, &[0x5a; 32]);
        assert_eq!(pk, want_pk);
        assert_eq!(*sk, *want_sk);
    }

    #[test]
    fn keys_from_the_os_have_the_standards_lengths_and_differ() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let (pk1, sk1) = key_gen(p).unwrap();
            let (pk2, _) = key_gen(p).unwrap();
            assert_eq!(pk1.len(), p.public_key_len(), "{}", p.name);
            assert_eq!(sk1.len(), p.private_key_len(), "{}", p.name);
            assert_ne!(pk1, pk2, "{}: two draws gave one key", p.name);
        }
    }
}
