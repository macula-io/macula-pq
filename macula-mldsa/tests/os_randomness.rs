//! The public API: key generation and signing that draw their randomness
//! from the OS, FIPS 204 Algorithms 1 and 2.
//!
//! Only the public API is used here, as a consumer would use it. That the
//! drawn bytes become the seed and the hedge, and that a failing source is
//! an error, is tested in the crate's unit tests, where the source can be
//! replaced.

use macula_mldsa::{
    key_gen, key_gen_seed, sign, verify, ParameterSet, PrivateKey, ML_DSA_44, ML_DSA_65, ML_DSA_87,
};

const SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

/// A constant or reused seed would still produce keys that sign and
/// verify. Only a second draw shows it.
#[test]
fn no_two_key_generations_are_the_same() {
    for p in SETS {
        let (pk1, sk1) = key_gen(p).unwrap();
        let (pk2, sk2) = key_gen(p).unwrap();
        assert_ne!(pk1, pk2, "{}: public keys", p.name);
        assert_ne!(*sk1, *sk2, "{}: private keys", p.name);
    }
}

/// Hedged signing: every signature draws its own `rnd`, so two signatures
/// on one message under one key differ, and both verify. A signer that
/// fell back to the deterministic variant would still produce valid
/// signatures, and only this would show it.
#[test]
fn no_two_signatures_on_one_message_are_the_same() {
    for p in SETS {
        let (pk, sk) = key_gen(p).unwrap();
        let a = sign(p, PrivateKey::Expanded(&sk), b"same", b"").unwrap();
        let b = sign(p, PrivateKey::Expanded(&sk), b"same", b"").unwrap();
        assert_ne!(
            a, b,
            "{}: two signatures on one message are identical",
            p.name
        );
        assert_eq!(verify(p, &pk, b"same", &a, b""), Ok(true), "{}", p.name);
        assert_eq!(verify(p, &pk, b"same", &b, b""), Ok(true), "{}", p.name);
    }
}

/// Keys kept as their seed, as RFC 9964's AKP key stores them: no two
/// draws are the same, and each signs and verifies as a seed.
#[test]
fn no_two_seed_keys_are_the_same_and_each_signs() {
    for p in SETS {
        let (pk1, seed1) = key_gen_seed(p).unwrap();
        let (pk2, seed2) = key_gen_seed(p).unwrap();
        assert_ne!(*seed1, *seed2, "{}: seeds", p.name);
        assert_ne!(pk1, pk2, "{}: public keys", p.name);
        let sig = sign(p, PrivateKey::Seed(&seed1), b"seed key", b"").unwrap();
        assert_eq!(
            verify(p, &pk1, b"seed key", &sig, b""),
            Ok(true),
            "{}",
            p.name
        );
    }
}

/// What a caller receives that is secret wipes itself when it is dropped:
/// the private key, expanded or as its seed.
#[test]
fn the_private_key_a_caller_receives_wipes_itself_on_drop() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    for p in SETS {
        let (_, sk) = key_gen(p).unwrap();
        wipes_on_drop(&sk);
        let (_, seed) = key_gen_seed(p).unwrap();
        wipes_on_drop(&seed);
    }
}
