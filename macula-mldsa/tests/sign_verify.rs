//! The public API end to end: keys from the OS, hedged signatures, both
//! private-key formats, and verification refusing what it must.
//!
//! NIST's vectors pin the algorithms byte-exactly; they cannot see the
//! public functions' own behaviour: that signing draws fresh randomness
//! every time, that a seed-format key signs as its expansion does, and
//! that a signature is bound to its message, its context and its key.

use macula_mldsa::{
    internal, key_gen, sign, verify, Error, ParameterSet, PrivateKey, ML_DSA_44, ML_DSA_65,
    ML_DSA_87,
};

const SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

#[test]
fn a_signature_verifies_and_is_bound_to_its_message_context_and_key() {
    for p in SETS {
        let (pk, sk) = key_gen(p).unwrap();
        let (other_pk, _) = key_gen(p).unwrap();
        let sig = sign(p, PrivateKey::Expanded(&sk), b"message", b"ctx").unwrap();
        assert_eq!(sig.len(), p.signature_len(), "{}", p.name);
        assert_eq!(
            verify(p, &pk, b"message", &sig, b"ctx"),
            Ok(true),
            "{}",
            p.name
        );
        assert_eq!(
            verify(p, &pk, b"messagE", &sig, b"ctx"),
            Ok(false),
            "{}: message",
            p.name
        );
        assert_eq!(
            verify(p, &pk, b"message", &sig, b"ctX"),
            Ok(false),
            "{}: context",
            p.name
        );
        assert_eq!(
            verify(p, &pk, b"message", &sig, b""),
            Ok(false),
            "{}: no context",
            p.name
        );
        assert_eq!(
            verify(p, &other_pk, b"message", &sig, b"ctx"),
            Ok(false),
            "{}: key",
            p.name
        );
    }
}

/// Hedged signing: each signature draws its own `rnd`, so two signatures
/// on one message differ, and both verify.
#[test]
fn signing_twice_gives_two_different_valid_signatures() {
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

/// A key stored as its seed signs exactly as its expansion does: with the
/// same `rnd`, the same signature.
#[test]
fn a_seed_key_signs_as_its_expansion_does() {
    for p in SETS {
        let seed = [7u8; 32];
        let (pk, sk) = internal::key_gen(p, &seed);
        let rnd = [9u8; 32];
        let from_seed =
            internal::sign_message(p, PrivateKey::Seed(&seed), b"m", b"c", &rnd).unwrap();
        let from_expanded =
            internal::sign_message(p, PrivateKey::Expanded(&sk), b"m", b"c", &rnd).unwrap();
        assert_eq!(from_seed, from_expanded, "{}", p.name);
        assert_eq!(
            verify(p, &pk, b"m", &from_seed, b"c"),
            Ok(true),
            "{}",
            p.name
        );
        let hedged = sign(p, PrivateKey::Seed(&seed), b"m", b"c").unwrap();
        assert_eq!(verify(p, &pk, b"m", &hedged, b"c"), Ok(true), "{}", p.name);
    }
}

#[test]
fn signing_refuses_a_long_context_and_a_key_of_the_wrong_length() {
    let p = ML_DSA_65;
    let (_, sk) = key_gen(p).unwrap();
    assert_eq!(
        sign(p, PrivateKey::Expanded(&sk), b"m", &[0u8; 256]),
        Err(Error::ContextTooLong)
    );
    assert!(sign(p, PrivateKey::Expanded(&sk), b"m", &[0u8; 255]).is_ok());
    for len in [0, sk.len() - 1, sk.len() + 1] {
        assert_eq!(
            sign(p, PrivateKey::Expanded(&vec![0u8; len]), b"m", b""),
            Err(Error::WrongLength),
            "length {len}"
        );
    }
    // An expanded key of another parameter set is the wrong length here.
    let (_, sk87) = key_gen(ML_DSA_87).unwrap();
    assert_eq!(
        sign(p, PrivateKey::Expanded(&sk87), b"m", b""),
        Err(Error::WrongLength)
    );
}
