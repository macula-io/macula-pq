//! A private key's public key, from either form, and refusal of an
//! expanded key that does not agree with itself.
//!
//! FIPS 204's expanded key carries `tr = H(pk)` and `t0`, both determined
//! by `rho`, `s1` and `s2`. Deriving the public key recomputes them, so a
//! key whose parts disagree, corrupted on disk or assembled wrongly, is
//! refused rather than handed a public key it never had. D6 of macula's
//! plan checks every loaded key this way.

use macula_mldsa::{
    internal, public_key, Error, ParameterSet, PrivateKey, ML_DSA_44, ML_DSA_65, ML_DSA_87,
};

const SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

#[test]
fn the_public_key_of_either_form_is_key_generations() {
    for p in SETS {
        for i in 0u8..5 {
            let seed = [i.wrapping_mul(37).wrapping_add(11); 32];
            let (pk, sk) = internal::key_gen(p, &seed);
            assert_eq!(
                public_key(p, PrivateKey::Seed(&seed)).unwrap(),
                pk,
                "{} seed {i}",
                p.name
            );
            assert_eq!(
                public_key(p, PrivateKey::Expanded(&sk)).unwrap(),
                pk,
                "{} expanded {i}",
                p.name
            );
        }
    }
}

/// One flipped bit in each part of an expanded key: `K` is not bound to
/// the public key and changes nothing it can check; every other part is.
#[test]
fn an_expanded_key_that_disagrees_with_itself_is_refused() {
    for p in SETS {
        let (pk, sk) = internal::key_gen(p, &[3u8; 32]);
        let s_len = 32 * (p.l + p.k) * if p.eta == 2 { 3 } else { 4 };
        for (part, at) in [
            ("rho", 0),
            ("tr", 64),
            ("s1", 128),
            ("s2", 128 + s_len - 1),
            ("t0", 128 + s_len),
            ("t0 end", sk.len() - 1),
        ] {
            let mut bad = sk.to_vec();
            bad[at] ^= 0x01;
            assert_eq!(
                public_key(p, PrivateKey::Expanded(&bad)),
                Err(Error::InconsistentPrivateKey),
                "{}: a flipped bit in {part} was not caught",
                p.name
            );
        }
        let mut other_k = sk.to_vec();
        other_k[40] ^= 0x01;
        assert_eq!(
            public_key(p, PrivateKey::Expanded(&other_k)).unwrap(),
            pk,
            "{}: K",
            p.name
        );
    }
}

#[test]
fn an_expanded_key_of_the_wrong_length_is_refused() {
    for p in SETS {
        assert_eq!(
            public_key(p, PrivateKey::Expanded(&vec![0u8; p.private_key_len() - 1])),
            Err(Error::WrongLength),
            "{}",
            p.name
        );
    }
}
