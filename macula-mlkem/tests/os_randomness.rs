//! The public API: key generation and encapsulation that draw their seeds
//! from the OS, FIPS 203 Algorithms 19 and 20.
//!
//! Only the public API is used here, as a consumer would use it. That the
//! drawn bytes become the seeds, and that a failing source is an error, is
//! tested in the crate's unit tests, where the source can be replaced.

use macula_mlkem::{
    decaps, decaps_key_valid, encaps, encaps_key_valid, key_gen, Error, ParameterSet, ML_KEM_1024,
    ML_KEM_512, ML_KEM_768,
};

const SETS: [ParameterSet; 3] = [ML_KEM_512, ML_KEM_768, ML_KEM_1024];

#[test]
fn generated_keys_pass_both_key_checks() {
    for p in SETS {
        let (ek, dk) = key_gen(p).unwrap();
        assert!(encaps_key_valid(p, &ek), "{}: encapsulation key", p.name);
        assert!(decaps_key_valid(p, &dk), "{}: decapsulation key", p.name);
    }
}

#[test]
fn decapsulation_recovers_the_encapsulated_secret() {
    for p in SETS {
        let (ek, dk) = key_gen(p).unwrap();
        let (c, sent) = encaps(p, &ek).unwrap();
        assert_eq!(decaps(p, &dk, &c).unwrap(), sent, "{}", p.name);
    }
}

/// A constant or reused seed would still produce keys that pass every
/// check above. Only a second draw shows it.
#[test]
fn no_two_key_generations_are_the_same() {
    for p in SETS {
        let (ek1, dk1) = key_gen(p).unwrap();
        let (ek2, dk2) = key_gen(p).unwrap();
        assert_ne!(ek1, ek2, "{}: encapsulation keys", p.name);
        assert_ne!(dk1, dk2, "{}: decapsulation keys", p.name);
    }
}

/// Whoever knows `m` knows the shared secret, so a reused `m` is the
/// failure that matters most, and it is silent: both sides still agree.
#[test]
fn no_two_encapsulations_to_one_key_are_the_same() {
    for p in SETS {
        let (ek, _) = key_gen(p).unwrap();
        let (c1, k1) = encaps(p, &ek).unwrap();
        let (c2, k2) = encaps(p, &ek).unwrap();
        assert_ne!(c1, c2, "{}: ciphertexts", p.name);
        assert_ne!(k1, k2, "{}: shared secrets", p.name);
    }
}

/// FIPS 203 section 7.2: a coefficient of `q` or more fails the modulus
/// check. `0xff, 0x0f` encodes 4095 in the first 12-bit slot.
#[test]
fn encapsulation_refuses_a_key_that_fails_the_modulus_check() {
    for p in SETS {
        let (mut ek, _) = key_gen(p).unwrap();
        ek[0] = 0xff;
        ek[1] |= 0x0f;
        assert_eq!(encaps(p, &ek), Err(Error::EncapsKeyInvalid), "{}", p.name);
    }
}

#[test]
fn encapsulation_refuses_a_key_of_the_wrong_length() {
    for p in SETS {
        let (ek, _) = key_gen(p).unwrap();
        assert_eq!(
            encaps(p, &ek[..ek.len() - 1]),
            Err(Error::WrongLength),
            "{}",
            p.name
        );
    }
}
