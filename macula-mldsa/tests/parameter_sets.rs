//! The values this crate DERIVES from FIPS 204's Table 1 must equal the
//! ones the standard states: beta in Table 1 itself, the key and
//! signature sizes in Table 2. The derivations are formulas over the
//! Table 1 fields, so a wrong bit width or a wrong field fails here, not
//! as a length mismatch deep in the ACVP run.

use macula_mldsa::{ParameterSet, ML_DSA_44, ML_DSA_65, ML_DSA_87};

/// (parameter set, beta, private key, public key, signature), in bytes,
/// copied from FIPS 204 Tables 1 and 2.
const FIPS_204: [(ParameterSet, i32, usize, usize, usize); 3] = [
    (ML_DSA_44, 78, 2560, 1312, 2420),
    (ML_DSA_65, 196, 4032, 1952, 3309),
    (ML_DSA_87, 120, 4896, 2592, 4627),
];

#[test]
fn beta_is_table_1s() {
    for (p, beta, ..) in FIPS_204 {
        assert_eq!(p.beta(), beta, "{} beta", p.name);
    }
}

#[test]
fn sizes_are_table_2s() {
    for (p, _, sk, pk, sig) in FIPS_204 {
        assert_eq!(p.private_key_len(), sk, "{} private key", p.name);
        assert_eq!(p.public_key_len(), pk, "{} public key", p.name);
        assert_eq!(p.signature_len(), sig, "{} signature", p.name);
    }
}
