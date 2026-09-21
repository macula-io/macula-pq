//! The hash functions of FIPS 203 section 4.1, all from `macula-keccak`.

use macula_keccak::{sha3_256, sha3_512, shake256};

/// `H(s) = SHA3-256(s)`.
pub fn h(s: &[u8]) -> [u8; 32] {
    sha3_256(s)
}

/// `J(s) = SHAKE256(s, 32 bytes)`, the implicit-rejection key derivation.
pub fn j(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(s, &mut out);
    out
}

/// `G(c) = SHA3-512(c)`, split into two 32-byte halves.
pub fn g(c: &[u8]) -> ([u8; 32], [u8; 32]) {
    let out = sha3_512(c);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}
