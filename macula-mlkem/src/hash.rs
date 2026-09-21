//! The hash functions of FIPS 203 section 4.1, all from `macula-keccak`.

use macula_keccak::{sha3_256, sha3_512, shake256};
use zeroize::Zeroizing;

/// `H(s) = SHA3-256(s)`. Only ever applied to the encapsulation key,
/// which is public, so its output is not wiped.
pub fn h(s: &[u8]) -> [u8; 32] {
    sha3_256(s)
}

/// `J(s) = SHAKE256(s, 32 bytes)`, the implicit-rejection secret.
pub fn j(s: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    shake256(s, &mut *out);
    out
}

/// `G(c) = SHA3-512(c)`, split into two 32-byte halves.
///
/// Both halves are wiped when dropped. Every use of G in FIPS 203 has at
/// least one secret half (`sigma`, `K`, `r`), and `rho`, the one public
/// half, costs nothing to wipe as well.
pub fn g(c: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let out = Zeroizing::new(sha3_512(c));
    let mut a = Zeroizing::new([0u8; 32]);
    let mut b = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}
