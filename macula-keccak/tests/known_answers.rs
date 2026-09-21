//! Three digests any correct SHA-3 must produce, from FIPS 202's own
//! examples. Small, independent of the ACVP plumbing, and the first thing
//! to check when the vector harness goes red: it separates "the
//! permutation is wrong" from "the harness is wrong".
use macula_keccak::{sha3_256, sha3_512, shake128, shake256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn sha3_256_of_empty() {
    assert_eq!(
        hex(&sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn sha3_512_of_empty() {
    assert_eq!(
        hex(&sha3_512(b"")),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
         15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
}

#[test]
fn sha3_256_of_abc() {
    assert_eq!(
        hex(&sha3_256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

#[test]
fn shake128_of_empty_32_bytes() {
    let mut o = [0u8; 32];
    shake128(b"", &mut o);
    assert_eq!(
        hex(&o),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
}

#[test]
fn shake256_of_empty_32_bytes() {
    let mut o = [0u8; 32];
    shake256(b"", &mut o);
    assert_eq!(
        hex(&o),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
}
