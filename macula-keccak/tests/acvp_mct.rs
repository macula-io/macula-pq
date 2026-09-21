//! The ACVP Monte Carlo tests, kept in their own file and reported
//! separately from AFT and VOT on purpose.
//!
//! ⚠ MCT IS A STRONG END-TO-END CHECK AND A USELESS DIAGNOSTIC. Each
//! iteration's output is the next iteration's input, 100,000 hashes deep,
//! so a single wrong byte anywhere collapses the entire chain and every
//! result after it. Merging its count into the AFT total would throw away
//! the diagnostic half: when MCT alone fails, the per-test vectors tell
//! you nothing is wrong with a single hash, and the fault is in chaining,
//! state reuse or output length handling.
//!
//! Algorithms transcribed from the ACVP SHA-3 specification
//! (<https://pages.nist.gov/ACVP/draft-celi-acvp-sha3.html>) rather than
//! reconstructed from memory: the SHAKE variant updates its output length
//! from the digest's own trailing bits, which is not something to guess
//! at.

use std::path::PathBuf;

use macula_keccak::{sha3_256, sha3_512, shake128, shake256};
use serde_json::Value;

fn vectors(dir: &str, file: &str) -> Value {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "vectors", dir, file]
        .iter()
        .collect();
    serde_json::from_reader(std::fs::File::open(&p).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn mct_group<'a>(v: &'a Value, want_expected: bool) -> &'a Value {
    v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| {
            if want_expected {
                g["tests"][0].get("resultsArray").is_some()
            } else {
                g["testType"] == "MCT"
            }
        })
        .expect("no MCT group")
}

/// SHA3 standard MCT, verbatim from the ACVP specification:
///
/// ```text
/// For j = 0 to 99
///   MD[0] = SEED;
///     For i = 1 to 1000
///       MSG = MD[i-1]
///       MD[i] = SHA3(MSG)
///     Output MD[1000]
///     SEED = MD[1000]
/// ```
fn run_sha3_mct(dir: &str, hash: &dyn Fn(&[u8]) -> Vec<u8>) {
    let prompt = vectors(dir, "prompt.json");
    let expected = vectors(dir, "expectedResults.json");
    let seed_hex = mct_group(&prompt, false)["tests"][0]["msg"]
        .as_str()
        .unwrap();
    let results = mct_group(&expected, true)["tests"][0]["resultsArray"]
        .as_array()
        .unwrap();
    assert_eq!(results.len(), 100, "{dir}: MCT is 100 outer iterations");

    let mut seed = hex(seed_hex);
    for (j, want) in results.iter().enumerate() {
        let mut md = seed.clone();
        for _ in 0..1000 {
            md = hash(&md);
        }
        assert_eq!(
            hex_of(&md),
            want["md"].as_str().unwrap().to_ascii_lowercase(),
            "{dir} MCT outer iteration {j}: the chain diverged at or before here"
        );
        seed = md;
    }
}

/// SHAKE MCT, verbatim from the ACVP specification:
///
/// ```text
/// Range = maxOutBytes - minOutBytes + 1
/// OutputLen = maxOutBytes
/// For j = 0 to 99
///   MD[0] = SEED
///   For i = 1 to 1000
///     MSG[i] = 128 leftmost bits of MD[i-1]
///     if (MSG[i] < 128 bits) append 0 bits until 128
///     MD[i] = SHAKE(MSG[i], OutputLen * 8)
///     RightmostOutputBits = 16 rightmost bits of MD[i] as an integer
///     OutputLen = minOutBytes + (RightmostOutputBits % Range)
///   Output MD[1000], OutputLen
///   SEED = MD[1000]
/// ```
fn run_shake_mct(dir: &str, xof: &dyn Fn(&[u8], &mut [u8])) {
    let prompt = vectors(dir, "prompt.json");
    let expected = vectors(dir, "expectedResults.json");
    let pg = mct_group(&prompt, false);
    let min_bytes = pg["minOutLen"].as_u64().unwrap() as usize / 8;
    let max_bytes = pg["maxOutLen"].as_u64().unwrap() as usize / 8;
    let range = max_bytes - min_bytes + 1;

    let results = mct_group(&expected, true)["tests"][0]["resultsArray"]
        .as_array()
        .unwrap();
    assert_eq!(results.len(), 100, "{dir}: MCT is 100 outer iterations");

    let mut seed = hex(pg["tests"][0]["msg"].as_str().unwrap());
    let mut out_len = max_bytes;
    for (j, want) in results.iter().enumerate() {
        let mut md = seed.clone();
        for _ in 0..1000 {
            // 128 leftmost bits, zero-padded on the right if shorter.
            let mut msg = [0u8; 16];
            let take = core::cmp::min(16, md.len());
            msg[..take].copy_from_slice(&md[..take]);

            md = vec![0u8; out_len];
            xof(&msg, &mut md);

            let rightmost = u16::from_be_bytes([md[md.len() - 2], md[md.len() - 1]]) as usize;
            out_len = min_bytes + (rightmost % range);
        }
        assert_eq!(
            hex_of(&md),
            want["md"].as_str().unwrap().to_ascii_lowercase(),
            "{dir} MCT outer iteration {j}: the chain diverged at or before here"
        );
        assert_eq!(
            md.len() * 8,
            want["outLen"].as_u64().unwrap() as usize,
            "{dir} MCT outer iteration {j}: output length"
        );
        seed = md;
    }
}

#[test]
fn sha3_256_mct() {
    run_sha3_mct("SHA3-256-2.0", &|m| sha3_256(m).to_vec());
}

#[test]
fn sha3_512_mct() {
    run_sha3_mct("SHA3-512-2.0", &|m| sha3_512(m).to_vec());
}

#[test]
fn shake128_mct() {
    run_shake_mct("SHAKE-128-1.0", &|m, o| shake128(m, o));
}

#[test]
fn shake256_mct() {
    run_shake_mct("SHAKE-256-1.0", &|m, o| shake256(m, o));
}
