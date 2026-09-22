//! ML-DSA against NIST's own ACVP vectors, byte-exact.
//!
//! ⚠ THIS FILE IS THE MOST DANGEROUS ARTEFACT IN THE CRATE. A vector
//! harness that silently passes everything would make every subsequent
//! claim green and meaningless. So its own failure path is tested:
//! `the_harness_fails_loudly_on_a_mismatch` feeds `compare` a deliberate
//! mismatch and asserts it panics with a message naming the parameter
//! set, the test id and the operation.
//!
//! ⚠ AND A RED MUST LOCALISE. Every assertion goes through `compare`,
//! which names the parameter set, the `tcId` and the operation, and shows
//! byte lengths before the values.
//!
//! ⛔ WHAT IS NOT RUN IS COUNTED, BESIDE ITS REASON. HashML-DSA groups are
//! excluded through one function, `hash_ml_dsa_excluded`, and the shape
//! tests assert exactly how many tests that removes from each file. A
//! vector file that grows a new kind of group fails here rather than
//! being skipped without anyone noticing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use macula_mldsa::{ParameterSet, ML_DSA_44, ML_DSA_65, ML_DSA_87};
use serde_json::Value;

const KEYGEN: &str = "ML-DSA-keyGen-FIPS204";
const SIGGEN: &str = "ML-DSA-sigGen-FIPS204";
const SIGGEN_TR1: &str = "ML-DSA-sigGen-FIPS204-tr1";
const SIGVER: &str = "ML-DSA-sigVer-FIPS204";

/// Why the HashML-DSA groups are not run. Kept beside the exclusion and
/// printed with the count, so the reason travels with the number.
const HASH_ML_DSA_REASON: &str = "HashML-DSA (FIPS 204 section 5.4) is not implemented: \
     pure ML-DSA only, no SHA-2 in this workspace";

/// The four ways NIST breaks a signature, and the one way it doesn't, as
/// labelled in the sigVer internalProjection.
const MODIFIED_MESSAGE: &str = "modified message";
const MODIFIED_COMMITMENT: &str = "modified signature - commitment";
const MODIFIED_Z: &str = "modified signature - z";
const MODIFIED_HINT: &str = "modified signature - hint";
const VALID: &str = "valid signature and message - signature should verify successfully";

fn vectors(dir: &str, file: &str) -> Value {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "vectors", dir, file]
        .iter()
        .collect();
    serde_json::from_reader(
        std::fs::File::open(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
    )
    .unwrap()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The single comparison every assertion goes through, so a red always
/// localises and always looks the same.
///
/// Panics with the parameter set, the `tcId` and the operation named. The
/// byte lengths come before the values because a length mismatch is a
/// different fault from a content mismatch and should be visible without
/// reading nine thousand hex characters.
fn compare(set: &str, tc_id: u64, op: &str, got: &[u8], want: &[u8]) {
    assert_eq!(
        got.len(),
        want.len(),
        "{set} tcId {tc_id} {op}: LENGTH differs, got {} bytes, expected {}",
        got.len(),
        want.len()
    );
    assert_eq!(
        hex_of(got),
        hex_of(want),
        "{set} tcId {tc_id} {op}: {} bytes, content differs",
        got.len()
    );
}

fn param(name: &str) -> ParameterSet {
    match name {
        "ML-DSA-44" => ML_DSA_44,
        "ML-DSA-65" => ML_DSA_65,
        "ML-DSA-87" => ML_DSA_87,
        other => panic!("unknown parameter set in the vectors: {other}"),
    }
}

fn groups(v: &Value) -> &Vec<Value> {
    v["testGroups"].as_array().unwrap()
}

fn tests(g: &Value) -> &Vec<Value> {
    g["tests"].as_array().unwrap()
}

/// Expected results by tcId, as the whole JSON object so each caller
/// reads the fields it needs.
fn expected(dir: &str) -> BTreeMap<u64, Value> {
    let e = vectors(dir, "expectedResults.json");
    let mut out = BTreeMap::new();
    for g in groups(&e) {
        for t in tests(g) {
            out.insert(t["tcId"].as_u64().unwrap(), t.clone());
        }
    }
    out
}

/// The `reason` labels live ONLY in internalProjection, not in prompt or
/// expectedResults. A harness built from the other two gets the negative
/// cases but cannot tell which is which, and would not notice all the
/// hint cases passing for the wrong reason.
fn reasons(dir: &str) -> BTreeMap<u64, String> {
    let p = vectors(dir, "internalProjection.json");
    let mut out = BTreeMap::new();
    for g in groups(&p) {
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let r = t["reason"]
                .as_str()
                .unwrap_or_else(|| panic!("tcId {tc} has no reason"));
            out.insert(tc, r.to_string());
        }
    }
    out
}

/// ⛔ THE ONE PLACE A GROUP IS LEFT OUT. True for a HashML-DSA group,
/// false for a pure one, and a panic for anything else: an interface or
/// pre-hash mode this harness has not been taught fails loudly instead of
/// being run as the wrong thing or skipped.
fn hash_ml_dsa_excluded(g: &Value) -> bool {
    match (
        g["signatureInterface"].as_str(),
        g.get("preHash").and_then(Value::as_str),
    ) {
        (Some("internal"), None) => false,
        (Some("external"), Some("pure")) => false,
        (Some("external"), Some("preHash")) => true,
        other => panic!(
            "tgId {}: a group kind this harness does not know: {other:?}",
            g["tgId"]
        ),
    }
}

/// The pure groups of a signing or verification file, and how many tests
/// the exclusion removed.
fn pure_groups(v: &Value) -> (Vec<&Value>, usize) {
    let mut run = Vec::new();
    let mut excluded = 0;
    for g in groups(v) {
        if hash_ml_dsa_excluded(g) {
            excluded += tests(g).len();
        } else {
            run.push(g);
        }
    }
    (run, excluded)
}

fn test_count(gs: &[&Value]) -> usize {
    gs.iter().map(|g| tests(g).len()).sum()
}

// ---------------------------------------------------------------------
// The shape of the vector files, asserted before anything is run
// ---------------------------------------------------------------------

/// ⛔ A vector file that changes shape must fail LOUDLY rather than
/// silently covering less.
#[test]
fn keygen_vector_file_has_the_expected_shape() {
    let p = vectors(KEYGEN, "prompt.json");
    let gs = groups(&p);
    assert_eq!(gs.len(), 3, "one keyGen group per parameter set");
    for g in gs {
        assert_eq!(g["testType"], "AFT");
        param(g["parameterSet"].as_str().unwrap());
        assert_eq!(
            tests(g).len(),
            25,
            "{}: keyGen AFT count",
            g["parameterSet"]
        );
    }
}

/// 24 groups of 15: per parameter set, internal and external-pure
/// signing each deterministic and hedged, internal with and without an
/// external mu, and the two HashML-DSA groups.
#[test]
fn siggen_vector_file_has_the_expected_shape() {
    let p = vectors(SIGGEN, "prompt.json");
    assert_eq!(groups(&p).len(), 24);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 90,
        "HashML-DSA sigGen tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 270, "pure sigGen tests run");
    for g in &run {
        assert!(
            g.get("keyFormat").is_none(),
            "the FIPS204 set has no key formats"
        );
    }
    let hedged = run.iter().filter(|g| g["deterministic"] == false).count();
    assert_eq!(hedged, 9, "3 hedged pure groups per parameter set");
}

/// The -tr1 revision: every sigGen group twice, once with the private key
/// expanded and once as the 32-byte seed. Both formats are run.
#[test]
fn siggen_tr1_vector_file_has_the_expected_shape() {
    let p = vectors(SIGGEN_TR1, "prompt.json");
    assert_eq!(groups(&p).len(), 48);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 180,
        "HashML-DSA sigGen-tr1 tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 540, "pure sigGen-tr1 tests run");

    let mut by_format: BTreeMap<&str, usize> = BTreeMap::new();
    for g in &run {
        let format = g["keyFormat"].as_str().unwrap();
        let key_field = match format {
            "seed" => "seed",
            "expanded" => "sk",
            other => panic!("a key format this harness does not know: {other}"),
        };
        for t in tests(g) {
            assert!(
                t.get(key_field).is_some(),
                "tcId {}: a {format} key carries `{key_field}`",
                t["tcId"]
            );
        }
        *by_format.entry(format).or_default() += tests(g).len();
    }
    assert_eq!(by_format.get("seed"), Some(&270), "seed-format tests run");
    assert_eq!(
        by_format.get("expanded"),
        Some(&270),
        "expanded-format tests run"
    );
}

/// ⛔ EVERY NEGATIVE IS COUNTED BY ITS REASON. 12 groups of 15, each
/// holding 3 of each of the four ways NIST breaks a signature and 3 valid
/// ones. If a later file drops the hint cases, this fails rather than the
/// suite quietly no longer testing hint decoding.
#[test]
fn sigver_vector_file_has_the_expected_shape() {
    let p = vectors(SIGVER, "prompt.json");
    let e = expected(SIGVER);
    let reasons = reasons(SIGVER);
    assert_eq!(groups(&p).len(), 12);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 45,
        "HashML-DSA sigVer tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 135, "pure sigVer tests run");

    let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
    for g in &run {
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let reason = reasons[&tc].as_str();
            let passes = e[&tc]["testPassed"].as_bool().unwrap();
            assert_eq!(
                passes,
                reason == VALID,
                "tcId {tc}: `{reason}` and testPassed agree"
            );
            *by_reason.entry(reason).or_default() += 1;
        }
    }
    let want: BTreeMap<&str, usize> = [
        (MODIFIED_MESSAGE, 27),
        (MODIFIED_COMMITMENT, 27),
        (MODIFIED_Z, 27),
        (MODIFIED_HINT, 27),
        (VALID, 27),
    ]
    .into();
    assert_eq!(by_reason, want, "pure sigVer cases by reason");
}

// ---------------------------------------------------------------------
// The harness's own failure path
// ---------------------------------------------------------------------

/// ⛔ PROVES THE HARNESS CAN FAIL, and that it says something useful when
/// it does. Without this, a harness that compared nothing would look
/// exactly like a correct implementation.
#[test]
fn the_harness_fails_loudly_on_a_mismatch() {
    let content = std::panic::catch_unwind(|| {
        compare("ML-DSA-87", 42, "signature", &[1, 2, 3], &[1, 2, 4]);
    })
    .unwrap_err();
    let msg = panic_message(&content);
    for needle in ["ML-DSA-87", "42", "signature", "content differs"] {
        assert!(
            msg.contains(needle),
            "a mismatch message must name {needle}: {msg}"
        );
    }

    let length = std::panic::catch_unwind(|| {
        compare("ML-DSA-65", 7, "public key", &[1, 2], &[1, 2, 3]);
    })
    .unwrap_err();
    let msg = panic_message(&length);
    assert!(
        msg.contains("LENGTH differs"),
        "a length mismatch must say so: {msg}"
    );
    assert!(
        msg.contains("ML-DSA-65") && msg.contains('7'),
        "and localise: {msg}"
    );
}

fn panic_message(e: &Box<dyn std::any::Any + Send>) -> String {
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// A positive control for the same function: matching values must NOT
/// panic. A `compare` that always panicked would pass the test above.
#[test]
fn the_harness_accepts_a_match() {
    compare("ML-DSA-87", 1, "signature", &[9, 9, 9], &[9, 9, 9]);
}

/// The exclusion refuses a group kind it was not taught, rather than
/// quietly running or skipping it.
#[test]
fn the_exclusion_refuses_an_unknown_group_kind() {
    let unknown: Value = serde_json::json!({
        "tgId": 99, "signatureInterface": "external", "preHash": "prehash-v2"
    });
    let e = std::panic::catch_unwind(|| hash_ml_dsa_excluded(&unknown)).unwrap_err();
    let msg = panic_message(&e);
    assert!(
        msg.contains("tgId 99") && msg.contains("prehash-v2"),
        "names the group: {msg}"
    );
}
