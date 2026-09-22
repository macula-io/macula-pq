# NIST ACVP test vectors for FIPS 204 (ML-DSA)

**These files are verbatim copies. Nothing here has been edited, reformatted
or trimmed**, so the checksums below can be checked against the source.

## Provenance

| | |
|---|---|
| Source | <https://github.com/usnistgov/ACVP-Server>, `gen-val/json-files/` |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` |
| Commit date | 2026-08-12 (newest ML-DSA change before it: 2026-07-20) |
| Retrieved | 2026-09-22 |

**Licence.** The ACVP-Server repository declares no licence and carries no
`LICENSE` file. These are works of the US Government, which are not subject
to copyright protection in the United States under 17 U.S.C. section 105.

## What they cover

Every function at ML-DSA-44, ML-DSA-65 and ML-DSA-87:

| Set | Cases | Per parameter set |
|---|---:|---|
| `ML-DSA-keyGen-FIPS204` | 75 | 25 |
| `ML-DSA-sigGen-FIPS204` | 360 | 8 groups of 15, expanded private keys |
| `ML-DSA-sigGen-FIPS204-tr1` | 720 | 16 groups of 15: the same 8 kinds, once with **seed** private keys and once with **expanded** ones |
| `ML-DSA-sigVer-FIPS204` | 180 | 4 groups of 15: 3 valid and 12 invalid in each |

⚠ **`-tr1` is not a duplicate, and it is the thicker set.** It is the only
one whose private keys are given as a 32-byte **seed** as well as the 4,896
byte expanded form. Both matter: macula stores expanded keys, and Go loads
ML-DSA keys from the seed only. The obvious directory alone would miss the
seed form entirely.

Groups vary by signature interface (external, or internal with or without
an externally computed `mu`), by deterministic or hedged signing, and by
context. `tests/acvp.rs` asserts every count before it runs anything.

## ⚠ Deliberate exclusion: HashML-DSA

Groups with `preHash: preHash` test HashML-DSA (FIPS 204 section 5.4), which
signs a pre-computed hash of the message with one of twelve named hashes, six
of them SHA-2. **This crate implements pure ML-DSA only**: TLS 1.3 and
macula's identity signatures use pure ML-DSA, and SHA-2 is not owned by this
workspace. Those groups are excluded by count, asserted in the tests:

| Set | Excluded | Run |
|---|---:|---:|
| `ML-DSA-sigGen-FIPS204` | 90 | 270 |
| `ML-DSA-sigGen-FIPS204-tr1` | 180 | 540 |
| `ML-DSA-sigVer-FIPS204` | 45 | 135 |

## Why sigVer's `internalProjection.json` is here

It is the only file that says **why** an invalid signature is invalid:
`modified message`, or `modified signature` in the commitment, `z` or the
hint, 36 of each before exclusion. A verifier that accepts everything passes
every valid case; the invalid ones are the test, so each is asserted by its
label. No other `internalProjection.json` is read, so none is vendored.

## Not published

About 28 MB, over crates.io's 10 MB package limit, so `Cargo.toml` excludes
this directory and the test that reads it from the published crate. They
run here, in the gate.

## Checksums

Verify with `sha256sum`, or regenerate from the commit above.

| File | Bytes | SHA-256 |
|---|---:|---|
| `ML-DSA-keyGen-FIPS204/expectedResults.json` | 873,632 | `361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df` |
| `ML-DSA-keyGen-FIPS204/prompt.json` | 10,062 | `43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef` |
| `ML-DSA-sigGen-FIPS204-tr1/expectedResults.json` | 5,023,936 | `8d86d120d128d2f2d29afb7843b7351677ac0f1bf649295d85b7bf3dd533949c` |
| `ML-DSA-sigGen-FIPS204-tr1/prompt.json` | 7,288,994 | `0a81a213fb4825f0a9d8893a20445a3fed88a6f1832703548120b9588c74a08e` |
| `ML-DSA-sigGen-FIPS204/expectedResults.json` | 2,511,972 | `228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb` |
| `ML-DSA-sigGen-FIPS204/prompt.json` | 5,044,293 | `447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d` |
| `ML-DSA-sigVer-FIPS204/expectedResults.json` | 13,956 | `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6` |
| `ML-DSA-sigVer-FIPS204/internalProjection.json` | 4,533,178 | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |
| `ML-DSA-sigVer-FIPS204/prompt.json` | 3,125,947 | `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e` |
