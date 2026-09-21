//! ML-KEM (FIPS 203), implemented here rather than depended on.
//!
//! ⚠ NOT YET IMPLEMENTED. This crate exists so the workspace shape is
//! visible and the eventual move to `macula-io/macula-pq` is a `git mv`.
//!
//! **It is built second, on `macula-keccak`, deliberately.** FIPS 203 is
//! built on SHA3-256, SHA3-512, SHAKE128 and SHAKE256, so implementing
//! ML-KEM while taking Keccak from a third party would relocate the
//! dependency rather than remove it.
//!
//! Verification will be **byte-exact against NIST's own ACVP vectors**
//! (`usnistgov/ACVP-Server`), covering key generation, encapsulation and
//! decapsulation, **including the implicit-rejection vectors**: FIPS 203
//! returns a deterministic pseudorandom secret for a modified ciphertext
//! rather than an error, and an implementation that errors instead passes
//! every happy-path vector.
//!
//! # ⚠ The timing harness is a GATE on this crate, not a follow-up
//!
//! Unlike Keccak, ML-KEM has real places to leak: rejection sampling, the
//! NTT, compression, any secret-dependent branch or table index. Writing
//! it without those is necessary and is **not evidence that it is free of
//! them**.
//!
//! **Shipping our own ML-KEM with an unverified timing claim would be
//! worse than keeping the dependency it replaces.** aws-lc-rs's
//! implementation has had that analysis; ours would merely look finished.
//! That inverts the reason for doing this at all.
//!
//! So this crate is not done when the ACVP vectors pass. It is done when
//! a harness MEASURES the property and the docs state what was measured
//! rather than what the code avoids. If the harness finds a leak, that is
//! the tool working and the finding gets reported.
