//! Keccak-f[1600], SHA3-256/512 and SHAKE128/256.
//!
//! ⚠ NOT YET IMPLEMENTED. Vector source is being established first.
//!
//! # Why this is built before ML-KEM
//!
//! FIPS 203 is built on SHA3-256, SHA3-512, SHAKE128 and SHAKE256.
//! Implementing ML-KEM while taking Keccak from a third party would
//! relocate the dependency rather than remove it.
//!
//! # Why this one is genuinely constant-time, when ML-KEM will not be
//!
//! Keccak-f[1600] is a fixed permutation of bitwise operations over a
//! fixed-size state. **There is no secret-dependent branch or table index
//! to write**, because nothing in the permutation is data-dependent: the
//! round count is fixed, the rotation offsets are constants, and the
//! round constants are indexed by the round number rather than by any
//! input. So the timing risk that ML-KEM's rejection sampling and NTT
//! carry does not arise here.
//!
//! ⚠ THAT IS AN ARGUMENT FROM THE ALGORITHM'S SHAPE, NOT A MEASUREMENT,
//! and the distinction is the point rather than a caveat.
//!
//! "Written without secret-dependent branches" is a claim about the
//! author's intentions. A timing measurement is evidence. An unmeasured
//! constant-time claim reads as a guarantee and is an assertion: the same
//! shape as a guard that is green and is not looking at anything.
//!
//! So a timing harness is a GATE on this work, not a follow-up to it, and
//! the claim here will be restated in terms of what was measured once it
//! exists. Until then this crate claims only what it avoids by
//! construction.
