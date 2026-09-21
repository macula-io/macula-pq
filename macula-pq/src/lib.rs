//! The facade: the one place macula's post-quantum posture is decided.
//!
//! ⚠ NOT YET IMPLEMENTED. Stubbed so the workspace shape is visible.
//! Lifting the provider construction out of `macula_quic` is a separate
//! step, after Mercurius's swap lands as it stands.
//!
//! # Why a facade, and why the posture lives here
//!
//! The `kx_groups` list IS the post-quantum posture: which groups are
//! offered, in what order, and that nothing classical-only is among them.
//! That is policy, not QUIC plumbing, so it does not belong in a QUIC
//! transport crate.
//!
//! `macula_quic` and `macula-rust` today each select a crypto provider
//! independently. Two copies of one posture is a contract in two places:
//! one of them eventually gains a classical fallback and nothing notices.
//! Both will call [`provider`] instead.
//!
//! # ⚠ How far "structural" actually goes, stated precisely
//!
//! The intent is that a caller CANNOT assemble a provider carrying a
//! classical-only group. What that can and cannot mean here:
//!
//! - **What is structural:** this crate exposes [`provider`] and does NOT
//!   re-export the individual key exchange groups. A consumer that
//!   depends only on `macula-pq` has no parts to assemble a different
//!   list from, so ours is the only provider it can obtain.
//! - **What is NOT structural, and must not be described as though it
//!   were:** `rustls::crypto::CryptoProvider` is rustls's own public
//!   type, and `macula-pq-kx` is a public crate in this workspace.
//!   Nothing here can PREVENT a determined caller depending on rustls
//!   directly and building whatever provider it likes. Claiming
//!   otherwise would be the same defect as a guard that cannot fire.
//!
//! So the guarantee is: **ours is the only provider these crates hand
//! out, and its contents are asserted by a test.** The negative control
//! that no classical-only group appears in the list is what makes the
//! posture checkable rather than merely documented.

/// The crypto provider every macula component builds its TLS from.
///
/// Not yet implemented: see the module documentation.
pub fn provider() -> rustls::crypto::CryptoProvider {
    todo!("assembled once the provider construction is lifted out of macula_quic")
}
