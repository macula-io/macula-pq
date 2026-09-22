//! `SecP384r1MLKEM1024` and `SecP256r1MLKEM768` hybrid key exchange for
//! rustls, on our own ML-KEM.
//!
//! # Why this crate exists
//!
//! `SecP384r1MLKEM1024` is the key exchange group macula's `pq_hybrid`
//! profile declares, and **no rustls provider supplies it**: not `ring`,
//! not `aws-lc-rs`, not rustls itself. BSI TR-02102-2 states it *intends
//! to recommend* the group once the corresponding RFC is adopted.
//!
//! OTP's own `ssl` does offer it, from OTP 28.4. That does not help,
//! because **macula's transport is QUIC through a Rust NIF, and OTP's
//! `ssl` does not do QUIC**: the TLS inside macula's QUIC is rustls, so it
//! needs a rustls provider.
//!
//! # Why rustls and aws-lc-rs are here at all
//!
//! - **rustls and quinn are the ENVELOPE**: record layers, handshake state
//!   machines, key schedules. That is protocol engineering, not
//!   cryptography, and there is no reason to own it.
//! - **aws-lc-rs supplies the elliptic-curve half**, P-256 and P-384 ECDH.
//!   The ML-KEM half is `macula-mlkem`'s.
//!
//! Each hybrid holds its two halves as `&'static dyn SupportedKxGroup` and
//! calls them only through the trait. That is why moving the ML-KEM half
//! from `aws-lc-rs`'s to ours changed two lines of this file and none of
//! what it actually contains: the ordering, the lengths, the splitting and
//! the secret concatenation.
//!
//! # What is and is not invented here
//!
//! **No cryptography is invented.** This is a composition: an ECDH share
//! concatenated with an ML-KEM share, and the two shared secrets
//! concatenated, exactly as
//! [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05)
//! specifies. ML-KEM is verified against NIST's vectors in `macula-mlkem`.
//!
//! # ⚠ How this is verified, stated precisely
//!
//! **Differentially, not against vectors.** `draft-ietf-tls-ecdhe-mlkem-05`
//! contains no test vectors and references none.
//!
//! - **`SecP256r1MLKEM768`** is exchanged in both directions against
//!   rustls's `SECP256R1MLKEM768`, an independently written implementation
//!   of the same draft running `aws-lc-rs`'s ML-KEM. One exchange checks
//!   two things at once: it completes only if this crate's composition AND
//!   our ML-KEM-768 both agree with the third party's.
//! - **Our ML-KEM-768 and ML-KEM-1024**, on their own, are exchanged in
//!   both directions against `aws-lc-rs`'s (`ml_kem.rs`).
//! - **`SecP384r1MLKEM1024`** is exchanged in both directions against the
//!   same composition on `aws-lc-rs`'s ML-KEM-1024. That checks our
//!   ML-KEM-1024 inside the full hybrid. It cannot check the composition,
//!   because both sides use this crate's.
//! - **Both hybrids against OTP's `ssl`**, which implements them
//!   independently: `scripts/otp-interop.sh`, a real TLS 1.3 handshake in
//!   both roles through `macula-pq`'s configuration builders, OTP offering one group
//!   at a time. This is the only independent check of the
//!   `SecP384r1MLKEM1024` composition, since no Rust implementation of it
//!   exists to exchange with. It runs OUTSIDE the gate, because it needs
//!   OTP 28.4 or later: it agreed in both roles on OTP 28.4.2, and fails
//!   when this crate's share order for the group is reversed.
//! - **Which ML-KEM each hybrid holds is asserted by identity**
//!   (`both_hybrids_carry_our_ml_kem`): ours and `aws-lc-rs`'s have the
//!   same names and lengths and agree on every exchange, so no behaviour
//!   can tell them apart.
//!
//! # ⚠ What this does NOT provide
//!
//! **The length guard prevents a REMOTE PANIC, not merely a wrong
//! length.** `split` receives an attacker-supplied share. Without the
//! total-length check, `slice::split_at` panics with `mid > len` on any
//! share shorter than the classical component, which is a denial of
//! service reachable by anyone who can send a key share. The guard is
//! what makes the function total. Mutation-verified: removing it makes
//! `a_short_client_share_is_refused_and_never_panics` panic at `split`.
//!
//! Length validation is layered. The guard here is exact on the
//! client-share path, where the expected ML-KEM encapsulation key length
//! is measured from the component. On the server-share path the expected
//! ciphertext length is not available without a throwaway encapsulation,
//! so ML-KEM validates the ciphertext's own length in `complete`; the
//! bounds check here still makes that path total.
//!
//! **Timing is measured for ML-KEM, not for the composition.** ML-KEM is
//! timed in `macula-mlkem` (no leak detected; see its docs for what that
//! means). The ECDH halves are `aws-lc-rs`'s and carry its properties. The
//! composition in this file copies and concatenates shared secret bytes,
//! which is exactly where a secret-dependent branch would hide, and it has
//! had no timing analysis. Do not describe it as constant-time.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ml_kem;

use std::boxed::Box;
use std::vec::Vec;

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// `SecP384r1MLKEM1024`, code point `0x11ED` (4589), from
/// `draft-ietf-tls-ecdhe-mlkem-05` section 7.3.
///
/// rustls 0.23.43's `NamedGroup` has no variant for this group, so it is
/// named by its ordinal. `NamedGroup::Unknown` round-trips through `u16`,
/// which `named_group_round_trips` asserts rather than assumes.
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &SECP384R1MLKEM1024_HYBRID;

static SECP384R1MLKEM1024_HYBRID: Hybrid = Hybrid {
    classical: rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    post_quantum: ml_kem::ML_KEM_1024,
    name: NamedGroup::Unknown(0x11ED),
    // ⚠ FALSE, and this is the single most important line in the crate.
    //
    // `SecP384r1MLKEM1024` puts the ECDH share FIRST. `X25519MLKEM768`
    // puts the ML-KEM share first. The draft acknowledges the discrepancy
    // explicitly. Getting this backwards produces a crate that passes
    // every self-consistency test and cannot talk to anything.
    post_quantum_first: false,
};

/// `SecP256r1MLKEM768`, code point `0x11EB`: the same composition at
/// P-256/ML-KEM-768.
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &SECP256R1MLKEM768_HYBRID;

static SECP256R1MLKEM768_HYBRID: Hybrid = Hybrid {
    classical: rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    post_quantum: ml_kem::ML_KEM_768,
    name: NamedGroup::secp256r1MLKEM768,
    post_quantum_first: false,
};

/// A hybrid of one ECDH group and one KEM, composed per
/// draft-ietf-tls-ecdhe-mlkem.
///
/// ⚠ This carries NO length constants. Every length is read from the
/// component at run time (`pub_key().len()`, and the server share length
/// from what the component actually produces). Copying `97`, `1568` and
/// `1184` in here would put the same contract in two places, where the
/// copy can silently disagree with the component it describes.
#[derive(Debug)]
struct Hybrid {
    classical: &'static dyn SupportedKxGroup,
    post_quantum: &'static dyn SupportedKxGroup,
    name: NamedGroup,
    /// Whether the post-quantum element comes first **in shares and in
    /// secrets**. One flag governs both; the draft never separates them.
    post_quantum_first: bool,
}

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// Order two components. Depends on the ordering flag and nothing else,
/// so both the group and an in-flight exchange use the same function
/// rather than each carrying a copy of the rule.
fn concat(post_quantum_first: bool, post_quantum: &[u8], classical: &[u8]) -> Vec<u8> {
    match post_quantum_first {
        true => [post_quantum, classical].concat(),
        false => [classical, post_quantum].concat(),
    }
}

/// Split a received share into (post_quantum, classical).
///
/// Both lengths are MEASURED from live components rather than stored as
/// constants, so the splitter is sized by the things it is splitting.
///
/// ⚠ `post_quantum_len` must be the EXPECTED length, never the remainder
/// of `share.len() - classical_len`. Passing the remainder makes the
/// guard below read `share.len() != share.len()`, a tautology that can
/// never fire. This crate was written with that bug and it survived a
/// full green suite; a mutation found it, because the components rejected
/// the malformed shares downstream and every test still passed.
///
/// ⚠ THE GUARD IS NOT DECORATION. `split_at` panics with `mid > len` on a
/// share shorter than `classical_len`, and the share is attacker
/// supplied. Removing the guard turns a malformed key share into a remote
/// panic.
fn split(
    post_quantum_first: bool,
    share: &[u8],
    classical_len: usize,
    post_quantum_len: usize,
) -> Option<(&[u8], &[u8])> {
    if share.len() != classical_len + post_quantum_len {
        return None;
    }
    Some(match post_quantum_first {
        true => share.split_at(post_quantum_len),
        false => {
            let (classical, post_quantum) = share.split_at(classical_len);
            (post_quantum, classical)
        }
    })
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let post_quantum = self.post_quantum.start()?;
        let combined_pub_key = concat(
            self.post_quantum_first,
            post_quantum.pub_key(),
            classical.pub_key(),
        );
        Ok(Box::new(ActiveHybrid {
            classical_share_len: classical.pub_key().len(),
            classical,
            post_quantum,
            name: self.name,
            post_quantum_first: self.post_quantum_first,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        // The classical share length comes from a live component of the
        // same group, so the split is sized by the thing it is splitting.
        // Both expectations come from live components of this same group:
        // the classical share length, and the length of an ML-KEM
        // ENCAPSULATION KEY, which is what a client sends. Measuring beats
        // storing, because a stored copy is a second place for the same
        // contract to live and can drift from the component silently.
        let classical_len = self.classical.start()?.pub_key().len();
        let post_quantum_len = self.post_quantum.start()?.pub_key().len();
        let (post_quantum_share, classical_share) = split(
            self.post_quantum_first,
            client_share,
            classical_len,
            post_quantum_len,
        )
        .ok_or(INVALID_KEY_SHARE)?;

        let cl = self.classical.start_and_complete(classical_share)?;
        let pq = self.post_quantum.start_and_complete(post_quantum_share)?;

        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: concat(self.post_quantum_first, &pq.pub_key, &cl.pub_key),
            secret: SharedSecret::from(concat(
                self.post_quantum_first,
                pq.secret.secret_bytes(),
                cl.secret.secret_bytes(),
            )),
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    /// SP 800-56C rev 2 permits a hybrid secret of the form `Z' = Z || T`,
    /// where the element appearing FIRST is the one whose approval
    /// carries. So the flag that orders the secret also decides this.
    fn fips(&self) -> bool {
        match self.post_quantum_first {
            true => self.post_quantum.fips(),
            false => self.classical.fips(),
        }
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    name: NamedGroup,
    post_quantum_first: bool,
    classical_share_len: usize,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // The SERVER's share carries a KEM CIPHERTEXT where the client's
        // carried an encapsulation key, and for ML-KEM those lengths
        // differ, so the client-side expectation cannot be reused here.
        //
        // ⚠ THE EXPECTED CIPHERTEXT LENGTH IS NOT AVAILABLE HERE without
        // performing a throwaway encapsulation, so this is a BOUNDS check
        // and not a length check: it rejects a share too short to contain
        // a classical component, and leaves the ciphertext's own length to
        // be validated by ML-KEM in `post_quantum.complete`, which refuses
        // a ciphertext of the wrong size. That is a real check, in the
        // component rather than here. It is written out because a reader
        // would otherwise take the line below for validation it is not.
        let post_quantum_len = peer_pub_key
            .len()
            .checked_sub(self.classical_share_len)
            .ok_or(INVALID_KEY_SHARE)?;
        let (post_quantum_share, classical_share) = split(
            self.post_quantum_first,
            peer_pub_key,
            self.classical_share_len,
            post_quantum_len,
        )
        .ok_or(INVALID_KEY_SHARE)?;

        let cl = self.classical.complete(classical_share)?;
        let pq = self.post_quantum.complete(post_quantum_share)?;
        Ok(SharedSecret::from(concat(
            self.post_quantum_first,
            pq.secret_bytes(),
            cl.secret_bytes(),
        )))
    }

    /// Lets a peer select the classical half alone.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::SupportedKxGroup;
    use rustls::NamedGroup;

    use super::{ml_kem, Hybrid, SECP256R1MLKEM768_HYBRID, SECP384R1MLKEM1024_HYBRID};

    /// ⛔ THE SWAP, ASSERTED BY IDENTITY. `aws-lc-rs`'s ML-KEM groups have
    /// the same names as ours, the same lengths, and agree with ours on
    /// every exchange, so no behavioural test can tell which one a hybrid
    /// holds. This compares the objects themselves.
    #[test]
    fn both_hybrids_carry_our_ml_kem() {
        assert!(
            std::ptr::addr_eq(SECP384R1MLKEM1024_HYBRID.post_quantum, ml_kem::ML_KEM_1024),
            "SecP384r1MLKEM1024's ML-KEM half is not macula-mlkem's"
        );
        assert!(
            std::ptr::addr_eq(SECP256R1MLKEM768_HYBRID.post_quantum, ml_kem::ML_KEM_768),
            "SecP256r1MLKEM768's ML-KEM half is not macula-mlkem's"
        );
    }

    /// This crate's composition with `aws-lc-rs`'s ML-KEM-1024 in place of
    /// ours: `SecP384r1MLKEM1024` as it was before the swap. Test-only.
    static SECP384R1MLKEM1024_ON_AWS_LC_RS: Hybrid = Hybrid {
        classical: rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        post_quantum: rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
        name: NamedGroup::Unknown(0x11ED),
        post_quantum_first: false,
    };

    /// No independent Rust implementation of `SecP384r1MLKEM1024` exists,
    /// so: ours against the same composition on `aws-lc-rs`'s ML-KEM-1024,
    /// in both directions. The exchange completes only if the two ML-KEMs
    /// agree inside the hybrid. It checks ML-KEM, not the composition,
    /// which both sides share.
    #[test]
    fn secp384r1mlkem1024_agrees_with_itself_on_aws_lc_rs_ml_kem() {
        let ours: &dyn SupportedKxGroup = &SECP384R1MLKEM1024_HYBRID;
        let theirs: &dyn SupportedKxGroup = &SECP384R1MLKEM1024_ON_AWS_LC_RS;
        for (client_side, server_side) in [(ours, theirs), (theirs, ours)] {
            let client = client_side.start().unwrap();
            let server = server_side.start_and_complete(client.pub_key()).unwrap();
            let secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
        }
    }
}
