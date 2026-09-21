//! The ORDERING, the LENGTHS, the SPLITTING and the SECRET CONCATENATION,
//! and, since the swap onto `macula-mlkem`, our ML-KEM-768 inside a real
//! hybrid.
//!
//! ⚠ THE VERIFICATION IS DIFFERENTIAL, NOT VECTOR-BACKED.
//! `draft-ietf-tls-ecdhe-mlkem-05` publishes no test vectors and
//! references none. So `SecP256r1MLKEM768` is exchanged against rustls's
//! `SECP256R1MLKEM768`, an independently written implementation of the
//! same draft on `aws-lc-rs`'s ML-KEM, in BOTH directions. An exchange
//! completes only if this crate's composition and our ML-KEM-768 both
//! agree with theirs.
//!
//! ⚠ `SecP384r1MLKEM1024` HAS NO INDEPENDENT RUST IMPLEMENTATION TO DIFFER
//! AGAINST. Its tests here assert structure and self-consistency. Its
//! ML-KEM-1024 half is exchanged against `aws-lc-rs`'s in the crate's unit
//! tests. Its composition is checked against OTP's `ssl` by
//! `scripts/otp-interop.sh`, outside the gate, since CI has no OTP.

use macula_pq_kx::{SECP256R1MLKEM768 as MINE, SECP384R1MLKEM1024};
use rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768 as THEIRS;
use rustls::NamedGroup;

// ---------------------------------------------------------------------
// The differential tests: this crate against rustls's own group
// ---------------------------------------------------------------------

/// My client, their server. If my share ordering disagreed with theirs,
/// their split would hand the ECDH bytes to ML-KEM and this could not
/// produce an agreeing secret.
#[test]
fn my_client_completes_against_their_server() {
    let mine = MINE.start().unwrap();
    let theirs = THEIRS.start_and_complete(mine.pub_key()).unwrap();
    let my_secret = mine.complete(&theirs.pub_key).unwrap();
    assert_eq!(my_secret.secret_bytes(), theirs.secret.secret_bytes());
}

/// Their client, my server. The reverse direction exercises my
/// `start_and_complete` split of a share I did not build.
#[test]
fn their_client_completes_against_my_server() {
    let theirs = THEIRS.start().unwrap();
    let mine = MINE.start_and_complete(theirs.pub_key()).unwrap();
    let their_secret = theirs.complete(&mine.pub_key).unwrap();
    assert_eq!(their_secret.secret_bytes(), mine.secret.secret_bytes());
}

/// Shares of the same shape. A length disagreement would show up as an
/// interop failure above, but this names the quantity directly.
#[test]
fn my_share_is_the_same_length_as_theirs() {
    assert_eq!(
        MINE.start().unwrap().pub_key().len(),
        THEIRS.start().unwrap().pub_key().len()
    );
}

// ---------------------------------------------------------------------
// Ordering, asserted on BYTES rather than on a behaviour
// ---------------------------------------------------------------------

/// ⚠ THE LINE THIS CRATE IS MOST LIKELY TO GET WRONG.
///
/// `SecP384r1MLKEM1024` and `SECP256R1MLKEM768` put the ECDH share FIRST.
/// `X25519MLKEM768` puts the ML-KEM share first. The draft acknowledges
/// the discrepancy. A crate with this backwards passes every
/// self-consistency test it has and cannot talk to anything.
///
/// So this asserts the actual bytes at the actual offset: the classical
/// share must be the PREFIX of the combined share.
#[test]
fn classical_share_is_the_prefix_not_the_suffix() {
    for group in [MINE, SECP384R1MLKEM1024] {
        let kx = group.start().unwrap();
        let (_, classical) = kx.hybrid_component().unwrap();
        let classical = classical.to_vec();
        let share = kx.pub_key();

        assert_eq!(
            &share[..classical.len()],
            &classical[..],
            "the classical share must be the prefix of {:?}",
            group.name()
        );
        assert_ne!(
            &share[share.len() - classical.len()..],
            &classical[..],
            "if the classical share were also the suffix this test could \
             not tell the two orderings apart"
        );
    }
}

/// A share with the two halves swapped must not silently produce a
/// secret. Asserted against rustls's implementation, so it is their
/// parser rejecting my deliberately malformed bytes.
#[test]
fn a_swapped_share_does_not_complete() {
    let kx = MINE.start().unwrap();
    let (_, classical) = kx.hybrid_component().unwrap();
    let classical_len = classical.len();
    let share = kx.pub_key();

    let (classical_part, pq_part) = share.split_at(classical_len);
    let swapped = [pq_part, classical_part].concat();
    assert_ne!(swapped, share, "the swap must actually change the bytes");

    // Their server either refuses it or derives a different secret. What
    // it must not do is agree with the correctly-ordered exchange.
    let correct = THEIRS.start_and_complete(share).unwrap();
    match THEIRS.start_and_complete(&swapped) {
        Err(_) => {}
        Ok(wrong) => assert_ne!(
            wrong.secret.secret_bytes(),
            correct.secret.secret_bytes(),
            "a swapped share must never yield the correct secret"
        ),
    }
}

// ---------------------------------------------------------------------
// Length handling
// ---------------------------------------------------------------------

/// ⚠ NAMED FOR THE BEHAVIOUR, NOT FOR THE GUARD THAT CURRENTLY PROVIDES
/// IT. A short client share is attacker supplied and must never panic the
/// process. Today a total-length check in `split` is what prevents it;
/// if a later refactor removes that check by some other route, this test
/// must still trip, which it will, because it asserts the outcome rather
/// than the mechanism.
///
/// Mutation-verified: removing the length guard makes this panic inside
/// `split` with `mid > len` rather than fail an assertion.
#[test]
fn a_short_client_share_is_refused_and_never_panics() {
    let share = MINE.start().unwrap().pub_key().to_vec();
    assert!(MINE.start_and_complete(&share[..share.len() - 1]).is_err());
    // Shorter than the classical component: the panic case.
    assert!(MINE.start_and_complete(&[]).is_err());
    assert!(MINE.start_and_complete(&[0u8; 3]).is_err());
    assert!(SECP384R1MLKEM1024.start_and_complete(&[0u8; 3]).is_err());
}

#[test]
fn an_overlong_share_is_refused() {
    let mut share = MINE.start().unwrap().pub_key().to_vec();
    share.push(0);
    assert!(MINE.start_and_complete(&share).is_err());
}

/// A client must refuse a server share of the wrong length too. The
/// server's share carries a KEM ciphertext where the client's carried an
/// encapsulation key, and for ML-KEM those lengths differ, so this length
/// cannot be reused from the client side.
#[test]
fn a_client_refuses_a_malformed_server_share() {
    let kx = MINE.start().unwrap();
    assert!(kx.complete(&[0u8; 7]).is_err());
}

// ---------------------------------------------------------------------
// SecP384r1MLKEM1024 itself
// ---------------------------------------------------------------------

/// Measured, not asserted from a constant this crate carries. The crate
/// deliberately holds no length constants; these are the values the
/// components produced when measured, and this test is what would notice
/// if a component changed underneath the pin.
#[test]
fn secp384r1mlkem1024_shares_have_the_measured_lengths() {
    let kx = SECP384R1MLKEM1024.start().unwrap();
    let (_, classical) = kx.hybrid_component().unwrap();
    assert_eq!(classical.len(), 97, "P-384 uncompressed point");
    // client share = P-384 point + ML-KEM-1024 encapsulation key
    assert_eq!(kx.pub_key().len(), 97 + 1568);

    let server = SECP384R1MLKEM1024.start_and_complete(kx.pub_key()).unwrap();
    // server share = P-384 point + ML-KEM-1024 ciphertext
    assert_eq!(server.pub_key.len(), 97 + 1568);
    // secret = P-384 shared secret (48) + ML-KEM-1024 shared secret (32)
    assert_eq!(server.secret.secret_bytes().len(), 48 + 32);
}

/// Self-consistency only, and named so. There is no third-party
/// implementation of this group to exchange with; that is the point of
/// the crate.
#[test]
fn secp384r1mlkem1024_completes_against_itself() {
    let client = SECP384R1MLKEM1024.start().unwrap();
    let server = SECP384R1MLKEM1024
        .start_and_complete(client.pub_key())
        .unwrap();
    let client_secret = client.complete(&server.pub_key).unwrap();
    assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
}

#[test]
fn named_group_round_trips() {
    let g = SECP384R1MLKEM1024.name();
    assert_eq!(g, NamedGroup::Unknown(0x11ED));
    let raw: u16 = g.into();
    assert_eq!(raw, 0x11ED, "draft-ietf-tls-ecdhe-mlkem-05 section 7.3");
    assert_eq!(NamedGroup::from(raw), g);
}

/// TLS 1.3 only: a hybrid group has no meaning in earlier versions.
#[test]
fn usable_for_tls13_only() {
    use rustls::ProtocolVersion;
    assert!(SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_3));
    assert!(!SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_2));
}
