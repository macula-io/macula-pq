//! The facade: the one place macula's post-quantum posture is decided.
//!
//! # Why a facade, and why the posture lives here
//!
//! The `kx_groups` list IS the post-quantum posture: which groups are
//! offered, in what order, and that nothing classical-only is among them.
//! That is policy, not QUIC plumbing, so it does not belong in a QUIC
//! transport crate.
//!
//! `macula_quic` and `macula-rust` each select a crypto provider
//! themselves today. Two copies of one posture is a contract in two places:
//! one of them eventually gains a classical fallback and nothing notices.
//! Both are to call [`provider`] instead; neither does yet.
//!
//! # ⚠ How far "structural" actually goes, stated precisely
//!
//! The intent is that a caller CANNOT assemble a provider carrying a
//! classical-only group. What that can and cannot mean here:
//!
//! - **What is structural:** this crate exposes [`provider`] and nothing
//!   else. It does not re-export the key exchange groups, and the list is
//!   a local inside that one function, with no constant, builder or
//!   second constructor beside it. A consumer that depends only on
//!   `macula-pq` has no parts to assemble a different list from.
//! - **What is NOT structural, and must not be described as though it
//!   were:** `rustls::crypto::CryptoProvider` is rustls's own type with
//!   public fields, and `macula-pq-kx` is a public crate. A caller can edit
//!   the provider it is handed, or depend on rustls directly and build
//!   whatever it likes. Nothing in Rust can prevent that, and claiming
//!   otherwise would be the same defect as a guard that cannot fire.
//!
//! So the guarantee is: **ours is the only provider these crates hand out,
//! and its contents are asserted by tests beside it**, including the
//! negative control that makes the posture checkable rather than merely
//! documented.

#![forbid(unsafe_code)]

/// The crypto provider every macula component builds its TLS from.
///
/// # The key exchange groups
///
/// `[SecP384r1MLKEM1024, SecP256r1MLKEM768]`, in preference order, both
/// from `macula-pq-kx`: ML-KEM from `macula-mlkem`, ECDH from `aws-lc-rs`.
///
/// - **`SecP384r1MLKEM1024` leads** because it is the group macula's
///   `pq_hybrid` profile declares, so two macula peers on this provider
///   negotiate it.
/// - **`SecP256r1MLKEM768` follows**: it is the hybrid on BSI TR-02102-2's
///   list, and the one `macula_quic` leads with today. A peer still on that
///   list has no `SecP384r1MLKEM1024`, so it and this provider agree on
///   `SecP256r1MLKEM768`, after one HelloRetryRequest when we dial it.
///
/// Everything else comes from `aws-lc-rs`'s default provider: cipher
/// suites, signature verification, randomness for the TLS layer, and key
/// loading.
///
/// # ⛔ Nothing classical is offered, and three things depend on that
///
/// 1. **Nothing classical is offered.** A peer with no post-quantum group
///    in common fails to connect rather than quietly agreeing on X25519.
///    `nothing_classical_is_offered` asserts it.
/// 2. **The offering is proved real by a negative control**, below: a
///    classical-only peer CANNOT agree with this provider, in either role.
///    It could only agree if the list were not in force.
/// 3. **Erlang deduces the negotiated group from (1) and (2).** `quinn`
///    does not surface the group a QUIC connection negotiated, so
///    `macula_quic_pq_kx_tests` cannot ask for it. It argues instead that
///    a handshake which completes while only post-quantum groups are
///    offered cannot have landed on a classical one.
///
/// ⚠ **ADDING A CLASSICAL FALLBACK GROUP HERE KILLS THAT DEDUCTION.** A
/// completed QUIC handshake would once more be consistent with X25519, and
/// the Erlang test would stop proving anything while staying green. So a
/// fallback obliges a negative control IN ERLANG, against a classical-only
/// peer, which needs a per-endpoint key exchange group option on the NIF.
/// If you are adding the fallback, that is part of the work.
///
/// And this is key exchange, not signatures: certificates are verified
/// with ECDSA, Ed25519 or RSA. Say "post-quantum key exchange", never
/// "post-quantum TLS".
pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: vec![
            macula_pq_kx::SECP384R1MLKEM1024,
            macula_pq_kx::SECP256R1MLKEM768,
        ],
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

#[cfg(test)]
mod tests {
    //! The negative control lives HERE, next to `provider()`, so the list
    //! and the proof that it is in force cannot drift apart.

    use std::sync::Arc;

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::crypto::aws_lc_rs::kx_group as aws;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{
        ClientConfig, ClientConnection, Connection, NamedGroup, RootCertStore, ServerConfig,
        ServerConnection,
    };

    use super::provider;

    /// `SecP384r1MLKEM1024`. rustls 0.23.43 has no variant for it.
    const SECP384R1MLKEM1024: NamedGroup = NamedGroup::Unknown(0x11ED);

    /// The groups whose shared secret a quantum computer cannot recover
    /// from the wire: ML-KEM and the hybrids that carry it. Named rather
    /// than derived from code points, so a classical group numbered near
    /// the ML-KEM block cannot count as post-quantum by accident.
    fn is_post_quantum(group: NamedGroup) -> bool {
        group == SECP384R1MLKEM1024
            || matches!(
                group,
                NamedGroup::MLKEM512
                    | NamedGroup::MLKEM768
                    | NamedGroup::MLKEM1024
                    | NamedGroup::secp256r1MLKEM768
                    | NamedGroup::X25519MLKEM768
            )
    }

    /// Exactly our two hybrids, in this order, and they are OUR objects.
    /// `aws-lc-rs` ships a `SECP256R1MLKEM768` with the same name, the same
    /// lengths and the same behaviour on the wire, so only identity tells
    /// ours from theirs.
    #[test]
    fn offers_our_two_hybrids_in_order_and_nothing_else() {
        let groups = provider().kx_groups;
        assert_eq!(
            groups.len(),
            2,
            "{:?}",
            groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        );
        assert!(
            std::ptr::addr_eq(groups[0], macula_pq_kx::SECP384R1MLKEM1024),
            "first group is not macula-pq-kx's SecP384r1MLKEM1024"
        );
        assert!(
            std::ptr::addr_eq(groups[1], macula_pq_kx::SECP256R1MLKEM768),
            "second group is not macula-pq-kx's SecP256r1MLKEM768"
        );
        assert!(
            !std::ptr::addr_eq(groups[1], aws::SECP256R1MLKEM768),
            "second group is aws-lc-rs's, which runs aws-lc-rs's ML-KEM"
        );
    }

    /// The property itself, independent of the exact list, so a later
    /// change to the list still has to keep it.
    #[test]
    fn nothing_classical_is_offered() {
        for group in provider().kx_groups {
            assert!(
                is_post_quantum(group.name()),
                "{:?} is offered and is classical",
                group.name()
            );
        }
    }

    /// Two macula peers agree on the group the list leads with.
    #[test]
    fn two_peers_on_this_provider_negotiate_secp384r1mlkem1024() {
        let id = Identity::new();
        let agreed = handshake(client(provider(), &id), server(provider(), &id));
        assert_eq!(agreed, Ok(SECP384R1MLKEM1024));
    }

    /// `macula_quic`'s list as it stands at macula `c91e0214`, before it
    /// moves to this provider: all four on `aws-lc-rs`. A peer on it has no
    /// `SecP384r1MLKEM1024`, so the two agree on `SecP256r1MLKEM768`, ours
    /// against `aws-lc-rs`'s in a full TLS handshake, in both roles. This
    /// is also the positive twin of the negative control below: the same
    /// harness, a peer with a group in common, a handshake that completes.
    fn macula_quic_list_today() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![
                aws::SECP256R1MLKEM768,
                aws::X25519MLKEM768,
                aws::MLKEM1024,
                aws::MLKEM768,
            ],
            ..rustls::crypto::aws_lc_rs::default_provider()
        }
    }

    #[test]
    fn a_peer_on_macula_quics_current_list_negotiates_secp256r1mlkem768() {
        let id = Identity::new();
        let as_client = handshake(
            client(provider(), &id),
            server(macula_quic_list_today(), &id),
        );
        let as_server = handshake(
            client(macula_quic_list_today(), &id),
            server(provider(), &id),
        );
        assert_eq!(as_client, Ok(NamedGroup::secp256r1MLKEM768), "we dial them");
        assert_eq!(as_server, Ok(NamedGroup::secp256r1MLKEM768), "they dial us");
    }

    /// ⛔ THE NEGATIVE CONTROL. The tests above show post-quantum groups
    /// being negotiated. They do not show the list doing any work: if
    /// `kx_groups` were ignored and a default applied, handshakes would
    /// still come up. So a peer offering ONLY classical groups must FAIL
    /// to agree with us, in both roles. It can only fail if our list is
    /// genuinely in force.
    #[test]
    fn a_classical_only_peer_cannot_agree_with_us() {
        let classical = || CryptoProvider {
            kx_groups: vec![aws::X25519, aws::SECP256R1, aws::SECP384R1],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let id = Identity::new();
        let as_client = handshake(client(provider(), &id), server(classical(), &id));
        let as_server = handshake(client(classical(), &id), server(provider(), &id));
        assert!(
            as_client.is_err(),
            "a classical-only server agreed with us: {as_client:?}"
        );
        assert!(
            as_server.is_err(),
            "a classical-only client agreed with us: {as_server:?}"
        );
    }

    // -----------------------------------------------------------------
    // A real TLS 1.3 handshake, in memory
    // -----------------------------------------------------------------

    /// A CA and a server certificate it signed, so the client verifies
    /// the chain for real rather than skipping verification.
    struct Identity {
        roots: RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    }

    impl Identity {
        fn new() -> Identity {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::new(ca_params, ca_key);

            let server_key = KeyPair::generate().unwrap();
            let server_cert = CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .signed_by(&server_key, &issuer)
                .unwrap();

            let mut roots = RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            Identity {
                roots,
                chain: vec![server_cert.der().clone()],
                key: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            }
        }
    }

    fn server(provider: CryptoProvider, id: &Identity) -> ServerConfig {
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(id.chain.clone(), id.key.clone_key())
            .unwrap()
    }

    fn client(provider: CryptoProvider, id: &Identity) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(id.roots.clone())
            .with_no_client_auth()
    }

    /// One handshake; the group both sides agreed on, or why they did not.
    /// A failure to agree is a result here, not an error: it is what the
    /// negative control asserts. Both sides must report the same group.
    fn handshake(client_cfg: ClientConfig, server_cfg: ServerConfig) -> Result<NamedGroup, String> {
        let name = ServerName::try_from("localhost").unwrap();
        let mut client = Connection::Client(
            ClientConnection::new(Arc::new(client_cfg), name).map_err(|e| e.to_string())?,
        );
        let mut server = Connection::Server(
            ServerConnection::new(Arc::new(server_cfg)).map_err(|e| e.to_string())?,
        );
        // Far more flights than TLS 1.3 needs, including a HelloRetryRequest;
        // bounds a handshake that stops making progress.
        for _ in 0..20 {
            let moved = pump(&mut client, &mut server)? + pump(&mut server, &mut client)?;
            if moved == 0 && !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        if client.is_handshaking() || server.is_handshaking() {
            return Err("handshake never completed".to_string());
        }
        let agreed = |c: &Connection| c.negotiated_key_exchange_group().map(|g| g.name());
        match (agreed(&client), agreed(&server)) {
            (Some(c), Some(s)) if c == s => Ok(c),
            other => Err(format!("the two sides disagree on the group: {other:?}")),
        }
    }

    /// Moves what `from` wants to send into `to`; returns the bytes moved.
    fn pump(from: &mut Connection, to: &mut Connection) -> Result<usize, String> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut cursor = std::io::Cursor::new(&buf[..]);
        while (cursor.position() as usize) < buf.len() {
            to.read_tls(&mut cursor).map_err(|e| e.to_string())?;
            to.process_new_packets().map_err(|e| e.to_string())?;
        }
        Ok(buf.len())
    }
}
