//! QUIC config building from the builders, the way a quinn consumer
//! (macula_quic) builds one. quinn protects QUIC Initial packets with
//! AES-128-GCM (RFC 9001) and, by default, looks for that suite in the
//! provider's own `cipher_suites`. The provider offers AES-256-GCM alone
//! (macula issue #39), so the Initial suite must come from
//! `quic_initial_suite()`: a config built with `try_from` alone fails with
//! `NoInitialCipherSuite`, and nothing connects. Caught in review of
//! 454b7ff, which shipped the one-suite list without this.
use std::sync::Arc;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::CipherSuite;

fn client() -> rustls::ClientConfig {
    macula_pqc::client_builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(macula_pqc::KeyPossessionVerifier::new()))
        .with_no_client_auth()
}

fn server() -> rustls::ServerConfig {
    let (cert, key) =
        macula_pqc::self_signed_certificate(&[3u8; 32], vec!["localhost".into()]).unwrap();
    macula_pqc::server_builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap()
}

#[test]
fn quic_configs_build_from_the_builders_with_the_initial_suite() {
    let as_client =
        QuicClientConfig::with_initial(Arc::new(client()), macula_pqc::quic_initial_suite());
    let as_server =
        QuicServerConfig::with_initial(Arc::new(server()), macula_pqc::quic_initial_suite());
    assert!(as_client.is_ok(), "client: {:?}", as_client.err());
    assert!(as_server.is_ok(), "server: {:?}", as_server.err());
}

#[test]
fn the_initial_suite_is_aes_128_gcm_and_the_handshake_list_stays_aes_256() {
    assert_eq!(
        macula_pqc::quic_initial_suite().suite.common.suite,
        CipherSuite::TLS13_AES_128_GCM_SHA256
    );
    let handshake: Vec<CipherSuite> = macula_pqc::client_builder()
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| s.suite())
        .collect();
    assert_eq!(handshake, vec![CipherSuite::TLS13_AES_256_GCM_SHA384]);
}

/// ⛔ THE NEGATIVE CONTROL: without the Initial suite, a quinn config cannot be
/// built from these builders. It can only fail if AES-128-GCM is truly absent
/// from the handshake list, which is the point of the list.
#[test]
fn without_the_initial_suite_a_quic_config_cannot_be_built() {
    assert!(QuicClientConfig::try_from(client()).is_err());
    assert!(QuicServerConfig::try_from(server()).is_err());
}
