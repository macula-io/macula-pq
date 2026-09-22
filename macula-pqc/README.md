# macula-pqc

rustls configuration builders locked to **post-quantum hybrid key
exchange**: `SecP384r1MLKEM1024`, then `SecP256r1MLKEM768`, and nothing
classical. The ML-KEM half is this project's own implementation, verified
byte-exact against NIST's ACVP vectors; the elliptic-curve half is
`aws-lc-rs`.

**This is the crate to depend on.** `macula-keccak`, `macula-mlkem` and
`macula-pqc-kx` are published only because cargo requires a crate's
dependencies to be on crates.io.

## Getting started

```rust
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// A client: you choose how the server is verified.
fn client(roots: RootCertStore) -> ClientConfig {
    let mut config = macula_pqc::client_builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"macula".to_vec()];
    config
}

/// A server: you choose client authentication and the certificate.
fn server(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    macula_pqc::server_builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
}
```

Both offer `SecP384r1MLKEM1024`, then `SecP256r1MLKEM768`, and nothing
else. For QUIC, hand the result to quinn as usual, for example
`quinn::crypto::rustls::QuicClientConfig::try_from(client(roots))`: QUIC
requires TLS 1.3, which both builders already fix.

This example is compiled by the crate's tests, and the
[crate documentation](https://docs.rs/macula-pqc) runs a fuller one.

## What is decided for you, and what is not

- **Decided:** the key exchange groups and TLS 1.3. No function returns
  the crypto provider itself; it goes straight into the rustls builder,
  which keeps it private.
- **Yours:** certificates, the verifier, client authentication, ALPN and
  everything else a rustls configuration holds.
- **Not preventable:** code that depends on rustls directly can build a
  configuration from scratch. That bypasses this crate on purpose.

A peer offering only classical groups cannot connect, in either role:
tested, and checked against OTP's own `ssl`, the one independent
implementation of `SecP384r1MLKEM1024`.

## What is not claimed

This is post-quantum **key exchange**, not post-quantum TLS: certificates
are verified with ECDSA, Ed25519 or RSA. Nothing here is claimed to be
constant-time; ML-KEM's timing has been measured, and what that means is
stated in the [project README](https://github.com/macula-io/macula-pqc#what-is-not-claimed).

## License

Apache-2.0. See [LICENSE](LICENSE).
