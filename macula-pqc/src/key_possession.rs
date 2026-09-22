//! [`KeyPossessionVerifier`]: a server is trusted to hold the key in the one ML-DSA-87 certificate it presents, and
//! for nothing else.
//!
//! A macula station presents a self-signed ML-DSA-87 certificate on its TLS key, and no certificate authority issues
//! ML-DSA certificates, so there is no chain to walk and no name to match. What TLS can still prove is possession:
//! the station's CertificateVerify, a signature over this handshake's transcript, verifies under the key in that
//! certificate. Who the key belongs to is proved outside TLS: macula's connection handshake carries the station
//! identity key's binding over its TLS key, which the client checks against the certificate it received here, before
//! it signs anything (macula's plan, D12 and D16).

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, DigitallySignedStruct, Error, OtherError, PeerIncompatible, SignatureScheme,
};

use crate::signatures::{is_ml_dsa_87_key, SIGNATURE_VERIFICATION_ALGORITHMS};

/// A rustls server certificate verifier for a self-signed ML-DSA-87 certificate: it accepts exactly one certificate
/// whose key is ML-DSA-87, and then the server's TLS 1.3 handshake signature under that key, checked with
/// `macula-mldsa` as every signature through this crate is.
///
/// ⚠ **It proves possession of the key, not identity.** No root store, name, expiry or certificate signature is
/// checked, because none of them says who a self-signed certificate belongs to. A caller that uses it must bind the
/// certificate it received to an identity itself, as macula's connection handshake does, and must not treat a
/// completed handshake as that binding.
///
/// ```
/// # use std::sync::Arc;
/// let config = macula_pqc::client_builder()
///     .dangerous()
///     .with_custom_certificate_verifier(Arc::new(macula_pqc::KeyPossessionVerifier::new()))
///     .with_no_client_auth();
/// # let _ = config;
/// ```
///
/// Refused: more than one certificate, a certificate that does not parse, a key other than ML-DSA-87, a handshake
/// signature that does not verify under the certificate's key, and every TLS 1.2 signature.
#[derive(Debug)]
pub struct KeyPossessionVerifier {
    _private: (),
}

impl KeyPossessionVerifier {
    /// The verifier. It holds no state: the algorithms are this crate's.
    pub fn new() -> KeyPossessionVerifier {
        KeyPossessionVerifier { _private: () }
    }
}

impl Default for KeyPossessionVerifier {
    fn default() -> KeyPossessionVerifier {
        KeyPossessionVerifier::new()
    }
}

impl ServerCertVerifier for KeyPossessionVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(refused(Refusal::MoreThanOneCertificate));
        }
        let key = ParsedCertificate::try_from(end_entity)?.subject_public_key_info();
        match is_ml_dsa_87_key(&key) {
            true => Ok(ServerCertVerified::assertion()),
            false => Err(refused(Refusal::NotAnMlDsa87Key)),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &SIGNATURE_VERIFICATION_ALGORITHMS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SIGNATURE_VERIFICATION_ALGORITHMS.supported_schemes()
    }
}

/// Why a presented certificate was refused, carried to the caller inside rustls' `CertificateError::Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    MoreThanOneCertificate,
    NotAnMlDsa87Key,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::MoreThanOneCertificate => {
                "the server presented more than one certificate; a self-signed ML-DSA-87 certificate is expected alone"
            }
            Refusal::NotAnMlDsa87Key => "the server's certificate key is not ML-DSA-87",
        })
    }
}

impl std::error::Error for Refusal {}

fn refused(refusal: Refusal) -> Error {
    Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(refusal))))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::SignatureScheme;

    use super::KeyPossessionVerifier;
    use crate::self_signed_certificate;

    fn ours() -> CertificateDer<'static> {
        self_signed_certificate(&[5u8; 32], vec!["localhost".to_string()])
            .unwrap()
            .0
    }

    fn classical() -> CertificateDer<'static> {
        let key = KeyPair::generate().unwrap();
        CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .der()
            .clone()
    }

    fn check(end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> bool {
        KeyPossessionVerifier::new()
            .verify_server_cert(
                end_entity,
                intermediates,
                &ServerName::try_from("localhost").unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    /// The certificate step on its own: an ML-DSA-87 certificate passes, an ECDSA one, a chain and bytes that are
    /// not a certificate do not.
    #[test]
    fn only_one_ml_dsa_87_certificate_passes_the_certificate_step() {
        assert!(check(&ours(), &[]));
        assert!(!check(&classical(), &[]), "an ECDSA certificate");
        assert!(!check(&ours(), &[ours()]), "a chain");
        assert!(
            !check(&CertificateDer::from(vec![0x30, 0x00]), &[]),
            "not a certificate"
        );
    }

    #[test]
    fn it_states_ml_dsa_87_alone() {
        assert_eq!(
            KeyPossessionVerifier::new().supported_verify_schemes(),
            vec![SignatureScheme::ML_DSA_87]
        );
    }
}
