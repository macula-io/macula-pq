//! ML-DSA-87 in TLS: every handshake signature and certificate signature both builders make or check.
//!
//! - **Verification.** [`SIGNATURE_VERIFICATION_ALGORITHMS`] holds one algorithm, ML-DSA-87 (TLS scheme 0x0906,
//!   `id-ml-dsa-87` in certificates), checked by `macula-mldsa` under an empty context string, as the TLS and X.509
//!   profiles of ML-DSA require. It is the provider's list, so every verifier built on a configuration from this
//!   crate, rustls' own or a caller's, checks signatures with it and refuses anything classical.
//! - **Signing.** A private key reaches rustls through the provider's key loader, [`KeyLoader`], which takes an
//!   ML-DSA-87 PKCS#8 key (RFC 9881's `seed`, `expandedKey` or `both` form) and nothing else. Its signer signs with
//!   `macula-mldsa`, hedged, with randomness from the OS.
//! - **Certificates.** [`self_signed_certificate`] makes a self-signed ML-DSA-87 certificate and its PKCS#8 key from
//!   a seed, the form a macula node stores its TLS key in (D6, D12).

use std::fmt;
use std::sync::Arc;

use macula_mldsa::{PrivateKey, Zeroizing, ML_DSA_87};
use rustls::crypto::{KeyProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, CertificateDer, InvalidSignature, PrivateKeyDer,
    PrivatePkcs8KeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

/// `id-ml-dsa-87`, 2.16.840.1.101.3.4.3.19, as a DER OBJECT IDENTIFIER.
const ID_ML_DSA_87: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];

// ---------------------------------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct Mldsa87Verification;

impl SignatureVerificationAlgorithm for Mldsa87Verification {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match macula_mldsa::verify(ML_DSA_87, public_key, message, signature, &[]) {
            Ok(true) => Ok(()),
            _ => Err(InvalidSignature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ML_DSA_87
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ML_DSA_87
    }
}

static MLDSA87: &dyn SignatureVerificationAlgorithm = &Mldsa87Verification;

/// The signature algorithms both builders verify with: ML-DSA-87 alone, for certificates and for TLS 1.3
/// CertificateVerify.
pub(crate) static SIGNATURE_VERIFICATION_ALGORITHMS: WebPkiSupportedAlgorithms =
    WebPkiSupportedAlgorithms {
        all: &[MLDSA87],
        mapping: &[(SignatureScheme::ML_DSA_87, &[MLDSA87])],
    };

// ---------------------------------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------------------------------

/// An ML-DSA-87 private key, as its seed or in the expanded form, wiped when dropped.
enum Secret {
    Seed(Zeroizing<[u8; 32]>),
    Expanded(Zeroizing<Vec<u8>>),
}

impl Secret {
    fn private_key(&self) -> PrivateKey<'_> {
        match self {
            Secret::Seed(seed) => PrivateKey::Seed(seed),
            Secret::Expanded(expanded) => PrivateKey::Expanded(expanded),
        }
    }
}

/// An ML-DSA-87 signing key for rustls. Its secret is never printed.
struct Mldsa87Key {
    secret: Arc<Secret>,
    public: Vec<u8>,
}

impl fmt::Debug for Mldsa87Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mldsa87Key")
            .field("public_len", &self.public.len())
            .finish_non_exhaustive()
    }
}

impl Mldsa87Key {
    fn new(secret: Secret) -> Result<Mldsa87Key, Error> {
        let public =
            macula_mldsa::public_key(ML_DSA_87, secret.private_key()).map_err(key_error)?;
        Ok(Mldsa87Key {
            secret: Arc::new(secret),
            public,
        })
    }
}

impl SigningKey for Mldsa87Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ML_DSA_87)
            .then(|| Box::new(Mldsa87Signer(Arc::clone(&self.secret))) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(subject_public_key_info(
            &self.public,
        )))
    }

    /// ML-DSA has no TLS 1.2 SignatureAlgorithm, and rustls consults this only for TLS 1.2, which neither builder
    /// speaks. 0x09 is the high byte of its TLS 1.3 schemes.
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0x09)
    }
}

struct Mldsa87Signer(Arc<Secret>);

impl fmt::Debug for Mldsa87Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mldsa87Signer")
    }
}

impl Signer for Mldsa87Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        macula_mldsa::sign(ML_DSA_87, self.0.private_key(), message, &[])
            .map_err(|e| Error::General(format!("ML-DSA-87 signing failed: {e:?}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ML_DSA_87
    }
}

fn key_error(e: macula_mldsa::Error) -> Error {
    Error::General(format!("not a usable ML-DSA-87 private key: {e:?}"))
}

// ---------------------------------------------------------------------------------------------------------------------
// Loading a private key
// ---------------------------------------------------------------------------------------------------------------------

/// The provider's key loader: an ML-DSA-87 PKCS#8 key, and no other.
#[derive(Debug)]
pub(crate) struct KeyLoader;

impl KeyProvider for KeyLoader {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        match key_der {
            PrivateKeyDer::Pkcs8(pkcs8) => Ok(Arc::new(Mldsa87Key::new(secret_of(
                pkcs8.secret_pkcs8_der(),
            )?)?)),
            _ => Err(Error::General(
                "only an ML-DSA-87 PKCS#8 private key is accepted".into(),
            )),
        }
    }
}

/// The secret an ML-DSA-87 OneAsymmetricKey holds (RFC 5958, RFC 9881). Its privateKey is one of: the 32-byte seed
/// as `[0] IMPLICIT OCTET STRING`; the expanded key as an OCTET STRING; or both, a SEQUENCE of the two, which must
/// be the same key.
fn secret_of(pkcs8: &[u8]) -> Result<Secret, Error> {
    let malformed = || Error::General("not an ML-DSA-87 PKCS#8 private key".into());
    let (0x30, body, []) = tlv(pkcs8).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    let (0x02, version, rest) = tlv(body).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    if version != [0] && version != [1] {
        return Err(malformed());
    }
    let (0x30, algorithm, rest) = tlv(rest).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    if algorithm != ID_ML_DSA_87 {
        return Err(Error::General("the PKCS#8 key is not ML-DSA-87".into()));
    }
    let (0x04, private_key, _attributes_and_public_key) = tlv(rest).ok_or_else(malformed)? else {
        return Err(malformed());
    };
    match tlv(private_key).ok_or_else(malformed)? {
        (0x80, seed, []) => seed_secret(seed).ok_or_else(malformed),
        (0x04, expanded, []) => Ok(Secret::Expanded(Zeroizing::new(expanded.to_vec()))),
        (0x30, both, []) => both_secret(both).ok_or_else(malformed)?,
        _ => Err(malformed()),
    }
}

fn seed_secret(seed: &[u8]) -> Option<Secret> {
    let seed: [u8; 32] = seed.try_into().ok()?;
    Some(Secret::Seed(Zeroizing::new(seed)))
}

/// The `both` form: the seed is kept, once the expanded key is shown to be the same key.
fn both_secret(both: &[u8]) -> Option<Result<Secret, Error>> {
    let (0x04, seed, rest) = tlv(both)? else {
        return None;
    };
    let (0x04, expanded, []) = tlv(rest)? else {
        return None;
    };
    let seeded = seed_secret(seed)?;
    let from_seed = macula_mldsa::public_key(ML_DSA_87, seeded.private_key()).ok()?;
    let from_expanded = macula_mldsa::public_key(ML_DSA_87, PrivateKey::Expanded(expanded)).ok()?;
    Some(if from_seed == from_expanded {
        Ok(seeded)
    } else {
        Err(Error::General(
            "the PKCS#8 key's seed and expanded key are different keys".into(),
        ))
    })
}

/// One DER TLV with a one-byte tag: the tag, its contents and what follows. Lengths up to 2^32 - 1.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7F => (usize::from(first), rest),
        0x81..=0x84 => {
            let n = usize::from(first & 0x7F);
            let (bytes, rest) = rest.split_at_checked(n)?;
            (
                bytes
                    .iter()
                    .fold(0usize, |acc, &b| (acc << 8) | usize::from(b)),
                rest,
            )
        }
        _ => return None,
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

// ---------------------------------------------------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------------------------------------------------

fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    match len {
        0..=0x7F => out.push(len as u8),
        0x80..=0xFF => out.extend([0x81, len as u8]),
        _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

/// SubjectPublicKeyInfo for an ML-DSA-87 public key: the algorithm with no parameters (RFC 9881), then the key as a
/// BIT STRING.
fn subject_public_key_info(public: &[u8]) -> Vec<u8> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(public);
    der(0x30, &[der(0x30, ID_ML_DSA_87), der(0x03, &bits)].concat())
}

/// Whether a SubjectPublicKeyInfo is an ML-DSA-87 key: exactly the encoding [`subject_public_key_info`] gives the
/// key it ends with, so the algorithm, its absent parameters and the key's length must all be ML-DSA-87's.
pub(crate) fn is_ml_dsa_87_key(spki: &[u8]) -> bool {
    let key_len = ML_DSA_87.public_key_len();
    spki.len() > key_len && subject_public_key_info(&spki[spki.len() - key_len..]) == spki
}

/// The PKCS#8 OneAsymmetricKey for a seed, in RFC 9881's `seed` form.
fn pkcs8_of_seed(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let private_key = Zeroizing::new(der(0x80, seed));
    let octets = Zeroizing::new(der(0x04, &private_key));
    Zeroizing::new(der(
        0x30,
        &[&[0x02, 0x01, 0x00][..], &der(0x30, ID_ML_DSA_87), &octets].concat(),
    ))
}

// ---------------------------------------------------------------------------------------------------------------------
// A self-signed certificate
// ---------------------------------------------------------------------------------------------------------------------

/// A self-signed ML-DSA-87 certificate for the key a seed derives, naming `subject_alt_names`, and the key as PKCS#8
/// for [`crate::server_builder`]'s `with_single_cert`. The certificate's signature is `macula-mldsa`'s.
pub fn self_signed_certificate(
    seed: &[u8; 32],
    subject_alt_names: Vec<String>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Error> {
    let key = Mldsa87Key::new(Secret::Seed(Zeroizing::new(*seed)))?;
    let params = rcgen::CertificateParams::new(subject_alt_names)
        .map_err(|e| Error::General(format!("certificate names: {e}")))?;
    let certificate = params
        .self_signed(&CertificateSigner(&key))
        .map_err(|e| Error::General(format!("self-signing the certificate: {e}")))?;
    let pkcs8 = pkcs8_of_seed(seed);
    Ok((
        certificate.der().clone(),
        PrivatePkcs8KeyDer::from(pkcs8.to_vec()).into(),
    ))
}

/// The key rcgen signs a certificate's tbsCertificate with.
struct CertificateSigner<'k>(&'k Mldsa87Key);

impl rcgen::PublicKeyData for CertificateSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.0.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ML_DSA_87
    }
}

impl rcgen::SigningKey for CertificateSigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        macula_mldsa::sign(ML_DSA_87, self.0.secret.private_key(), message, &[])
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];

    fn key() -> Mldsa87Key {
        Mldsa87Key::new(Secret::Seed(Zeroizing::new(SEED))).unwrap()
    }

    /// OTP's `public_key` writes ML-DSA private keys in these three forms; each is built here the way RFC 9881 lays
    /// it out, independently of `pkcs8_of_seed`.
    fn pkcs8(private_key: &[u8]) -> Vec<u8> {
        der(
            0x30,
            &[
                &[0x02, 0x01, 0x00][..],
                &der(0x30, ID_ML_DSA_87),
                &der(0x04, private_key),
            ]
            .concat(),
        )
    }

    fn expanded() -> Vec<u8> {
        let (_, expanded) = macula_mldsa::key_gen(ML_DSA_87).unwrap();
        expanded.to_vec()
    }

    #[test]
    fn a_signature_verifies_with_the_algorithm_and_not_when_changed() {
        let key = key();
        let signer = key.choose_scheme(&[SignatureScheme::ML_DSA_87]).unwrap();
        let signature = signer.sign(b"transcript").unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ML_DSA_87);
        assert!(MLDSA87
            .verify_signature(&key.public, b"transcript", &signature)
            .is_ok());
        assert!(MLDSA87
            .verify_signature(&key.public, b"transcripT", &signature)
            .is_err());
        let mut changed = signature.clone();
        changed[100] ^= 1;
        assert!(MLDSA87
            .verify_signature(&key.public, b"transcript", &changed)
            .is_err());
    }

    /// A peer that offers no ML-DSA-87 gets no signer, so the handshake fails rather than signing classically.
    #[test]
    fn no_signer_unless_ml_dsa_87_is_offered() {
        let key = key();
        assert!(key
            .choose_scheme(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP384_SHA384
            ])
            .is_none());
        assert!(key.choose_scheme(&[SignatureScheme::ML_DSA_65]).is_none());
    }

    /// The SPKI: SEQUENCE { SEQUENCE { id-ml-dsa-87 }, BIT STRING { 0 unused bits, the 2,592-byte key } }.
    #[test]
    fn the_public_key_is_the_rfc_9881_subject_public_key_info() {
        let key = key();
        let spki = key.public_key().unwrap();
        let (0x30, body, []) = tlv(spki.as_ref()).unwrap() else {
            panic!("outer")
        };
        let (0x30, algorithm, rest) = tlv(body).unwrap() else {
            panic!("algorithm")
        };
        assert_eq!(algorithm, ID_ML_DSA_87);
        let (0x03, bits, []) = tlv(rest).unwrap() else {
            panic!("bit string")
        };
        assert_eq!(bits[0], 0);
        assert_eq!(&bits[1..], &key.public[..]);
        assert_eq!(key.public.len(), 2592);
    }

    #[test]
    fn the_loader_takes_all_three_pkcs8_forms() {
        let (public, expanded) = macula_mldsa::internal::key_gen(ML_DSA_87, &SEED);
        for form in [
            der(0x80, &SEED),
            der(0x04, &expanded),
            der(0x30, &[der(0x04, &SEED), der(0x04, &expanded)].concat()),
        ] {
            let loaded = KeyLoader
                .load_private_key(PrivatePkcs8KeyDer::from(pkcs8(&form)).into())
                .unwrap();
            assert_eq!(
                loaded.public_key().unwrap().as_ref(),
                subject_public_key_info(&public).as_slice()
            );
        }
        let Secret::Expanded(held) = secret_of(&pkcs8(&der(0x04, &expanded))).unwrap() else {
            panic!("the expanded form did not load as the expanded key")
        };
        assert_eq!(held.as_slice(), expanded.as_slice());
    }

    /// `both` must hold one key: a seed with another key's expanded form is refused.
    #[test]
    fn the_loader_refuses_both_forms_of_different_keys() {
        let both = der(0x30, &[der(0x04, &SEED), der(0x04, &expanded())].concat());
        assert!(KeyLoader
            .load_private_key(PrivatePkcs8KeyDer::from(pkcs8(&both)).into())
            .is_err());
    }

    #[test]
    fn the_loader_refuses_other_keys_and_malformed_ones() {
        let ed25519_oid: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
        let ed25519 = der(
            0x30,
            &[
                &[0x02, 0x01, 0x00][..],
                &der(0x30, ed25519_oid),
                &der(0x04, &der(0x04, &[1; 32])),
            ]
            .concat(),
        );
        for bad in [
            ed25519,
            pkcs8(&der(0x80, &[7; 31])),
            pkcs8(&der(0x81, &SEED)),
            vec![0x30, 0x00],
            vec![],
        ] {
            assert!(
                KeyLoader
                    .load_private_key(PrivatePkcs8KeyDer::from(bad.clone()).into())
                    .is_err(),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn the_seed_form_round_trips_through_the_loader() {
        let loaded = KeyLoader
            .load_private_key(PrivatePkcs8KeyDer::from(pkcs8_of_seed(&SEED).to_vec()).into())
            .unwrap();
        assert_eq!(
            loaded.public_key().unwrap().as_ref(),
            key().public_key().unwrap().as_ref()
        );
    }

    #[test]
    fn a_self_signed_certificate_carries_the_seeds_key() {
        let (certificate, private_key) =
            self_signed_certificate(&SEED, vec!["localhost".into()]).unwrap();
        let spki = subject_public_key_info(&key().public);
        let found = certificate
            .as_ref()
            .windows(spki.len())
            .any(|w| w == spki.as_slice());
        assert!(
            found,
            "the certificate does not carry the seed's SubjectPublicKeyInfo"
        );
        let loaded = KeyLoader.load_private_key(private_key).unwrap();
        assert_eq!(loaded.public_key().unwrap().as_ref(), spki.as_slice());
    }

    #[test]
    fn debug_output_holds_no_secret() {
        let shown = format!(
            "{:?} {:?}",
            key(),
            Mldsa87Signer(Arc::new(Secret::Seed(Zeroizing::new(SEED))))
        );
        assert!(!shown.contains("7, 7, 7"), "{shown}");
    }
}
