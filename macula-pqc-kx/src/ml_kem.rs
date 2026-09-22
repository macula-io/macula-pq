//! ML-KEM as a rustls key exchange group, backed by `macula-mlkem`.
//!
//! Private to this crate on purpose: plain ML-KEM is not a hybrid, and
//! the only way it leaves this crate is as the post-quantum half of one.

use std::boxed::Box;
use std::vec::Vec;

use macula_mlkem::{ParameterSet, Zeroizing};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};

use crate::INVALID_KEY_SHARE;

// ⚠ NAMED STATICS, NOT `&MlKem { .. }` INLINE. A reference to an inline
// value in a static initializer points at a promoted constant, and Rust
// does not promise a promoted constant one address: copied into a hybrid's
// initializer, it was duplicated, and the test that checks by identity
// which ML-KEM a hybrid holds failed on the right object. A named static
// has exactly one address.
pub(crate) static ML_KEM_768: &dyn SupportedKxGroup = &ML_KEM_768_GROUP;
static ML_KEM_768_GROUP: MlKem = MlKem {
    set: macula_mlkem::ML_KEM_768,
    name: NamedGroup::MLKEM768,
};

pub(crate) static ML_KEM_1024: &dyn SupportedKxGroup = &ML_KEM_1024_GROUP;
static ML_KEM_1024_GROUP: MlKem = MlKem {
    set: macula_mlkem::ML_KEM_1024,
    name: NamedGroup::MLKEM1024,
};

#[derive(Debug)]
struct MlKem {
    set: ParameterSet,
    name: NamedGroup,
}

/// What each `macula-mlkem` error means on the wire. Exhaustive, so a new
/// error variant does not compile until it has a meaning here.
fn to_rustls(e: macula_mlkem::Error) -> Error {
    match e {
        macula_mlkem::Error::RandomnessUnavailable => Error::FailedToGetRandomBytes,
        // The peer's share: an encapsulation key failing the FIPS 203
        // section 7.2 check, or a share of the wrong length.
        macula_mlkem::Error::EncapsKeyInvalid | macula_mlkem::Error::WrongLength => {
            INVALID_KEY_SHARE
        }
        // Our own key, made moments ago by `key_gen`: not the peer's doing.
        macula_mlkem::Error::DecapsKeyInvalid => {
            Error::General("ML-KEM decapsulation key failed its own check".into())
        }
    }
}

impl SupportedKxGroup for MlKem {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (ek, dk) = macula_mlkem::key_gen(self.set).map_err(to_rustls)?;
        Ok(Box::new(ActiveMlKem {
            set: self.set,
            name: self.name,
            ek,
            dk,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (c, k) = macula_mlkem::encaps(self.set, client_share).map_err(to_rustls)?;
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: c,
            secret: SharedSecret::from(&k[..]),
        })
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    /// Not FIPS validated, and never claimed to be.
    fn fips(&self) -> bool {
        false
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveMlKem {
    set: ParameterSet,
    name: NamedGroup,
    ek: Vec<u8>,
    /// Wiped when the exchange completes or is abandoned.
    dk: Zeroizing<Vec<u8>>,
}

impl ActiveKeyExchange for ActiveMlKem {
    /// The peer's share is an ML-KEM ciphertext. A modified one yields
    /// FIPS 203's implicit-rejection secret, not an error, so the failure
    /// surfaces later as a handshake that cannot be authenticated.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let k = macula_mlkem::decaps(self.set, &self.dk, peer_pub_key).map_err(to_rustls)?;
        Ok(SharedSecret::from(&k[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.ek
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
    //! ⚠ DIFFERENTIAL, against `aws-lc-rs`'s ML-KEM through rustls: an
    //! independently written implementation of the same standard. A key
    //! exchange completes in both directions only if both implementations
    //! agree on every byte of the encapsulation key, the ciphertext and the
    //! shared secret.

    use rustls::crypto::aws_lc_rs::kx_group::{MLKEM1024 as THEIR_1024, MLKEM768 as THEIR_768};
    use rustls::crypto::SupportedKxGroup;
    use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

    use super::{to_rustls, ML_KEM_1024, ML_KEM_768};

    const PAIRS: [(&str, &dyn SupportedKxGroup, &dyn SupportedKxGroup); 2] = [
        ("ML-KEM-768", ML_KEM_768, THEIR_768),
        ("ML-KEM-1024", ML_KEM_1024, THEIR_1024),
    ];

    #[test]
    fn our_client_agrees_with_their_server() {
        for (set, ours, theirs) in PAIRS {
            let client = ours.start().unwrap();
            let server = theirs.start_and_complete(client.pub_key()).unwrap();
            let secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes(), "{set}");
        }
    }

    #[test]
    fn their_client_agrees_with_our_server() {
        for (set, ours, theirs) in PAIRS {
            let client = theirs.start().unwrap();
            let server = ours.start_and_complete(client.pub_key()).unwrap();
            let secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes(), "{set}");
        }
    }

    #[test]
    fn names_are_the_iana_code_points() {
        assert_eq!(ML_KEM_768.name(), NamedGroup::MLKEM768);
        assert_eq!(ML_KEM_1024.name(), NamedGroup::MLKEM1024);
        for (set, ours, theirs) in PAIRS {
            assert_eq!(ours.name(), theirs.name(), "{set}");
        }
    }

    #[test]
    fn usable_for_tls13_only() {
        for (set, ours, _) in PAIRS {
            assert!(ours.usable_for_version(ProtocolVersion::TLSv1_3), "{set}");
            assert!(!ours.usable_for_version(ProtocolVersion::TLSv1_2), "{set}");
        }
    }

    /// FIPS 203 section 7.2: an encapsulation key with a coefficient of `q`
    /// or more is refused. `0xff, 0x0f` puts 4095 in the first slot.
    #[test]
    fn a_client_share_failing_the_modulus_check_is_refused() {
        for (set, ours, _) in PAIRS {
            let mut share = ours.start().unwrap().pub_key().to_vec();
            share[0] = 0xff;
            share[1] |= 0x0f;
            assert_eq!(
                ours.start_and_complete(&share).err(),
                Some(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                "{set}"
            );
        }
    }

    #[test]
    fn shares_of_the_wrong_length_are_refused() {
        for (set, ours, _) in PAIRS {
            let share = ours.start().unwrap().pub_key().to_vec();
            assert!(
                ours.start_and_complete(&share[1..]).is_err(),
                "{set}: client share"
            );

            let client = ours.start().unwrap();
            let server = ours.start_and_complete(client.pub_key()).unwrap();
            assert!(
                client.complete(&server.pub_key[1..]).is_err(),
                "{set}: server share"
            );
        }
    }

    /// FIPS 203 implicit rejection, through the rustls interface: a
    /// modified ciphertext yields a secret, not an error, and not the
    /// server's.
    #[test]
    fn a_modified_server_share_completes_with_a_different_secret() {
        for (set, ours, _) in PAIRS {
            let client = ours.start().unwrap();
            let server = ours.start_and_complete(client.pub_key()).unwrap();
            let mut share = server.pub_key.clone();
            share[0] ^= 1;
            let secret = client.complete(&share).unwrap();
            assert_ne!(secret.secret_bytes(), server.secret.secret_bytes(), "{set}");
        }
    }

    /// Every `macula-mlkem` error has one rustls meaning. The match in
    /// `to_rustls` is exhaustive, so a new error variant is a compile
    /// error until someone decides what it means on the wire.
    #[test]
    fn errors_map_to_their_rustls_meaning() {
        use macula_mlkem::Error as E;
        let invalid = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
        assert_eq!(
            to_rustls(E::RandomnessUnavailable),
            Error::FailedToGetRandomBytes
        );
        assert_eq!(to_rustls(E::EncapsKeyInvalid), invalid);
        assert_eq!(to_rustls(E::WrongLength), invalid);
        assert!(matches!(to_rustls(E::DecapsKeyInvalid), Error::General(_)));
    }
}
