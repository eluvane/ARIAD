#![forbid(unsafe_code)]

use std::sync::Arc;

use ariad_core::EngineError;

use crate::tls_policy::MAX_CERTIFICATE_DER_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchState {
    Unsupported,
}

/// A caller-reported peer-check outcome. Constructing a verdict does not verify a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVerdict {
    Verified,
    NameMismatch,
    Expired,
    UntrustedChain,
    PinMismatch,
}

/// Map a supplied verdict to credential eligibility without performing peer checks.
pub fn may_present_credential(verdict: TrustVerdict) -> bool {
    match verdict {
        TrustVerdict::Verified => true,
        TrustVerdict::NameMismatch
        | TrustVerdict::Expired
        | TrustVerdict::UntrustedChain
        | TrustVerdict::PinMismatch => false,
    }
}

/// Accept a reported `Verified` verdict; reject all other outcomes as identity failures.
/// The caller is responsible for obtaining the verdict from the required peer checks.
pub fn credential_gate(verdict: TrustVerdict) -> Result<(), ariad_core::EngineError> {
    if may_present_credential(verdict) {
        Ok(())
    } else {
        Err(ariad_core::EngineError::PeerIdentityFailed)
    }
}

/// Expected SHA-256 digest of a leaf certificate's DER SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpkiPin([u8; 32]);

impl SpkiPin {
    pub const fn from_bytes(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    /// Hash the supplied SPKI bytes without parsing or validating their DER encoding.
    pub fn from_spki_der(spki: &[u8]) -> Result<Self, EngineError> {
        #[cfg(feature = "tls-rustls")]
        let digest = rustls_policy::sha256(spki).map_err(|_| EngineError::InvalidConfig)?;
        #[cfg(all(feature = "tls-boring", not(feature = "tls-rustls")))]
        let digest = boring::sha::sha256(spki);
        Ok(Self(digest))
    }

    #[cfg(feature = "tls-rustls")]
    /// Parse the certificate and hash its SPKI. This does not establish peer trust.
    pub fn from_certificate(
        certificate: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<Self, EngineError> {
        let parsed_certificate = rustls::server::ParsedCertificate::try_from(certificate)
            .map_err(|_| EngineError::InvalidConfig)?;
        Self::from_spki_der(parsed_certificate.subject_public_key_info().as_ref())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Host-selected trust roots and optional restrictions on leaf public keys.
/// Pins add requirements to certificate-chain, validity and hostname checks.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    trust_group: u64,
    #[cfg(feature = "tls-rustls")]
    roots: Arc<rustls::RootCertStore>,
    roots_der: Option<Arc<Vec<Vec<u8>>>>,
    pins: Vec<SpkiPin>,
}

impl TrustPolicy {
    /// Maximum bytes in one DER root certificate.
    pub const MAX_ROOT_CERTIFICATE_BYTES: usize = MAX_CERTIFICATE_DER_BYTES;

    #[cfg(feature = "tls-rustls")]
    /// Create a rustls policy from a nonempty root store.
    /// Native backends need original CA DER from [`Self::from_der_roots`].
    pub fn new(trust_group: u64, roots: rustls::RootCertStore) -> Result<Self, EngineError> {
        if roots.is_empty() {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self {
            trust_group,
            roots: Arc::new(roots),
            roots_der: None,
            pins: Vec::new(),
        })
    }

    /// Build a policy from 1 to 64 DER root certificates and retain their original bytes.
    ///
    /// Each certificate must be nonempty and fit [`Self::MAX_ROOT_CERTIFICATE_BYTES`].
    /// More than 256 KiB in total returns `ResourceLimitExceeded`. Invalid counts
    /// or individual lengths return `InvalidConfig`.
    pub fn from_der_roots(
        trust_group: u64,
        certificates: Vec<Vec<u8>>,
    ) -> Result<Self, EngineError> {
        if certificates.is_empty() || certificates.len() > 64 {
            return Err(EngineError::InvalidConfig);
        }
        let root_bytes = certificates
            .iter()
            .try_fold(0usize, |root_bytes, certificate| {
                if certificate.is_empty() || certificate.len() > Self::MAX_ROOT_CERTIFICATE_BYTES {
                    return Err(EngineError::InvalidConfig);
                }
                root_bytes
                    .checked_add(certificate.len())
                    .ok_or(EngineError::ResourceLimitExceeded)
            })?;
        if root_bytes > 256 * 1024 {
            return Err(EngineError::ResourceLimitExceeded);
        }
        #[cfg(feature = "tls-rustls")]
        let roots = {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in &certificates {
                roots
                    .add(rustls::pki_types::CertificateDer::from(
                        certificate.as_slice(),
                    ))
                    .map_err(|_| EngineError::InvalidConfig)?;
            }
            Arc::new(roots)
        };
        #[cfg(all(feature = "tls-boring", not(feature = "tls-rustls")))]
        for certificate in &certificates {
            let _certificate = boring::x509::X509::from_der(certificate)
                .map_err(|_| EngineError::InvalidConfig)?;
        }
        Ok(Self {
            trust_group,
            #[cfg(feature = "tls-rustls")]
            roots,
            roots_der: Some(Arc::new(certificates)),
            pins: Vec::new(),
        })
    }

    /// Replace the permitted leaf-SPKI digests with 1 to 8 distinct pins.
    /// A leaf must match one pin in addition to passing chain, validity and name checks.
    pub fn with_spki_pins(mut self, pins: Vec<SpkiPin>) -> Result<Self, EngineError> {
        if pins.is_empty() || pins.len() > 8 {
            return Err(EngineError::InvalidConfig);
        }
        for (index, pin) in pins.iter().enumerate() {
            if pins[..index].contains(pin) {
                return Err(EngineError::InvalidConfig);
            }
        }
        self.pins = pins;
        Ok(self)
    }

    pub const fn trust_group(&self) -> u64 {
        self.trust_group
    }

    /// Original DER roots, or `None` when created from a rustls root store.
    pub fn certificate_roots_der(&self) -> Option<&[Vec<u8>]> {
        self.roots_der.as_deref().map(Vec::as_slice)
    }

    /// Permitted leaf-SPKI digests. An empty slice adds no pin restriction.
    pub fn spki_pins(&self) -> &[SpkiPin] {
        &self.pins
    }
}

#[cfg(feature = "tls-rustls")]
mod rustls_policy {
    use std::sync::Arc;

    use ariad_core::EngineError;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::crypto::hash::HashAlgorithm;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::ParsedCertificate;
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

    use super::{SpkiPin, TrustPolicy};
    use crate::tls_policy::{H2_ALPN, RUSTLS_TLS_VERSION};

    impl TrustPolicy {
        pub(crate) fn client_config(self) -> Result<ClientConfig, EngineError> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let chain_verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::clone(&self.roots),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|_| EngineError::InvalidConfig)?;
            let pinned_verifier = Arc::new(PinnedVerifier {
                verifier: chain_verifier,
                pins: self.pins,
            });
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[RUSTLS_TLS_VERSION])
                .map_err(|_| EngineError::InvalidConfig)?
                .dangerous()
                .with_custom_certificate_verifier(pinned_verifier)
                .with_no_client_auth();
            config.alpn_protocols = vec![H2_ALPN.to_vec()];
            config.enable_early_data = false;
            config.resumption = rustls::client::Resumption::disabled();
            config.enable_secret_extraction = false;
            Ok(config)
        }
    }

    #[derive(Debug)]
    struct PinnedVerifier {
        verifier: Arc<WebPkiServerVerifier>,
        pins: Vec<SpkiPin>,
    }

    impl ServerCertVerifier for PinnedVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            // A matching pin cannot replace chain, validity or hostname verification.
            let chain_and_name_verified = self.verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
            if !self.pins.is_empty() {
                let certificate = ParsedCertificate::try_from(end_entity)?;
                let spki_digest = sha256(certificate.subject_public_key_info().as_ref())?;
                if !self.pins.contains(&SpkiPin(spki_digest)) {
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
            }
            Ok(chain_and_name_verified)
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verifier
                .verify_tls12_signature(message, certificate, signature)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verifier
                .verify_tls13_signature(message, certificate, signature)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.verifier.supported_verify_schemes()
        }
    }

    pub(super) fn sha256(bytes: &[u8]) -> Result<[u8; 32], rustls::Error> {
        let provider: CryptoProvider = rustls::crypto::ring::default_provider();
        let sha256_provider = provider
            .cipher_suites
            .iter()
            .filter_map(|suite| suite.tls13())
            .map(|suite| suite.common.hash_provider)
            .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)
            .ok_or_else(|| rustls::Error::General("SHA256 unavailable".into()))?;
        sha256_provider
            .hash(bytes)
            .as_ref()
            .try_into()
            .map_err(|_| rustls::Error::General("invalid SHA256 output".into()))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "tls-rustls")]
    use super::SpkiPin;
    use super::{TrustPolicy, TrustVerdict, credential_gate, may_present_credential};
    use ariad_core::EngineError;

    #[test]
    fn verified_presents_credential() {
        assert!(may_present_credential(TrustVerdict::Verified));
        assert_eq!(credential_gate(TrustVerdict::Verified), Ok(()));
    }

    #[test]
    fn identity_failures_block_credential() {
        for verdict in [
            TrustVerdict::NameMismatch,
            TrustVerdict::Expired,
            TrustVerdict::UntrustedChain,
            TrustVerdict::PinMismatch,
        ] {
            assert!(!may_present_credential(verdict), "{verdict:?}");
            assert_eq!(
                credential_gate(verdict),
                Err(EngineError::PeerIdentityFailed),
                "{verdict:?}"
            );
        }
    }

    #[test]
    fn der_roots_are_bounded_before_parsing() {
        assert!(matches!(
            TrustPolicy::from_der_roots(1, Vec::new()),
            Err(EngineError::InvalidConfig)
        ));
        assert!(matches!(
            TrustPolicy::from_der_roots(1, vec![vec![1]; 65]),
            Err(EngineError::InvalidConfig)
        ));
        assert!(matches!(
            TrustPolicy::from_der_roots(
                1,
                vec![vec![1; TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES + 1]],
            ),
            Err(EngineError::InvalidConfig)
        ));
        assert!(matches!(
            TrustPolicy::from_der_roots(
                1,
                vec![vec![1; TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES]; 17],
            ),
            Err(EngineError::ResourceLimitExceeded)
        ));
    }

    #[cfg(feature = "tls-rustls")]
    #[test]
    fn empty_roots_and_invalid_pin_rotation_are_rejected() {
        assert!(matches!(
            TrustPolicy::new(1, rustls::RootCertStore::empty()),
            Err(EngineError::InvalidConfig)
        ));
        let certificate = rcgen::generate_simple_self_signed(vec!["endpoint.test".into()]).unwrap();
        let policy = TrustPolicy::from_der_roots(1, vec![certificate.cert.der().to_vec()]).unwrap();
        let pin = SpkiPin::from_certificate(certificate.cert.der()).unwrap();
        for pins in [Vec::new(), vec![pin, pin], vec![pin; 9]] {
            assert!(matches!(
                policy.clone().with_spki_pins(pins),
                Err(EngineError::InvalidConfig)
            ));
        }
        assert_eq!(
            policy
                .with_spki_pins(vec![pin, SpkiPin::from_bytes([0x11; 32])])
                .unwrap()
                .spki_pins()
                .len(),
            2
        );
    }
}
