#![forbid(unsafe_code)]

use std::error::Error as StdError;
#[cfg(feature = "h3")]
use std::net::IpAddr;
use std::net::SocketAddr;

use ariad_core::{BindingId, EndpointDescriptor, EngineError};
use boring::pkey::{PKey, Private};
use boring::ssl::{
    AlpnError, ErrorCode, SslAcceptor, SslConnector, SslContextBuilder, SslMethod, SslRef,
    SslSessionCacheMode, SslVerifyMode, select_next_proto,
};
use boring::x509::store::X509StoreBuilder;
#[cfg(feature = "h3")]
use boring::x509::verify::X509CheckFlags;
use boring::x509::{X509, X509Ref, X509VerifyError};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::Deadline;
#[cfg(feature = "h3")]
use crate::tls_policy::H3_ALPN;
use crate::tls_policy::{
    H2_ALPN, H2_ALPN_OFFER, MAX_CERTIFICATE_DER_BYTES, NATIVE_TLS_VERSION,
    native_negotiation_matches,
};
use crate::trust::{EchState, TrustPolicy};

/// BoringSSL peer verification for one configured trust group.
#[derive(Clone)]
pub struct NativeTlsConnector {
    connector: SslConnector,
    policy: TrustPolicy,
}

/// TLS 1.3 with h2 ALPN after chain, validity, hostname and configured pin checks.
pub struct NativeVerifiedTlsChannel {
    io: SslStream<TcpStream>,
    endpoint: EndpointDescriptor,
    address: SocketAddr,
}

impl NativeTlsConnector {
    /// Build an H2 client configuration from the policy's original DER roots.
    /// Missing original roots return `UnsupportedCapability`.
    pub fn new(policy: TrustPolicy) -> Result<Self, EngineError> {
        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(|_| EngineError::InvalidConfig)?;
        configure_client(&mut builder, &policy)?;
        builder
            .set_alpn_protos(&H2_ALPN_OFFER)
            .map_err(|_| EngineError::InvalidConfig)?;
        Ok(Self {
            connector: builder.build(),
            policy,
        })
    }

    pub const fn trust_group(&self) -> u64 {
        self.policy.trust_group()
    }

    /// Complete TLS 1.3 with h2 ALPN on an already connected TCP stream.
    ///
    /// The TCP peer must equal `address`. The endpoint supplies the identity name
    /// and must permit H2 under this trust group. The deadline covers the TLS
    /// handshake; H2 startup runs separately after the verified stream is returned.
    pub async fn connect(
        &self,
        endpoint: &EndpointDescriptor,
        io: TcpStream,
        address: SocketAddr,
        deadline: Deadline,
    ) -> Result<NativeVerifiedTlsChannel, EngineError> {
        self.validate_endpoint(endpoint, BindingId::H2)?;
        if address.port() == 0 || io.peer_addr().ok() != Some(address) {
            return Err(EngineError::InvalidConfig);
        }
        let tls_config = self
            .connector
            .configure()
            .map_err(|_| EngineError::InvalidConfig)?;
        let tls = deadline
            .run(async {
                tokio_boring::connect(tls_config, &endpoint.identity_hostname, io)
                    .await
                    .map_err(|error| classify_handshake_error(&error))
            })
            .await?;
        self.verify_peer(tls.ssl(), H2_ALPN)?;
        deadline.remaining()?;
        Ok(NativeVerifiedTlsChannel {
            io: tls,
            endpoint: endpoint.clone(),
            address,
        })
    }

    pub(crate) fn validate_endpoint(
        &self,
        endpoint: &EndpointDescriptor,
        binding: BindingId,
    ) -> Result<(), EngineError> {
        endpoint.validate()?;
        if !endpoint.permits_credential_group(self.policy.trust_group()) {
            return Err(EngineError::PeerIdentityFailed);
        }
        if endpoint.ech_required || !endpoint.permits_binding(binding) {
            return Err(EngineError::UnsupportedCapability);
        }
        Ok(())
    }

    fn verify_peer(&self, ssl: &SslRef, expected_alpn: &[u8]) -> Result<(), EngineError> {
        if !native_negotiation_matches(ssl, expected_alpn) {
            return Err(EngineError::UnsupportedCapability);
        }
        // Handshake chain and name checks must succeed before pins can admit the leaf.
        if ssl.verify_result().is_err() {
            return Err(EngineError::PeerIdentityFailed);
        }
        let certificate = ssl
            .peer_certificate()
            .ok_or(EngineError::PeerIdentityFailed)?;
        if !self.policy.spki_pins().is_empty() {
            let spki_digest = certificate_spki_digest(&certificate)?;
            if !self
                .policy
                .spki_pins()
                .iter()
                .any(|pin| boring::memcmp::eq(pin.as_bytes(), &spki_digest))
            {
                return Err(EngineError::PeerIdentityFailed);
            }
        }
        Ok(())
    }

    #[cfg(feature = "h3")]
    pub(crate) fn quiche_config(&self) -> Result<quiche::Config, EngineError> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(|_| EngineError::InvalidConfig)?;
        configure_client(&mut builder, &self.policy)?;
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
                .map_err(|_| EngineError::InvalidConfig)?;
        config.verify_peer(true);
        Ok(config)
    }

    #[cfg(feature = "h3")]
    pub(crate) fn verify_quiche<F: quiche::BufFactory>(
        &self,
        connection: &mut quiche::Connection<F>,
    ) -> Result<(), EngineError> {
        if !connection.is_established() || connection.is_in_early_data() {
            return Err(EngineError::PeerIdentityFailed);
        }
        self.verify_peer(connection.as_mut(), H3_ALPN)
    }

    #[cfg(feature = "h3")]
    pub(crate) fn configure_quiche_identity<F: quiche::BufFactory>(
        &self,
        connection: &mut quiche::Connection<F>,
        endpoint: &EndpointDescriptor,
    ) -> Result<(), EngineError> {
        // quiche sets DNS names. Match SslConnector's IP and wildcard checks.
        let ssl: &mut SslRef = connection.as_mut();
        let parameters = ssl.verify_param_mut();
        parameters.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        if let Ok(ip) = endpoint.identity_hostname.parse::<IpAddr>() {
            parameters
                .set_ip(ip)
                .map_err(|_| EngineError::InvalidConfig)?;
        }
        Ok(())
    }
}

fn certificate_spki_digest(certificate: &X509Ref) -> Result<[u8; 32], EngineError> {
    // BoringSSL retains the original TBS bytes. Exporting the decoded EC key
    // replaces compressed points and changes the SPKI digest.
    let certificate_der = certificate
        .to_der()
        .map_err(|_| EngineError::PeerIdentityFailed)?;
    let spki_der =
        encoded_certificate_spki(&certificate_der).ok_or(EngineError::PeerIdentityFailed)?;
    Ok(boring::sha::sha256(spki_der))
}

fn encoded_certificate_spki(certificate_der: &[u8]) -> Option<&[u8]> {
    // The caller has validated X509. This function only reads field boundaries.
    let mut input = certificate_der;
    let (_, mut certificate) = take_der_element(&mut input, 0x30)?;
    if !input.is_empty() {
        return None;
    }
    let (_, mut tbs) = take_der_element(&mut certificate, 0x30)?;
    if tbs.first() == Some(&0xa0) {
        take_der_element(&mut tbs, 0xa0)?;
    }
    // Serial number, signature, issuer, validity and subject precede SPKI.
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        take_der_element(&mut tbs, tag)?;
    }
    let (spki, _) = take_der_element(&mut tbs, 0x30)?;
    Some(spki)
}

fn take_der_element<'a>(input: &mut &'a [u8], tag: u8) -> Option<(&'a [u8], &'a [u8])> {
    let encoded = *input;
    if encoded.first() != Some(&tag) {
        return None;
    }
    let first_length = *encoded.get(1)?;
    let (header_bytes, content_bytes) = if first_length & 0x80 == 0 {
        (2, usize::from(first_length))
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
            return None;
        }
        let length = encoded.get(2..2 + length_bytes)?;
        if length.first() == Some(&0) {
            return None;
        }
        let content_bytes = length.iter().try_fold(0usize, |total, byte| {
            total.checked_mul(256)?.checked_add(usize::from(*byte))
        })?;
        if content_bytes < 128 {
            return None;
        }
        (2 + length_bytes, content_bytes)
    };
    let end = header_bytes.checked_add(content_bytes)?;
    let element = encoded.get(..end)?;
    let content = encoded.get(header_bytes..end)?;
    *input = encoded.get(end..)?;
    Some((element, content))
}

impl NativeVerifiedTlsChannel {
    pub fn endpoint(&self) -> &EndpointDescriptor {
        &self.endpoint
    }

    pub const fn endpoint_id(&self) -> u64 {
        self.endpoint.id
    }

    pub const fn trust_group(&self) -> u64 {
        self.endpoint.trust_group
    }

    pub const fn binding(&self) -> BindingId {
        BindingId::H2
    }

    pub const fn ech(&self) -> EchState {
        EchState::Unsupported
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Transfer the TLS stream to the caller. H2 startup has not yet run.
    pub fn into_io(self) -> SslStream<TcpStream> {
        self.io
    }
}

/// Server identity and TLS 1.3 configuration for native H2 and H3 transports.
#[derive(Clone)]
pub struct NativeTlsServer {
    acceptor: SslAcceptor,
    #[cfg(feature = "h3")]
    certificates: Vec<X509>,
    #[cfg(feature = "h3")]
    key: PKey<Private>,
}

impl NativeTlsServer {
    /// Build a server from a leaf-first DER certificate chain and a matching private key.
    ///
    /// The chain must have 1 to 8 nonempty certificates, each within
    /// [`TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES`] and at most 128 KiB in total.
    /// The DER key must be nonempty and at most 64 KiB.
    /// Invalid lengths, malformed DER or a mismatched key return `InvalidConfig`.
    pub fn from_der(
        certificate_chain: &[Vec<u8>],
        private_key_der: &[u8],
    ) -> Result<Self, EngineError> {
        if certificate_chain.is_empty()
            || certificate_chain.len() > 8
            || private_key_der.is_empty()
            || private_key_der.len() > 64 * 1024
        {
            return Err(EngineError::InvalidConfig);
        }
        let mut chain_bytes = 0usize;
        let mut certificates = Vec::new();
        for certificate_der in certificate_chain {
            chain_bytes = chain_bytes
                .checked_add(certificate_der.len())
                .ok_or(EngineError::InvalidConfig)?;
            if certificate_der.is_empty()
                || certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
                || chain_bytes > 128 * 1024
            {
                return Err(EngineError::InvalidConfig);
            }
            certificates
                .push(X509::from_der(certificate_der).map_err(|_| EngineError::InvalidConfig)?);
        }
        let key =
            PKey::private_key_from_der(private_key_der).map_err(|_| EngineError::InvalidConfig)?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|_| EngineError::InvalidConfig)?;
        configure_server(&mut builder, &certificates, &key)?;
        builder.set_alpn_select_callback(|_, offered| {
            select_next_proto(&H2_ALPN_OFFER, offered).ok_or(AlpnError::ALERT_FATAL)
        });
        Ok(Self {
            acceptor: builder.build(),
            #[cfg(feature = "h3")]
            certificates,
            #[cfg(feature = "h3")]
            key,
        })
    }

    /// Complete a server TLS 1.3 handshake with h2 ALPN by the deadline.
    /// A completed handshake with a different version or ALPN returns `ProtocolViolation`.
    pub async fn accept(
        &self,
        io: TcpStream,
        deadline: Deadline,
    ) -> Result<SslStream<TcpStream>, EngineError> {
        let tls = deadline
            .run(async {
                tokio_boring::accept(&self.acceptor, io)
                    .await
                    .map_err(|_| EngineError::TransportUnavailable)
            })
            .await?;
        if !native_negotiation_matches(tls.ssl(), H2_ALPN) {
            return Err(EngineError::ProtocolViolation);
        }
        deadline.remaining()?;
        Ok(tls)
    }

    #[cfg(feature = "h3")]
    pub(crate) fn quiche_config(&self) -> Result<quiche::Config, EngineError> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(|_| EngineError::InvalidConfig)?;
        configure_server(&mut builder, &self.certificates, &self.key)?;
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
            .map_err(|_| EngineError::InvalidConfig)
    }
}

fn configure_client(
    builder: &mut SslContextBuilder,
    policy: &TrustPolicy,
) -> Result<(), EngineError> {
    let root_certificates_der = policy
        .certificate_roots_der()
        .ok_or(EngineError::UnsupportedCapability)?;
    let mut store = X509StoreBuilder::new().map_err(|_| EngineError::InvalidConfig)?;
    for certificate_der in root_certificates_der {
        let certificate =
            X509::from_der(certificate_der).map_err(|_| EngineError::InvalidConfig)?;
        store
            .add_cert(&certificate)
            .map_err(|_| EngineError::InvalidConfig)?;
    }
    builder.set_cert_store_builder(store);
    builder.set_verify(SslVerifyMode::PEER);
    configure_tls13(builder)
}

fn configure_server(
    builder: &mut SslContextBuilder,
    certificates: &[X509],
    key: &PKey<Private>,
) -> Result<(), EngineError> {
    configure_tls13(builder)?;
    let leaf = certificates.first().ok_or(EngineError::InvalidConfig)?;
    builder
        .set_certificate(leaf)
        .map_err(|_| EngineError::InvalidConfig)?;
    for certificate in &certificates[1..] {
        builder
            .add_extra_chain_cert(certificate.clone())
            .map_err(|_| EngineError::InvalidConfig)?;
    }
    builder
        .set_private_key(key)
        .map_err(|_| EngineError::InvalidConfig)?;
    builder
        .check_private_key()
        .map_err(|_| EngineError::InvalidConfig)
}

fn configure_tls13(builder: &mut SslContextBuilder) -> Result<(), EngineError> {
    builder
        .set_min_proto_version(Some(NATIVE_TLS_VERSION))
        .map_err(|_| EngineError::InvalidConfig)?;
    builder
        .set_max_proto_version(Some(NATIVE_TLS_VERSION))
        .map_err(|_| EngineError::InvalidConfig)?;
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    Ok(())
}

fn classify_handshake_error<S: std::fmt::Debug>(
    error: &tokio_boring::HandshakeError<S>,
) -> EngineError {
    // INVALID_CALL is returned before a verification session exists.
    if error.ssl().is_some_and(|ssl| {
        ssl.verify_result()
            .is_err_and(|error| error != X509VerifyError::INVALID_CALL)
    }) {
        EngineError::PeerIdentityFailed
    } else if error
        .source()
        .and_then(|source| source.downcast_ref::<boring::ssl::Error>())
        .and_then(boring::ssl::Error::ssl_error)
        .is_some_and(|stack| {
            stack.errors().iter().any(|cause| {
                let Some(reason) = cause.library_reason(boring_sys::ERR_LIB_SSL) else {
                    return false;
                };
                [
                    boring_sys::SSL_R_NO_APPLICATION_PROTOCOL,
                    boring_sys::SSL_R_TLSV1_ALERT_NO_APPLICATION_PROTOCOL,
                    boring_sys::SSL_R_TLSV1_ALERT_PROTOCOL_VERSION,
                    boring_sys::SSL_R_UNSUPPORTED_PROTOCOL,
                ]
                .contains(&reason)
            })
        })
    {
        EngineError::UnsupportedCapability
    } else if error.as_io_error().is_some()
        || matches!(
            error.code(),
            Some(ErrorCode::SYSCALL | ErrorCode::ZERO_RETURN)
        )
    {
        EngineError::TransportUnavailable
    } else {
        EngineError::PeerIdentityFailed
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::trust::SpkiPin;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData,
        SignatureAlgorithm, date_time_ymd,
    };

    struct CompressedEcPublicKey(Vec<u8>);

    impl PublicKeyData for CompressedEcPublicKey {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }

        fn algorithm(&self) -> &SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    pub(crate) struct CertificateFixture {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
        private_key_der: Vec<u8>,
        pub(crate) pin: SpkiPin,
    }

    impl CertificateFixture {
        const IDENTITY_HOSTNAME: &str = "endpoint.test";
        const TRUST_GROUP: u64 = 7;

        pub(crate) fn new(expired: bool) -> Self {
            Self::with_point_format(expired, false)
        }

        pub(crate) fn with_compressed_spki() -> Self {
            Self::with_point_format(false, true)
        }

        fn with_point_format(expired: bool, compressed: bool) -> Self {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_parameters
                .distinguished_name
                .push(DnType::CommonName, "ARIAD test CA");
            ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca = ca_parameters.self_signed(&ca_key).unwrap();
            let key = KeyPair::generate().unwrap();
            let mut parameters =
                CertificateParams::new(vec![Self::IDENTITY_HOSTNAME.to_owned()]).unwrap();
            if expired {
                parameters.not_before = date_time_ymd(1975, 1, 1);
                parameters.not_after = date_time_ymd(2000, 1, 1);
            }
            let certificate = if compressed {
                let raw_key = key.public_key_raw();
                assert_eq!(raw_key.len(), 65);
                assert_eq!(raw_key[0], 4);
                let mut public_key = vec![2 | (raw_key[64] & 1)];
                public_key.extend_from_slice(&raw_key[1..33]);
                parameters
                    .signed_by(&CompressedEcPublicKey(public_key), &ca, &ca_key)
                    .unwrap()
            } else {
                parameters.signed_by(&key, &ca, &ca_key).unwrap()
            };
            let spki = rustls::server::ParsedCertificate::try_from(certificate.der())
                .unwrap()
                .subject_public_key_info();
            let pin = SpkiPin::from_bytes(boring::sha::sha256(spki.as_ref()));
            Self {
                root_der: ca.der().to_vec(),
                leaf_der: certificate.der().to_vec(),
                private_key_der: key.serialize_der(),
                pin,
            }
        }

        pub(crate) fn policy(&self) -> TrustPolicy {
            TrustPolicy::from_der_roots(Self::TRUST_GROUP, vec![self.root_der.clone()]).unwrap()
        }

        pub(crate) fn leaf_der(&self) -> &[u8] {
            &self.leaf_der
        }

        pub(crate) fn server(&self) -> NativeTlsServer {
            NativeTlsServer::from_der(
                &[self.leaf_der.clone(), self.root_der.clone()],
                &self.private_key_der,
            )
            .unwrap()
        }

        pub(crate) fn server_with_alpn(&self, alpn: &'static [u8]) -> SslAcceptor {
            let certificates = [
                X509::from_der(&self.leaf_der).unwrap(),
                X509::from_der(&self.root_der).unwrap(),
            ];
            let key = PKey::private_key_from_der(&self.private_key_der).unwrap();
            let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            configure_server(&mut builder, &certificates, &key).unwrap();
            builder.set_alpn_select_callback(move |_, offered| {
                select_next_proto(alpn, offered).ok_or(AlpnError::ALERT_FATAL)
            });
            builder.build()
        }

        pub(crate) fn endpoint(&self, binding: BindingId) -> EndpointDescriptor {
            EndpointDescriptor {
                id: 1,
                generation: 1,
                identity_hostname: Self::IDENTITY_HOSTNAME.to_owned(),
                trust_group: Self::TRUST_GROUP,
                bindings: vec![binding],
                ech_required: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::CertificateFixture;
    use super::*;
    use crate::trust::SpkiPin;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpListener;

    fn deadline() -> Deadline {
        Deadline::after(Duration::from_secs(5)).unwrap()
    }

    async fn handshake(
        fixture: &CertificateFixture,
        endpoint: EndpointDescriptor,
        policy: TrustPolicy,
    ) -> Result<NativeVerifiedTlsChannel, EngineError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = fixture.server();
        let server_task = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            server.accept(io, deadline()).await
        });
        let io = TcpStream::connect(address).await.unwrap();
        let connector = NativeTlsConnector::new(policy).unwrap();
        let result = connector.connect(&endpoint, io, address, deadline()).await;
        let _ = server_task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn native_h2_accepts_matching_chain_name_and_pin() {
        let fixture = CertificateFixture::new(false);
        let policy = fixture.policy().with_spki_pins(vec![fixture.pin]).unwrap();
        let endpoint = fixture.endpoint(BindingId::H2);
        let channel = handshake(&fixture, endpoint.clone(), policy).await.unwrap();
        assert_eq!(channel.endpoint(), &endpoint);
        assert_eq!(channel.binding(), BindingId::H2);
        assert_eq!(
            channel.into_io().ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice())
        );
    }

    #[tokio::test]
    async fn native_h2_pins_the_original_compressed_spki() {
        let fixture = CertificateFixture::with_compressed_spki();
        let endpoint = fixture.endpoint(BindingId::H2);
        let channel = handshake(&fixture, endpoint.clone(), fixture.policy())
            .await
            .unwrap();
        let peer = channel.into_io().ssl().peer_certificate().unwrap();
        let exported_spki = peer.public_key().unwrap().public_key_to_der().unwrap();
        assert_ne!(&boring::sha::sha256(&exported_spki), fixture.pin.as_bytes());
        assert_eq!(
            encoded_certificate_spki(&peer.to_der().unwrap()),
            encoded_certificate_spki(fixture.leaf_der())
        );
        let matching_pin = fixture.policy().with_spki_pins(vec![fixture.pin]).unwrap();
        let channel = handshake(&fixture, endpoint.clone(), matching_pin)
            .await
            .unwrap();
        assert_eq!(channel.endpoint(), &endpoint);
        let wrong_pin = fixture
            .policy()
            .with_spki_pins(vec![SpkiPin::from_bytes([0xff; 32])])
            .unwrap();
        assert!(matches!(
            handshake(&fixture, endpoint, wrong_pin).await,
            Err(EngineError::PeerIdentityFailed)
        ));
    }

    #[test]
    fn spki_extraction_rejects_truncated_certificate_der() {
        let fixture = CertificateFixture::with_compressed_spki();
        let certificate_der = fixture.leaf_der();
        for end in 0..certificate_der.len() {
            assert!(encoded_certificate_spki(&certificate_der[..end]).is_none());
        }
        let spki = encoded_certificate_spki(certificate_der).unwrap();
        assert_eq!(&boring::sha::sha256(spki), fixture.pin.as_bytes());
        let mut trailing_bytes = certificate_der.to_vec();
        trailing_bytes.push(0);
        assert!(encoded_certificate_spki(&trailing_bytes).is_none());
    }

    #[test]
    fn der_framing_rejects_invalid_or_overflowing_lengths() {
        let width = std::mem::size_of::<usize>();
        let mut overflowing = vec![0x30, 0x80 | width as u8];
        overflowing.extend(std::iter::repeat_n(0xff, width));
        let mut too_wide = vec![0x30, 0x80 | (width + 1) as u8];
        too_wide.extend(std::iter::repeat_n(1, width + 1));
        for encoded in [
            Vec::new(),
            vec![0x30],
            vec![0x30, 0x80],
            vec![0x30, 0x81],
            vec![0x30, 0x81, 1, 0],
            vec![0x30, 0x82, 0, 0x80],
            vec![0x30, 2, 0],
            overflowing,
            too_wide,
        ] {
            let mut input = encoded.as_slice();
            assert!(take_der_element(&mut input, 0x30).is_none(), "{encoded:?}");
            assert_eq!(input, encoded);
        }
    }

    #[tokio::test]
    async fn native_h2_rejects_name_pin_expiry_and_other_root() {
        let fixture = CertificateFixture::new(false);
        let mut endpoint = fixture.endpoint(BindingId::H2);
        endpoint.identity_hostname = "other.test".to_owned();
        assert!(matches!(
            handshake(&fixture, endpoint, fixture.policy()).await,
            Err(EngineError::PeerIdentityFailed)
        ));
        let policy = fixture
            .policy()
            .with_spki_pins(vec![SpkiPin::from_bytes([0; 32])])
            .unwrap();
        assert!(matches!(
            handshake(&fixture, fixture.endpoint(BindingId::H2), policy).await,
            Err(EngineError::PeerIdentityFailed)
        ));
        let other_ca = CertificateFixture::new(false);
        assert!(matches!(
            handshake(&fixture, fixture.endpoint(BindingId::H2), other_ca.policy()).await,
            Err(EngineError::PeerIdentityFailed)
        ));
        let expired = CertificateFixture::new(true);
        assert!(matches!(
            handshake(&expired, expired.endpoint(BindingId::H2), expired.policy()).await,
            Err(EngineError::PeerIdentityFailed)
        ));
    }

    #[tokio::test]
    async fn native_h2_incompatible_alpn_is_a_retryable_capability_failure() {
        let fixture = CertificateFixture::new(false);
        let endpoint = fixture.endpoint(BindingId::H2);
        let policy = fixture.policy().with_spki_pins(vec![fixture.pin]).unwrap();
        let connector = NativeTlsConnector::new(policy).unwrap();
        let server = fixture.server_with_alpn(b"\x08http/1.1");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let watchdog = Duration::from_secs(10);
        let mut server_task = tokio::spawn(async move {
            tokio::time::timeout(watchdog, async move {
                let (io, _) = listener.accept().await.unwrap();
                tokio_boring::accept(&server, io).await.is_err()
            })
            .await
            .expect("server handshake watchdog")
        });
        let result = tokio::time::timeout(watchdog, async {
            let io = TcpStream::connect(address).await.unwrap();
            connector.connect(&endpoint, io, address, deadline()).await
        })
        .await;
        let rejected = match tokio::time::timeout(watchdog, &mut server_task).await {
            Ok(result) => result.expect("server task"),
            Err(_) => {
                server_task.abort();
                let _ = tokio::time::timeout(watchdog, &mut server_task).await;
                panic!("server task cleanup watchdog");
            }
        };
        assert!(rejected, "incompatible ALPN completed the server handshake");
        assert_eq!(
            result.expect("client handshake watchdog").err(),
            Some(EngineError::UnsupportedCapability)
        );
    }

    #[derive(Debug)]
    struct ResetIo;

    impl AsyncRead for ResetIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            )))
        }
    }

    impl AsyncWrite for ResetIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn native_handshake_io_failure_remains_retryable_transport_failure() {
        let fixture = CertificateFixture::new(false);
        let connector = NativeTlsConnector::new(fixture.policy()).unwrap();
        let result = tokio_boring::connect(
            connector.connector.configure().unwrap(),
            "endpoint.test",
            ResetIo,
        )
        .await;
        let error = result.err().unwrap();
        assert_eq!(
            classify_handshake_error(&error),
            EngineError::TransportUnavailable
        );
    }
}
