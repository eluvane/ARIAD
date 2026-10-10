#![cfg(feature = "tls-rustls")]
#![forbid(unsafe_code)]

mod support;

#[path = "support/auth.rs"]
mod auth_support;

#[path = "support/rustls.rs"]
mod rustls_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ariad_core::{BindingId, BudgetLimits, EngineError, NetworkEpoch};
use ariad_engine::{
    DefaultSocketFactory, EXPERIMENTAL_CREDENTIAL_HEADER, EndpointPolicy, Engine, EngineConfig,
    H2Session, HostServices, SocketFactory, SpkiPin, SystemBootstrapResolver, attach_h2_versions,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use auth_support::credential;
use rustls_support::{IO_TIMEOUT, deadline};
use support::{CertificateFixture, HOSTNAME, TRUST_GROUP, endpoint, tcp_destination};

struct CountingSocketFactory(Arc<AtomicUsize>);

impl SocketFactory for CountingSocketFactory {
    fn create_tcp(&self, address: std::net::SocketAddr) -> Result<TcpSocket, EngineError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        DefaultSocketFactory.create_tcp(address)
    }
}

#[derive(Debug, Clone, Copy)]
enum TrustFailure {
    WrongHostname,
    UnknownCa,
    Expired,
    WrongPin,
    MatchingPinWrongHostname,
    MatchingPinUnknownCa,
    MatchingPinExpired,
}

#[tokio::test]
async fn real_certificate_failures_send_no_application_bytes() {
    for failure in [
        TrustFailure::WrongHostname,
        TrustFailure::UnknownCa,
        TrustFailure::Expired,
        TrustFailure::WrongPin,
        TrustFailure::MatchingPinWrongHostname,
        TrustFailure::MatchingPinUnknownCa,
        TrustFailure::MatchingPinExpired,
    ] {
        let leaf_expired = matches!(
            failure,
            TrustFailure::Expired | TrustFailure::MatchingPinExpired
        );
        let server_certificate = CertificateFixture::new(leaf_expired);
        let other_ca = CertificateFixture::new(false);
        let uses_other_ca = matches!(
            failure,
            TrustFailure::UnknownCa | TrustFailure::MatchingPinUnknownCa
        );
        let mut trust_policy = if uses_other_ca {
            other_ca.policy()
        } else {
            server_certificate.policy()
        };
        if matches!(failure, TrustFailure::WrongPin) {
            let mut wrong_pin = *server_certificate.pin.as_bytes();
            wrong_pin[0] ^= 1;
            trust_policy = trust_policy
                .with_spki_pins(vec![SpkiPin::from_bytes(wrong_pin)])
                .expect("wrong pin policy");
        } else if matches!(
            failure,
            TrustFailure::MatchingPinWrongHostname
                | TrustFailure::MatchingPinUnknownCa
                | TrustFailure::MatchingPinExpired
        ) {
            trust_policy = trust_policy
                .with_spki_pins(vec![server_certificate.pin])
                .expect("matching pin policy");
        }
        let identity_hostname = if matches!(
            failure,
            TrustFailure::WrongHostname | TrustFailure::MatchingPinWrongHostname
        ) {
            "other.test"
        } else {
            HOSTNAME
        };
        let endpoint = endpoint(identity_hostname, BindingId::H2);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let acceptor = TlsAcceptor::from(server_certificate.server_config(b"h2"));
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let Ok(mut io) = acceptor.accept(socket).await else {
                return Vec::new();
            };
            let mut read_buffer = [0u8; 128];
            match io.read(&mut read_buffer).await {
                Ok(n) => read_buffer[..n].to_vec(),
                Err(_) => Vec::new(),
            }
        });
        let tcp_create_calls = Arc::new(AtomicUsize::new(0));
        let services = HostServices::new(
            Arc::new(SystemBootstrapResolver),
            Arc::new(CountingSocketFactory(Arc::clone(&tcp_create_calls))),
            vec![trust_policy],
            4,
        )
        .expect("host services");
        let engine = Engine::with_host_services(
            EngineConfig {
                limits: BudgetLimits::lab_small(),
            },
            Arc::new(services),
        )
        .expect("engine");
        let endpoint_policy = EndpointPolicy::single(endpoint, address, NetworkEpoch::start())
            .expect("endpoint policy");
        let result = engine
            .connect(&endpoint_policy, credential(), deadline())
            .await;
        assert!(
            matches!(result, Err(EngineError::PeerIdentityFailed)),
            "{failure:?}: {result:?}"
        );
        assert_eq!(
            tcp_create_calls.load(Ordering::SeqCst),
            1,
            "{failure:?}: trust failure was retried"
        );
        let application_bytes = timeout(IO_TIMEOUT, server_task)
            .await
            .expect("server completion")
            .expect("server join");
        assert!(
            application_bytes.is_empty(),
            "{failure:?}: application bytes escaped"
        );
        let report = engine.shutdown_with_deadline(deadline()).await;
        assert_eq!(report.pending_connects, 0, "{failure:?}");
    }
}

#[tokio::test]
async fn matching_pin_and_valid_chain_allow_a_real_h2_open() {
    let certificate = CertificateFixture::new(false);
    let trust_policy = certificate.pinned_policy();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let acceptor = TlsAcceptor::from(certificate.server_config(b"h2"));
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let io = acceptor.accept(socket).await.expect("verified TLS");
        let mut connection = h2::server::handshake(io).await.expect("H2 handshake");
        let (request, mut respond) = connection
            .accept()
            .await
            .expect("request present")
            .expect("request");
        let credential_header = request
            .headers()
            .get(EXPERIMENTAL_CREDENTIAL_HEADER)
            .expect("credential")
            .clone();
        let mut response = http::Response::new(());
        attach_h2_versions(response.headers_mut()).expect("versions");
        respond.send_response(response, true).expect("response");
        match connection.accept().await {
            None => {}
            Some(Err(error)) => assert!(error.is_io(), "unexpected protocol failure: {error:?}"),
            Some(Ok(_)) => panic!("unexpected second request"),
        }
        credential_header
    });
    let services = HostServices::new(
        Arc::new(SystemBootstrapResolver),
        Arc::new(DefaultSocketFactory),
        vec![trust_policy],
        4,
    )
    .expect("host services");
    let verified = services
        .connect_verified(&endpoint(HOSTNAME, BindingId::H2), address, deadline())
        .await
        .expect("verified channel");
    assert_eq!(verified.endpoint_id(), 1);
    assert_eq!(verified.trust_group(), TRUST_GROUP);
    assert_eq!(verified.binding(), BindingId::H2);
    let session = H2Session::handshake(verified.into_io(), true)
        .await
        .expect("H2 session");
    let destination = tcp_destination();
    let mut opened = session
        .open_stream(&destination, &credential())
        .await
        .expect("open");
    assert_eq!(opened.status(), http::StatusCode::OK);
    opened.end_write().await.expect("half close");
    drop(opened);
    session.close(IO_TIMEOUT).await.expect("close");
    let received_credential = timeout(IO_TIMEOUT, server_task)
        .await
        .expect("server completion")
        .expect("server join");
    assert_eq!(received_credential.as_bytes(), "11".repeat(32).as_bytes());
}

#[tokio::test]
async fn incompatible_alpn_does_not_produce_a_verified_channel() {
    let certificate = CertificateFixture::new(false);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let acceptor = TlsAcceptor::from(certificate.server_config(b"http/1.1"));
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        acceptor.accept(socket).await.is_err()
    });
    let services = HostServices::new(
        Arc::new(SystemBootstrapResolver),
        Arc::new(DefaultSocketFactory),
        vec![certificate.policy()],
        4,
    )
    .expect("host services");
    let result = services
        .connect_verified(&endpoint(HOSTNAME, BindingId::H2), address, deadline())
        .await;
    assert!(
        matches!(result, Err(EngineError::UnsupportedCapability)),
        "{result:?}"
    );
    assert!(
        timeout(IO_TIMEOUT, server_task)
            .await
            .expect("server completion")
            .expect("server join")
    );
}
