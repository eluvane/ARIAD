#![cfg(feature = "tls-rustls")]
#![forbid(unsafe_code)]

mod support;

#[path = "support/auth.rs"]
mod auth_support;

#[path = "support/lifecycle.rs"]
mod lifecycle_support;

#[path = "support/resolver.rs"]
mod resolver_support;

#[path = "support/rustls.rs"]
mod rustls_support;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ariad_core::{
    AuthzDecision, BindingId, BudgetLimits, Credential, DatagramOutcome, DeliveryMode, Destination,
    EngineError, MemoryBudget, NetworkEpoch, ResourceBudget, SessionPhase,
};
use ariad_engine::{
    Authorizer, CloseMode, CloseOutcome, DatagramRequirements, Deadline, DefaultSocketFactory,
    DialCandidate, EXPERIMENTAL_H2_BINDING_VERSION_HEADER, EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
    EndpointPolicy, Engine, EngineConfig, EngineResources, H2Config, H2Session, HostServices,
    ReadOutcome, Session, StaticAuthorizer, Stream, StreamOptions, attach_credential,
    attach_h2_versions, check_h2_credential, handle_h2_connect_udp, serve_h2,
    serve_h2_with_handler,
};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsAcceptor;

use auth_support::credential;
use lifecycle_support::{assert_no_admission, assert_shutdown_complete, assert_tls_shutdown};
use resolver_support::FixedResolver;
use rustls_support::{IO_TIMEOUT, deadline};
use support::{
    CertificateFixture, HOSTNAME, TRUST_GROUP, endpoint, tcp_destination as target_destination,
};

struct Fixture {
    address: SocketAddr,
    certificate: CertificateFixture,
    endpoint_tcp_accepts: Arc<AtomicUsize>,
    target_dials: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    server: JoinHandle<Vec<Result<(), EngineError>>>,
    target: JoinHandle<()>,
}

impl Fixture {
    async fn new(endpoint_connections: usize, target_connections: usize) -> Self {
        Self::with_target(
            endpoint_connections,
            target_connections,
            H2Config::default(),
            |mut stream| async move {
                let mut payload = Vec::new();
                stream
                    .read_to_end(&mut payload)
                    .await
                    .expect("target request EOF");
                stream.write_all(&payload).await.expect("target reply");
                stream.shutdown().await.expect("target half close");
                payload
            },
        )
        .await
    }

    async fn with_target<F, Fut>(
        endpoint_connections: usize,
        target_connections: usize,
        server_config: H2Config,
        target_handler: F,
    ) -> Self
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Vec<u8>> + Send + 'static,
    {
        let certificate = CertificateFixture::new(false);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS listener");
        let address = listener.local_addr().expect("TLS address");
        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener");
        let target_address = target_listener.local_addr().expect("target address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let dials = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&received);
        let target_handler = Arc::new(target_handler);
        let target = tokio::spawn(async move {
            let mut targets = JoinSet::new();
            for _ in 0..target_connections {
                let (stream, _) = target_listener.accept().await.expect("target accept");
                let observed = Arc::clone(&observed);
                let target_handler = Arc::clone(&target_handler);
                targets.spawn(async move {
                    let payload = target_handler(stream).await;
                    observed.lock().expect("observations").push(payload);
                });
            }
            while let Some(result) = targets.join_next().await {
                result.expect("target join");
            }
        });
        let acceptor = TlsAcceptor::from(certificate.server_config(b"h2"));
        let accepts = Arc::clone(&accepted);
        let target_dials = Arc::clone(&dials);
        let server = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            for _ in 0..endpoint_connections {
                let (socket, _) = listener.accept().await.expect("TLS accept");
                accepts.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let target_dials = Arc::clone(&target_dials);
                let config = server_config.clone();
                sessions.spawn(async move {
                    let tls = acceptor.accept(socket).await.expect("TLS handshake");
                    serve_h2(
                        tls,
                        Arc::new(StaticAuthorizer::new(credential(), 1)),
                        false,
                        config,
                        move |destination| {
                            let target_dials = Arc::clone(&target_dials);
                            async move {
                                assert_eq!(destination, target_destination());
                                target_dials.fetch_add(1, Ordering::SeqCst);
                                TcpStream::connect(target_address)
                                    .await
                                    .map_err(|_| EngineError::TargetConnectFailed)
                            }
                        },
                        std::future::pending::<()>(),
                    )
                    .await
                });
            }
            let mut results = Vec::new();
            while let Some(result) = sessions.join_next().await {
                results.push(result.expect("session server join"));
            }
            results
        });
        Self {
            address,
            certificate,
            endpoint_tcp_accepts: accepted,
            target_dials: dials,
            received,
            server,
            target,
        }
    }

    fn engine(&self, limits: BudgetLimits) -> Engine {
        Engine::with_host_services(EngineConfig { limits }, self.host_services()).expect("engine")
    }

    fn host_services(&self) -> Arc<HostServices> {
        host_services(self.address, &self.certificate)
    }

    fn policy(&self, epoch: NetworkEpoch) -> EndpointPolicy {
        EndpointPolicy::single(endpoint(HOSTNAME, BindingId::H2), self.address, epoch)
            .expect("endpoint policy")
    }

    async fn finish(self, expected: Vec<Vec<u8>>) {
        self.finish_with_expected_error(expected, None).await;
    }

    async fn finish_with_expected_error(
        self,
        mut expected: Vec<Vec<u8>>,
        expected_error: Option<EngineError>,
    ) {
        timeout(IO_TIMEOUT, self.target)
            .await
            .expect("target completion")
            .expect("target task");
        for result in timeout(IO_TIMEOUT, self.server)
            .await
            .expect("server completion")
            .expect("server task")
        {
            assert_tls_shutdown(result, expected_error);
        }
        let mut observed = self.received.lock().expect("observations").clone();
        observed.sort();
        expected.sort();
        assert_eq!(observed.len(), expected.len(), "payload count");
        for (index, (observed, expected)) in observed.iter().zip(&expected).enumerate() {
            assert!(
                observed == expected,
                "payload {index}: received {} bytes, expected {} bytes; first mismatch {:?}",
                observed.len(),
                expected.len(),
                observed.iter().zip(expected).position(|(a, b)| a != b)
            );
        }
    }
}

fn host_services(address: SocketAddr, certificate: &CertificateFixture) -> Arc<HostServices> {
    let policy = certificate.pinned_policy();
    Arc::new(
        HostServices::new(
            Arc::new(FixedResolver::new(address, Some(HOSTNAME))),
            Arc::new(DefaultSocketFactory),
            vec![policy],
            4,
        )
        .expect("host services"),
    )
}

async fn connect(engine: &Engine, fixture: &Fixture, epoch: NetworkEpoch) -> Session {
    engine
        .connect(&fixture.policy(epoch), credential(), deadline())
        .await
        .expect("session")
}

async fn write_all(stream: &mut Stream, mut payload: &[u8]) {
    while !payload.is_empty() {
        let written = stream.write(payload, deadline()).await.expect("write");
        assert!(written > 0 && written <= payload.len());
        payload = &payload[written..];
    }
}

async fn read_all(stream: &mut Stream) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut buffer = [0u8; 3];
    loop {
        match stream.read(&mut buffer, deadline()).await.expect("read") {
            ReadOutcome::Data(n) => {
                assert!(n > 0 && n <= buffer.len());
                assert!(payload.len() + n <= 64 * 1024);
                payload.extend_from_slice(&buffer[..n]);
            }
            ReadOutcome::Eof => return payload,
            outcome => panic!("unexpected read outcome: {outcome:?}"),
        }
    }
}

fn duplex_limits() -> BudgetLimits {
    BudgetLimits {
        decoded_header_bytes: 8 * 1024,
        stream_queue_per_direction: 4 * 1024,
        session_application_budget: 96 * 1024,
        control_reserve: 32 * 1024,
        active_flows_per_session: 1,
        udp_queue_bytes: 8 * 1024,
        pending_egress_opens: 1,
        pending_handshakes: 1,
        active_sessions: 1,
        global_application_budget: 192 * 1024,
        ..BudgetLimits::lab_small()
    }
}

fn duplex_server_config() -> H2Config {
    H2Config {
        direction_buffer_bytes: 4 * 1024,
        initial_connection_window: 64 * 1024,
        ..H2Config::default()
    }
}

fn fixture_engine(services: Arc<HostServices>, resources: &Arc<EngineResources>) -> Engine {
    Engine::with_host_services_and_resources(
        EngineConfig {
            limits: duplex_limits(),
        },
        services,
        Arc::clone(resources),
    )
    .expect("engine with resource pool")
}

async fn finish_engine(engine: Engine, session: Session, resources: &EngineResources) {
    assert_eq!(
        session.close(CloseMode::Graceful, deadline()).await,
        Ok(CloseOutcome::Graceful)
    );
    drop(session);
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
    assert_eq!(report.forced_sessions, 0);
    drop(engine);
    assert_no_admission(resources);
}

#[tokio::test]
async fn public_stream_halves_exchange_independent_payloads_beyond_h2_windows() {
    let request: Vec<u8> = (0..512 * 1024).map(|index| (index % 251) as u8).collect();
    let response: Vec<u8> = (0..512 * 1024)
        .map(|index| (17 + index % 239) as u8)
        .collect();
    let server_response = response.clone();
    let (start_prefix, prefix_started) = tokio::sync::oneshot::channel();
    let (start_response, response_started) = tokio::sync::oneshot::channel();
    let (consumed_response, response_consumed) = tokio::sync::oneshot::channel();
    let target_gates = Arc::new(Mutex::new(Some((
        prefix_started,
        response_started,
        response_consumed,
    ))));
    let fixture = Fixture::with_target(1, 1, duplex_server_config(), move |mut stream| {
        let (prefix_started, response_started, response_consumed) = target_gates
            .lock()
            .expect("target gates")
            .take()
            .expect("one target connection");
        let response = server_response.clone();
        async move {
            prefix_started.await.expect("prefix gate");
            stream
                .write_all(b"server-first")
                .await
                .expect("unsolicited prefix");
            response_started.await.expect("response gate");
            stream
                .write_all(&response)
                .await
                .expect("independent response");
            stream.shutdown().await.expect("response EOF");
            response_consumed.await.expect("response consumed");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.expect("request EOF");
            request
        }
    })
    .await;
    let resources = Arc::new(EngineResources::new(duplex_limits()).expect("resources"));
    let engine = fixture_engine(fixture.host_services(), &resources);
    let session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    let stream = session
        .open_stream(&target_destination(), StreamOptions::default(), deadline())
        .await
        .expect("stream");
    let (mut reader, mut writer) = stream.into_split();
    let io_deadline = deadline();
    let mut prefix = [0u8; 12];
    let mut prefix_read = Box::pin(async {
        let mut offset = 0;
        while offset < prefix.len() {
            match reader
                .read(&mut prefix[offset..], io_deadline)
                .await
                .expect("prefix read")
            {
                ReadOutcome::Data(count) if count > 0 && count <= prefix.len() - offset => {
                    offset += count;
                }
                outcome => panic!("unexpected prefix outcome: {outcome:?}"),
            }
        }
    });
    std::future::poll_fn(|cx| {
        assert!(prefix_read.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    start_prefix.send(()).expect("start unsolicited prefix");
    prefix_read.await;
    assert_eq!(&prefix, b"server-first");

    let mut reading = Box::pin(async {
        let mut received = Vec::new();
        let mut buffer = [0u8; 4 * 1024];
        loop {
            match reader
                .read(&mut buffer, io_deadline)
                .await
                .expect("response read")
            {
                ReadOutcome::Data(count) if count > 0 && count <= buffer.len() => {
                    assert!(received.len() + count <= response.len());
                    received.extend_from_slice(&buffer[..count]);
                }
                ReadOutcome::Eof => break,
                outcome => panic!("unexpected response outcome: {outcome:?}"),
            }
        }
        consumed_response.send(()).expect("response observation");
        received
    });
    std::future::poll_fn(|cx| {
        assert!(reading.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let first_write = writer
        .write(&request, io_deadline)
        .await
        .expect("write with pending read");
    assert!(first_write > 0 && first_write <= request.len());
    start_response.send(()).expect("start independent response");
    let writing = async {
        let mut offset = first_write;
        while offset < request.len() {
            let count = writer
                .write(&request[offset..], io_deadline)
                .await
                .expect("request write");
            assert!(count > 0 && count <= request.len() - offset);
            offset += count;
        }
        writer
            .end_write(io_deadline)
            .await
            .expect("request half close");
    };
    let (received, ()) = timeout(IO_TIMEOUT, async { tokio::join!(reading, writing) })
        .await
        .expect("full duplex completion");
    assert_eq!(received, response);
    drop((reader, writer));
    finish_engine(engine, session, &resources).await;
    assert_eq!(resources.application_memory_used(), 0);
    fixture.finish(vec![request]).await;
}

#[tokio::test]
async fn public_writer_half_close_and_drop_preserves_pending_reader() {
    let fixture = Fixture::with_target(1, 1, duplex_server_config(), |mut stream| async move {
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.expect("request EOF");
        stream
            .write_all(b"reply-after-half-close")
            .await
            .expect("response");
        stream.shutdown().await.expect("response EOF");
        request
    })
    .await;
    let resources = Arc::new(EngineResources::new(duplex_limits()).expect("resources"));
    let engine = fixture_engine(fixture.host_services(), &resources);
    let session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    let stream = session
        .open_stream(&target_destination(), StreamOptions::default(), deadline())
        .await
        .expect("stream");
    let (mut reader, mut writer) = stream.into_split();
    let io_deadline = deadline();
    let mut reading = Box::pin(async {
        let mut response = Vec::new();
        let mut buffer = [0u8; 8];
        loop {
            match reader
                .read(&mut buffer, io_deadline)
                .await
                .expect("read after writer drop")
            {
                ReadOutcome::Data(count) if count > 0 && count <= buffer.len() => {
                    assert!(response.len() + count <= b"reply-after-half-close".len());
                    response.extend_from_slice(&buffer[..count]);
                }
                ReadOutcome::Eof => return response,
                outcome => panic!("unexpected read after writer drop: {outcome:?}"),
            }
        }
    });
    std::future::poll_fn(|cx| {
        assert!(reading.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        writer.write(b"request", io_deadline).await.expect("write"),
        7
    );
    writer.end_write(io_deadline).await.expect("half close");
    drop(writer);
    assert_eq!(reading.await, b"reply-after-half-close");
    drop(reader);
    finish_engine(engine, session, &resources).await;
    assert_eq!(resources.application_memory_used(), 0);
    fixture.finish(vec![b"request".to_vec()]).await;
}

#[tokio::test]
async fn public_stream_cancel_and_pending_read_drop_release_shared_flow() {
    let fixture = Fixture::with_target(1, 2, duplex_server_config(), |mut stream| async move {
        let mut request = Vec::new();
        if let Err(error) = stream.read_to_end(&mut request).await {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        request
    })
    .await;
    let resources = Arc::new(EngineResources::new(duplex_limits()).expect("resources"));
    let engine = fixture_engine(fixture.host_services(), &resources);
    let session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    for drop_pending_read in [false, true] {
        let stream = session
            .open_stream(&target_destination(), StreamOptions::default(), deadline())
            .await
            .expect("flow admission available");
        let (mut reader, mut writer) = stream.into_split();
        let mut output = [0x5a; 16];
        let mut reading = Box::pin(reader.read(&mut output, deadline()));
        std::future::poll_fn(|cx| {
            assert!(reading.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let outcome = if drop_pending_read {
            drop(reading);
            reader.read(&mut output, deadline()).await
        } else {
            writer.cancel();
            reading.await
        };
        assert_eq!(outcome, Ok(ReadOutcome::Cancelled));
        assert_eq!(output, [0x5a; 16]);
        assert_eq!(
            writer.write(b"not accepted", deadline()).await,
            Err(EngineError::Cancelled)
        );
        assert_eq!(
            writer.end_write(deadline()).await,
            Err(EngineError::Cancelled)
        );
        assert_eq!(resources.active_flows(), 0);
        assert_eq!(resources.pending_opens(), 0);
        drop((reader, writer));
    }
    finish_engine(engine, session, &resources).await;
    assert_eq!(resources.application_memory_used(), 0);
    fixture
        .finish_with_expected_error(vec![Vec::new(), Vec::new()], Some(EngineError::RemoteReset))
        .await;
}

#[tokio::test]
async fn public_stream_control_and_timeout_preserve_terminal_causes() {
    for timeout_write in [false, true] {
        let certificate = CertificateFixture::new(false);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS listener");
        let address = listener.local_addr().expect("TLS address");
        let acceptor = TlsAcceptor::from(certificate.server_config(b"h2"));
        let (observed_resets, mut resets) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TLS accept");
            let tls = acceptor.accept(socket).await.expect("TLS handshake");
            let authorizer = Arc::new(StaticAuthorizer::new(credential(), 1));
            let config = H2Config {
                direction_buffer_bytes: 1024,
                initial_connection_window: 1024,
                ..H2Config::default()
            };
            serve_h2_with_handler(
                tls,
                config,
                move |request, mut respond, _| {
                    let authorizer = Arc::clone(&authorizer);
                    let observed_resets = observed_resets.clone();
                    async move {
                        check_h2_credential(&request, &*authorizer)?;
                        // Retain the request without releasing DATA credit.
                        let _request = request;
                        let mut response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())
                            .map_err(|_| EngineError::ProtocolViolation)?;
                        attach_h2_versions(response.headers_mut())?;
                        let mut body = respond
                            .send_response(response, false)
                            .map_err(|_| EngineError::TransportUnavailable)?;
                        let reset = std::future::poll_fn(|cx| body.poll_reset(cx)).await;
                        observed_resets
                            .send(reset)
                            .await
                            .map_err(|_| EngineError::Cancelled)?;
                        Ok(())
                    }
                },
                std::future::pending::<()>(),
            )
            .await
        });
        let resources = Arc::new(EngineResources::new(duplex_limits()).expect("resources"));
        let engine = fixture_engine(host_services(address, &certificate), &resources);
        let policy = EndpointPolicy::single(
            endpoint(HOSTNAME, BindingId::H2),
            address,
            NetworkEpoch::start(),
        )
        .expect("policy");
        let session = engine
            .connect(&policy, credential(), deadline())
            .await
            .expect("session");
        let stream = session
            .open_stream(&target_destination(), StreamOptions::default(), deadline())
            .await
            .expect("stream");
        let (mut reader, mut writer) = stream.into_split();
        let control = writer.control();
        assert_eq!(
            writer
                .write(&[0xaa; 1024], deadline())
                .await
                .expect("fill peer receive window"),
            1024
        );
        let mut output = [0x5a; 16];
        let mut reading = Box::pin(reader.read(&mut output, deadline()));
        let write_deadline = if timeout_write {
            Deadline::after(Duration::from_millis(500)).expect("write deadline")
        } else {
            deadline()
        };
        let mut writing = Box::pin(writer.write(b"blocked", write_deadline));
        std::future::poll_fn(|cx| {
            assert!(reading.as_mut().poll(cx).is_pending());
            assert!(writing.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let (read_result, write_result) = if timeout_write {
            assert_eq!(
                timeout(IO_TIMEOUT, writing)
                    .await
                    .expect("write timeout completion"),
                Err(EngineError::DeadlineExceeded)
            );
            drop(reading);
            (
                reader.read(&mut output, deadline()).await,
                writer.write(b"not accepted", deadline()).await,
            )
        } else {
            control.cancel();
            timeout(IO_TIMEOUT, async { tokio::join!(reading, writing) })
                .await
                .expect("both cancelled directions complete")
        };
        let terminal_error = if timeout_write {
            assert_eq!(read_result, Err(EngineError::DeadlineExceeded));
            EngineError::DeadlineExceeded
        } else {
            assert_eq!(read_result, Ok(ReadOutcome::Cancelled));
            EngineError::Cancelled
        };
        assert_eq!(write_result, Err(terminal_error));
        assert_eq!(writer.end_write(deadline()).await, Err(terminal_error));
        assert_eq!(output, [0x5a; 16]);
        let reason = timeout(IO_TIMEOUT, resets.recv())
            .await
            .expect("reset observation deadline")
            .expect("reset observation")
            .expect("peer reset reason");
        assert_eq!(reason, h2::Reason::CANCEL);
        assert_eq!(resources.active_flows(), 0);
        assert_eq!(resources.pending_opens(), 0);
        drop((reader, writer));
        finish_engine(engine, session, &resources).await;
        assert!(resources.application_memory_used() > 0);
        drop(control);
        assert_eq!(resources.application_memory_used(), 0);
        let server_result = timeout(IO_TIMEOUT, server)
            .await
            .expect("server completion")
            .expect("server join");
        assert!(
            matches!(
                server_result,
                Ok(()) | Err(EngineError::TransportUnavailable)
            ),
            "{server_result:?}"
        );
    }
}

#[tokio::test]
async fn public_association_halves_preserve_whole_messages_and_received_ownership() {
    let certificate = CertificateFixture::new(false);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS listener");
    let address = listener.local_addr().expect("TLS address");
    let udp_target = UdpSocket::bind("127.0.0.1:0").await.expect("UDP target");
    let target_address = udp_target.local_addr().expect("UDP target address");
    let destination = Destination::parse("udp.fixture:443").expect("UDP destination");
    let (observed_opens, mut opens) = tokio::sync::mpsc::channel(1);
    let (start_target, target_started) = tokio::sync::oneshot::channel();
    let target = tokio::spawn(async move {
        let peer = target_started.await.expect("association socket address");
        assert_eq!(
            udp_target
                .send_to(b"server-first", peer)
                .await
                .expect("unsolicited message"),
            12
        );
        let mut messages = Vec::new();
        let mut buffer = [0u8; 1024];
        for reply in [&[][..], &b"independent-reply"[..]] {
            let (count, source) = udp_target
                .recv_from(&mut buffer)
                .await
                .expect("target datagram");
            messages.push((buffer[..count].to_vec(), source));
            let count = udp_target
                .send_to(reply, source)
                .await
                .expect("target reply");
            assert_eq!(count, reply.len());
        }
        messages
    });
    let acceptor = TlsAcceptor::from(certificate.server_config(b"h2"));
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("TLS accept");
        let tls = acceptor.accept(socket).await.expect("TLS handshake");
        let authorizer = Arc::new(StaticAuthorizer::new(credential(), 1));
        serve_h2_with_handler(
            tls,
            duplex_server_config(),
            move |request, respond, config| {
                let authorizer = Arc::clone(&authorizer);
                let observed_opens = observed_opens.clone();
                handle_h2_connect_udp(
                    request,
                    respond,
                    authorizer,
                    config,
                    move |decision, destination, open_deadline| async move {
                        open_deadline.remaining()?;
                        let socket = UdpSocket::bind("127.0.0.1:0")
                            .await
                            .map_err(|_| EngineError::TargetConnectFailed)?;
                        socket
                            .connect(target_address)
                            .await
                            .map_err(|_| EngineError::TargetConnectFailed)?;
                        let peer = socket
                            .local_addr()
                            .map_err(|_| EngineError::TargetConnectFailed)?;
                        observed_opens
                            .send((decision, destination, peer))
                            .await
                            .map_err(|_| EngineError::Cancelled)?;
                        Ok((socket, (), 1024))
                    },
                )
            },
            std::future::pending::<()>(),
        )
        .await
    });
    let resources = Arc::new(EngineResources::new(duplex_limits()).expect("resources"));
    let engine = fixture_engine(host_services(address, &certificate), &resources);
    let policy = EndpointPolicy::single(
        endpoint(HOSTNAME, BindingId::H2),
        address,
        NetworkEpoch::start(),
    )
    .expect("policy");
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("session");
    let association = session
        .open_datagram_association(&destination, DatagramRequirements::default(), deadline())
        .await
        .expect("association");
    assert_eq!(
        association.delivery_mode(),
        DeliveryMode::ReliableEncapsulation
    );
    assert_eq!(association.max_payload(), 1024);
    let generation = association.generation();
    assert!(generation > 0);
    let (mut sender, mut receiver) = association.into_split();
    assert_eq!(sender.generation(), generation);
    assert_eq!(receiver.generation(), generation);
    assert_eq!(sender.delivery_mode(), DeliveryMode::ReliableEncapsulation);
    assert_eq!(receiver.max_payload(), 1024);
    let (decision, opened_destination, peer) = timeout(IO_TIMEOUT, opens.recv())
        .await
        .expect("open observation deadline")
        .expect("open observation");
    assert_eq!(decision.principal, 1);
    assert!(decision.valid_for > Duration::ZERO);
    assert_eq!(opened_destination, destination);

    let mut receiving = Box::pin(receiver.recv(deadline()));
    std::future::poll_fn(|cx| {
        assert!(receiving.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    start_target.send(peer).expect("start unsolicited datagram");
    let first = receiving.await.expect("unsolicited payload");
    assert_eq!(first.as_bytes(), b"server-first");
    let retained_bytes = first.into_bytes();
    let retained_clone = retained_bytes.clone();
    let retained_slice = retained_bytes.slice(1..);

    let mut receiving = Box::pin(receiver.recv(deadline()));
    std::future::poll_fn(|cx| {
        assert!(receiving.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        sender.send(&[], deadline()).await,
        Ok(DatagramOutcome::Queued)
    );
    let empty = receiving.await.expect("empty payload");
    assert!(empty.is_empty());
    let empty_clone = empty.clone();

    let mut receiving = Box::pin(receiver.recv(deadline()));
    std::future::poll_fn(|cx| {
        assert!(receiving.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        sender.send(b"whole-client-message", deadline()).await,
        Ok(DatagramOutcome::Queued)
    );
    let reply = receiving.await.expect("independent reply");
    assert_eq!(reply.as_bytes(), b"independent-reply");
    drop(reply);
    let messages = timeout(IO_TIMEOUT, target)
        .await
        .expect("UDP target completion")
        .expect("UDP target join");
    assert_eq!(
        messages,
        vec![(Vec::new(), peer), (b"whole-client-message".to_vec(), peer)]
    );

    let mut receiving = Box::pin(receiver.recv(deadline()));
    std::future::poll_fn(|cx| {
        assert!(receiving.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    sender.cancel().expect("association cancel");
    assert_eq!(receiving.await, Err(EngineError::Cancelled));
    assert_eq!(
        sender.send(b"not accepted", deadline()).await,
        Err(EngineError::Cancelled)
    );
    assert_eq!(resources.active_flows(), 0);
    assert_eq!(resources.pending_opens(), 0);
    drop((sender, receiver));
    finish_engine(engine, session, &resources).await;
    let retained_charge = resources.application_memory_used();
    assert!(retained_charge > 0);
    drop(retained_bytes);
    assert_eq!(resources.application_memory_used(), retained_charge);
    drop(retained_clone);
    assert_eq!(resources.application_memory_used(), retained_charge);
    assert_eq!(retained_slice.as_ref(), b"erver-first");
    drop(retained_slice);
    let empty_charge = resources.application_memory_used();
    assert!(empty_charge > 0 && empty_charge < retained_charge);
    drop(empty);
    assert_eq!(resources.application_memory_used(), empty_charge);
    drop(empty_clone);
    assert_eq!(resources.application_memory_used(), 0);
    let server_result = timeout(IO_TIMEOUT, server)
        .await
        .expect("UDP server completion")
        .expect("UDP server join");
    assert!(
        matches!(
            server_result,
            Ok(()) | Err(EngineError::RemoteReset | EngineError::TransportUnavailable)
        ),
        "{server_result:?}"
    );
}

#[tokio::test]
async fn verified_tls_peer_without_h2_readiness_loses_to_a_healthy_candidate() {
    let fixture = Fixture::new(1, 1).await;
    let stalled_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stalled TLS listener");
    let stalled_address = stalled_listener.local_addr().expect("stalled TLS address");
    let acceptor = TlsAcceptor::from(fixture.certificate.server_config(b"h2"));
    let (tls_ready, observed_tls) = tokio::sync::oneshot::channel();
    let stalled = tokio::spawn(async move {
        let (socket, _) = stalled_listener.accept().await.expect("stalled TLS accept");
        let tls = acceptor
            .accept(socket)
            .await
            .expect("stalled TLS handshake");
        tls_ready.send(()).expect("TLS observation receiver");
        let mut bytes = Vec::new();
        let result = timeout(IO_TIMEOUT, tls.take(8 * 1024).read_to_end(&mut bytes))
            .await
            .expect("loser socket closes");
        if let Err(error) = result {
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ),
                "{error}"
            );
        }
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert!(bytes.len() >= preface.len() && bytes.len() < 8 * 1024);
        assert_eq!(&bytes[..preface.len()], preface);
        let mut remaining = &bytes[preface.len()..];
        while remaining.len() >= 4 {
            assert_ne!(remaining[3], 1, "HEADERS must wait for H2 readiness");
            assert_ne!(remaining[3], 0, "DATA must wait for H2 readiness");
            if remaining.len() < 9 {
                break;
            }
            let length = (usize::from(remaining[0]) << 16)
                | (usize::from(remaining[1]) << 8)
                | usize::from(remaining[2]);
            if remaining.len() < 9 + length {
                break;
            }
            remaining = &remaining[9 + length..];
        }
    });
    let engine = fixture.engine(BudgetLimits::lab_small());
    let epoch = NetworkEpoch::start();
    let mut healthy_endpoint = endpoint(HOSTNAME, BindingId::H2);
    healthy_endpoint.id = 2;
    let policy = EndpointPolicy {
        candidates: vec![
            DialCandidate {
                endpoint: endpoint(HOSTNAME, BindingId::H2),
                address: stalled_address,
                binding: BindingId::H2,
                failure_domain: 1,
                network_epoch: epoch,
                rtt_hint_ms: 0,
            },
            DialCandidate {
                endpoint: healthy_endpoint,
                address: fixture.address,
                binding: BindingId::H2,
                failure_domain: 2,
                network_epoch: epoch,
                rtt_hint_ms: 1,
            },
        ],
        credential_trust_group: TRUST_GROUP,
        require_ech: false,
        require_unreliable: false,
    };
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("healthy H2 candidate");
    observed_tls.await.expect("first candidate completed TLS");
    assert_eq!(session.endpoint_id(), 2);
    assert_eq!(session.capabilities().binding, BindingId::H2);
    timeout(IO_TIMEOUT, stalled)
        .await
        .expect("stalled peer completion")
        .expect("stalled peer task");
    let mut stream = session
        .open_stream(&target_destination(), StreamOptions::default(), deadline())
        .await
        .expect("healthy stream");
    let payload = b"healthy-after-stalled-h2";
    write_all(&mut stream, payload).await;
    stream
        .end_write(deadline())
        .await
        .expect("healthy request FIN");
    assert_eq!(read_all(&mut stream).await.as_slice(), payload);
    drop(stream);
    assert_eq!(
        session
            .close(CloseMode::Graceful, deadline())
            .await
            .expect("healthy close"),
        CloseOutcome::Graceful
    );
    assert_eq!(fixture.endpoint_tcp_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.target_dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        engine
            .shutdown_with_deadline(deadline())
            .await
            .pending_connects,
        0
    );
    fixture.finish(vec![payload.to_vec()]).await;
}

#[tokio::test]
async fn accepted_stream_keeps_buffered_data_and_eof_after_the_tls_peer_closes() {
    let certificate = CertificateFixture::new(false);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("closing TLS listener");
    let address = listener.local_addr().expect("closing TLS address");
    let acceptor = TlsAcceptor::from(certificate.server_config(b"h2"));
    let (close_peer, close_requested) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("closing TLS accept");
        let tls = acceptor
            .accept(socket)
            .await
            .expect("closing TLS handshake");
        let mut connection = h2::server::handshake(tls)
            .await
            .expect("closing H2 handshake");
        let (request, mut respond) = connection
            .accept()
            .await
            .expect("closing CONNECT")
            .expect("closing request");
        let authorizer = StaticAuthorizer::new(credential(), 1);
        assert_eq!(
            check_h2_credential(&request, &authorizer)
                .expect("closing peer auth")
                .principal,
            1
        );
        let mut response = http::Response::new(());
        attach_h2_versions(response.headers_mut()).expect("closing response versions");
        let mut body = respond
            .send_response(response, false)
            .expect("closing response");
        body.send_data(Bytes::from(vec![0x7bu8; 1024]), true)
            .expect("closing response FIN");
        tokio::select! {
            _ = close_requested => {},
            extra = connection.accept() => panic!("unexpected request before transport close: {extra:?}"),
        }
        drop(body);
        drop(request);
        drop(connection);
    });
    let trust = certificate.pinned_policy();
    let services = HostServices::new(
        Arc::new(FixedResolver::new(address, Some(HOSTNAME))),
        Arc::new(DefaultSocketFactory),
        vec![trust],
        4,
    )
    .expect("closing host services");
    let engine = Engine::with_host_services(
        EngineConfig {
            limits: BudgetLimits::lab_small(),
        },
        Arc::new(services),
    )
    .expect("closing engine");
    let policy = EndpointPolicy::single(
        endpoint(HOSTNAME, BindingId::H2),
        address,
        NetworkEpoch::start(),
    )
    .expect("closing policy");
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("closing session");
    let mut stream = session
        .open_stream(&target_destination(), StreamOptions::default(), deadline())
        .await
        .expect("closing stream");
    stream
        .end_write(deadline())
        .await
        .expect("closing request FIN");
    let mut prefix = [0u8; 1];
    assert_eq!(
        stream
            .read(&mut prefix, deadline())
            .await
            .expect("closing prefix"),
        ReadOutcome::Data(1)
    );
    assert_eq!(prefix, [0x7b]);
    close_peer.send(()).expect("peer close request");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("peer close completion")
        .expect("peer close task");
    timeout(IO_TIMEOUT, async {
        while matches!(
            session.phase(),
            SessionPhase::Ready | SessionPhase::Draining
        ) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transport failure observed");
    assert!(matches!(
        session.phase(),
        SessionPhase::Failed | SessionPhase::Closed
    ));
    assert_eq!(read_all(&mut stream).await, vec![0x7b; 1023]);
    drop(stream);
    assert_eq!(
        engine
            .shutdown_with_deadline(deadline())
            .await
            .pending_connects,
        0
    );
}

#[tokio::test]
async fn one_verified_session_carries_two_independent_streams() {
    let fixture = Fixture::new(1, 2).await;
    let engine = fixture.engine(BudgetLimits::lab_small());
    let session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    assert_eq!(session.phase(), SessionPhase::Ready);
    assert_eq!(session.capabilities().binding, BindingId::H2);
    assert!(session.capabilities().tcp_streams);
    assert!(!session.capabilities().ech);
    let destination = target_destination();
    let unsupported = StreamOptions {
        require_binding: Some(BindingId::H3),
    };
    assert_eq!(
        session
            .open_stream(&destination, unsupported, deadline())
            .await
            .unwrap_err(),
        EngineError::UnsupportedCapability
    );
    assert_eq!(fixture.target_dials.load(Ordering::SeqCst), 0);
    let (first, second) = tokio::join!(
        session.open_stream(&destination, StreamOptions::default(), deadline()),
        session.open_stream(&destination, StreamOptions::default(), deadline()),
    );
    let mut first = first.expect("first stream");
    let mut second = second.expect("second stream");
    write_all(&mut first, b"first-stream").await;
    write_all(&mut second, b"second-stream").await;
    first.end_write(deadline()).await.expect("first half close");
    second
        .end_write(deadline())
        .await
        .expect("second half close");
    let (first_reply, second_reply) = tokio::join!(read_all(&mut first), read_all(&mut second));
    assert_eq!(first_reply, b"first-stream");
    assert_eq!(second_reply, b"second-stream");
    assert_eq!(fixture.endpoint_tcp_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.target_dials.load(Ordering::SeqCst), 2);
    drop((first, second));
    assert_eq!(
        session.close(CloseMode::Graceful, deadline()).await,
        Ok(CloseOutcome::Graceful)
    );
    assert_eq!(session.phase(), SessionPhase::Closed);
    assert_eq!(
        session
            .open_stream(&destination, StreamOptions::default(), deadline())
            .await
            .unwrap_err(),
        EngineError::ProtocolViolation
    );
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
    assert_eq!(report.forced_sessions, 0);
    fixture
        .finish(vec![b"first-stream".to_vec(), b"second-stream".to_vec()])
        .await;
}

#[tokio::test]
async fn new_network_epoch_drains_old_sessions_without_replay() {
    let fixture = Fixture::new(2, 2).await;
    let engine = fixture.engine(BudgetLimits::lab_small());
    let first_epoch = NetworkEpoch::start();
    let old_session = connect(&engine, &fixture, first_epoch).await;
    let destination = target_destination();
    let mut old_stream = old_session
        .open_stream(&destination, StreamOptions::default(), deadline())
        .await
        .expect("old stream");
    write_all(&mut old_stream, b"already-sent").await;
    old_stream
        .end_write(deadline())
        .await
        .expect("old half close");
    let next_epoch = first_epoch.advance().expect("next epoch");
    engine
        .on_network_change(next_epoch)
        .expect("network change");
    assert_eq!(old_session.phase(), SessionPhase::Draining);
    assert_eq!(
        old_session
            .open_stream(&destination, StreamOptions::default(), deadline())
            .await
            .unwrap_err(),
        EngineError::ProtocolViolation
    );
    let new_session = connect(&engine, &fixture, next_epoch).await;
    assert_eq!(new_session.network_epoch(), next_epoch);
    assert_eq!(old_session.network_epoch(), first_epoch);
    let mut new_stream = new_session
        .open_stream(&destination, StreamOptions::default(), deadline())
        .await
        .expect("new stream");
    write_all(&mut new_stream, b"new-operation").await;
    new_stream
        .end_write(deadline())
        .await
        .expect("new half close");
    assert_eq!(read_all(&mut old_stream).await, b"already-sent");
    assert_eq!(read_all(&mut new_stream).await, b"new-operation");
    drop((old_stream, new_stream));
    assert_eq!(
        old_session.close(CloseMode::Graceful, deadline()).await,
        Ok(CloseOutcome::Graceful)
    );
    assert_eq!(
        new_session.close(CloseMode::Graceful, deadline()).await,
        Ok(CloseOutcome::Graceful)
    );
    assert_eq!(fixture.endpoint_tcp_accepts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.target_dials.load(Ordering::SeqCst), 2);
    fixture
        .finish(vec![b"already-sent".to_vec(), b"new-operation".to_vec()])
        .await;
}

#[tokio::test]
async fn forced_close_releases_admission_while_old_handles_are_retained() {
    let fixture = Fixture::new(2, 2).await;
    let mut limits = BudgetLimits::lab_small();
    limits.active_sessions = 1;
    limits.active_flows_per_session = 1;
    limits.pending_egress_opens = 1;
    let engine = fixture.engine(limits);
    let old_session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    let destination = target_destination();
    let mut old_stream = old_session
        .open_stream(&destination, StreamOptions::default(), deadline())
        .await
        .expect("old stream");
    let old_payload = vec![0x7bu8; 1024];
    write_all(&mut old_stream, &old_payload).await;
    old_stream
        .end_write(deadline())
        .await
        .expect("old half close");
    let mut prefix = [0u8; 1];
    assert_eq!(
        old_stream
            .read(&mut prefix, deadline())
            .await
            .expect("prefix"),
        ReadOutcome::Data(1)
    );
    assert_eq!(prefix, [0x7b]);
    assert_eq!(
        old_session.close(CloseMode::Immediate, deadline()).await,
        Ok(CloseOutcome::Forced)
    );
    assert_eq!(old_session.phase(), SessionPhase::Closed);

    let new_session = connect(&engine, &fixture, NetworkEpoch::start()).await;
    let mut new_stream = new_session
        .open_stream(&destination, StreamOptions::default(), deadline())
        .await
        .expect("admission released before old handles are polled");
    write_all(&mut new_stream, b"replacement").await;
    new_stream
        .end_write(deadline())
        .await
        .expect("replacement half close");
    assert_eq!(read_all(&mut new_stream).await, b"replacement");
    prefix[0] = 0x55;
    assert_eq!(
        old_stream
            .read(&mut prefix, deadline())
            .await
            .expect("old cancellation"),
        ReadOutcome::Cancelled
    );
    assert_eq!(prefix, [0x55]);
    drop(new_stream);
    assert_eq!(
        new_session.close(CloseMode::Graceful, deadline()).await,
        Ok(CloseOutcome::Graceful)
    );
    fixture
        .finish(vec![old_payload, b"replacement".to_vec()])
        .await;
}

#[tokio::test]
async fn expired_connect_deadline_opens_no_tcp_connection() {
    let certificate = CertificateFixture::new(false);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let services = HostServices::new(
        Arc::new(FixedResolver::new(address, Some(HOSTNAME))),
        Arc::new(DefaultSocketFactory),
        vec![certificate.policy()],
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
    let policy = EndpointPolicy::single(
        endpoint(HOSTNAME, BindingId::H2),
        address,
        NetworkEpoch::start(),
    )
    .expect("policy");
    let result = engine
        .connect(&policy, credential(), Deadline::at(Instant::now()))
        .await;
    assert_eq!(result.unwrap_err(), EngineError::DeadlineExceeded);
    let mut accepted = Box::pin(listener.accept());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(accepted.as_mut().poll(cx).is_pending()))
            .await
    );
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
}

#[tokio::test]
async fn cancelling_h2_reclaims_flow_admission_and_preserves_retained_byte_charges() {
    let memory = MemoryBudget::new(8192).expect("process memory");
    let session_memory = MemoryBudget::new(8192).expect("session memory");
    let flows = ResourceBudget::new(1).expect("process flows");
    let session_flows = ResourceBudget::new(1).expect("session flows");
    let config = H2Config {
        direction_buffer_bytes: 1024,
        control_reserve_bytes: 64,
        max_concurrent_streams: 1,
        max_pending_opens: 1,
        process_budget: memory.clone(),
        session_budget: session_memory.clone(),
        process_flows: flows.clone(),
        session_flows: session_flows.clone(),
        process_opens: ResourceBudget::new(1).expect("process opens"),
        session_opens: ResourceBudget::new(1).expect("session opens"),
        ..H2Config::default()
    };
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let server = tokio::spawn(serve_h2_with_handler(
        server_io,
        H2Config::default(),
        |request, mut respond, _| async move {
            let mut response = http::Response::new(());
            attach_h2_versions(response.headers_mut())?;
            let mut send = respond
                .send_response(response, false)
                .map_err(|_| EngineError::TransportUnavailable)?;
            send.send_data(Bytes::from(vec![0x7bu8; 1024]), false)
                .map_err(|_| EngineError::TransportUnavailable)?;
            let _request = request;
            std::future::poll_fn(|cx| send.poll_reset(cx))
                .await
                .map_err(|_| EngineError::TransportUnavailable)?;
            Ok(())
        },
        std::future::pending::<()>(),
    ));
    let control_reserve_bytes = config.control_reserve_bytes;
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("H2 session");
    let memory_baseline = memory.used();
    let session_baseline = session_memory.used();
    let owner_memory = memory_baseline - control_reserve_bytes;
    assert!(owner_memory > 0);
    assert_eq!(session_baseline, memory_baseline);
    let mut stream = session
        .open_stream(&target_destination(), &credential())
        .await
        .expect("open");
    let mut prefix = [0u8; 1];
    assert_eq!(
        stream.read(&mut prefix).await.expect("prefix"),
        ReadOutcome::Data(1)
    );
    let retained = memory.used() - memory_baseline;
    assert!(retained >= 1024);
    assert_eq!(session_memory.used(), session_baseline + retained);
    assert_eq!(
        stream.read(&mut prefix).await.expect("second prefix"),
        ReadOutcome::Data(1)
    );
    assert_eq!(memory.used(), memory_baseline + retained);
    assert_eq!(session_memory.used(), session_baseline + retained);
    assert_eq!(flows.used(), 1);
    session.cancel();
    assert_eq!(session.close(IO_TIMEOUT).await, Err(EngineError::Cancelled));
    assert_eq!(
        memory.used(),
        owner_memory + retained,
        "retained allocation must remain charged after driver reserve is released"
    );
    assert_eq!(session_memory.used(), owner_memory + retained);
    assert_eq!(flows.used(), 0);
    assert_eq!(session_flows.used(), 0);
    stream.cancel().expect("discard retained data");
    let handle_memory = memory.used() - owner_memory;
    assert!(handle_memory > 0);
    assert_eq!(session_memory.used(), owner_memory + handle_memory);
    assert!(retained - handle_memory >= 1024);
    drop(stream);
    assert_eq!(memory.used(), owner_memory);
    assert_eq!(session_memory.used(), owner_memory);
    let result = timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join");
    assert!(
        matches!(result, Ok(()) | Err(EngineError::TransportUnavailable)),
        "{result:?}"
    );
    drop(session);
    assert_eq!(memory.used(), 0);
    assert_eq!(session_memory.used(), 0);
}

#[tokio::test]
async fn legacy_experimental_connect_without_version_headers_still_carries_data() {
    let fixture = Fixture::new(1, 1).await;
    let channel = fixture
        .host_services()
        .connect_verified(
            &endpoint(HOSTNAME, BindingId::H2),
            fixture.address,
            deadline(),
        )
        .await
        .expect("verified TLS");
    let session = H2Session::handshake(channel.into_io(), true)
        .await
        .expect("H2 session");
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("1.1.1.1:443")
        .body(())
        .expect("legacy CONNECT");
    let mut stream = session
        .open_request(request, &credential())
        .await
        .expect("legacy open");
    assert_eq!(stream.status(), http::StatusCode::OK);
    assert_eq!(stream.write(b"legacy-data").await.expect("write"), 11);
    stream.end_write().await.expect("half close");
    let mut reply = Vec::new();
    let mut buffer = [0u8; 3];
    loop {
        match stream.read(&mut buffer).await.expect("read") {
            ReadOutcome::Data(n) => reply.extend_from_slice(&buffer[..n]),
            ReadOutcome::Eof => break,
            outcome => panic!("unexpected read outcome: {outcome:?}"),
        }
    }
    assert_eq!(reply, b"legacy-data");
    drop(stream);
    session.close(IO_TIMEOUT).await.expect("close");
    fixture.finish(vec![b"legacy-data".to_vec()]).await;
}

#[tokio::test]
async fn timed_out_and_dropped_open_futures_return_pending_and_flow_permits() {
    let process_opens = ResourceBudget::new(1).expect("process opens");
    let session_opens = ResourceBudget::new(1).expect("session opens");
    let process_flows = ResourceBudget::new(1).expect("process flows");
    let session_flows = ResourceBudget::new(1).expect("session flows");
    let config = H2Config {
        max_concurrent_streams: 1,
        max_pending_opens: 1,
        process_opens: process_opens.clone(),
        session_opens: session_opens.clone(),
        process_flows: process_flows.clone(),
        session_flows: session_flows.clone(),
        ..H2Config::default()
    };
    let (accepted, mut requests) = tokio::sync::mpsc::channel(2);
    let (observed_resets, mut resets) = tokio::sync::mpsc::channel(2);
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let server = tokio::spawn(serve_h2_with_handler(
        server_io,
        H2Config::default(),
        move |request, mut respond, _| {
            let accepted = accepted.clone();
            let observed_resets = observed_resets.clone();
            async move {
                let _request = request;
                accepted
                    .send(())
                    .await
                    .map_err(|_| EngineError::Cancelled)?;
                let reset = std::future::poll_fn(|cx| respond.poll_reset(cx)).await;
                observed_resets
                    .send(reset)
                    .await
                    .map_err(|_| EngineError::Cancelled)?;
                Ok(())
            }
        },
        std::future::pending::<()>(),
    ));
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("session");
    for abort in [false, true] {
        let opening_session = session.clone();
        let opening = tokio::spawn(async move {
            let timeout = if abort {
                IO_TIMEOUT
            } else {
                Duration::from_millis(500)
            };
            opening_session
                .open_stream_with_deadline(
                    &target_destination(),
                    &credential(),
                    Deadline::after(timeout).expect("deadline"),
                )
                .await
        });
        assert_eq!(
            timeout(IO_TIMEOUT, requests.recv())
                .await
                .expect("request completion"),
            Some(())
        );
        assert_eq!(process_opens.used(), 1);
        assert_eq!(session_opens.used(), 1);
        if abort {
            opening.abort();
        }
        let opening_result = timeout(IO_TIMEOUT, opening)
            .await
            .expect("opening task completion");
        if abort {
            assert!(matches!(opening_result, Err(error) if error.is_cancelled()));
        } else {
            assert_eq!(
                opening_result.expect("opening join").err(),
                Some(EngineError::DeadlineExceeded)
            );
        }
        let reason = timeout(IO_TIMEOUT, resets.recv())
            .await
            .expect("reset observation deadline")
            .expect("reset observation")
            .expect("peer reset reason");
        assert_eq!(reason, h2::Reason::CANCEL, "aborted open: {abort}");
        assert_eq!(process_opens.used(), 0);
        assert_eq!(session_opens.used(), 0);
        assert_eq!(process_flows.used(), 0);
        assert_eq!(session_flows.used(), 0);
    }
    session.close(IO_TIMEOUT).await.expect("close");
    let result = timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join");
    assert!(
        matches!(result, Ok(()) | Err(EngineError::TransportUnavailable)),
        "{result:?}"
    );
}

struct CountingAuthorizer {
    inner: StaticAuthorizer,
    calls: Arc<AtomicUsize>,
}

impl Authorizer for CountingAuthorizer {
    fn authorize(&self, credential: &Credential) -> Result<AuthzDecision, EngineError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.authorize(credential)
    }
}

#[tokio::test]
async fn incompatible_wire_versions_are_rejected_before_authorization_or_dial() {
    #[derive(Debug, Clone, Copy)]
    enum VersionHeaderFailure {
        Missing,
        Duplicate,
        Unsupported,
        NonCanonical,
    }

    let authorizations = Arc::new(AtomicUsize::new(0));
    let dials = Arc::new(AtomicUsize::new(0));
    let dial_count = Arc::clone(&dials);
    let authorizer = CountingAuthorizer {
        inner: StaticAuthorizer::new(credential(), 1),
        calls: Arc::clone(&authorizations),
    };
    let (client_io, server_io) = tokio::io::duplex(8 * 1024);
    let server = tokio::spawn(serve_h2(
        server_io,
        Arc::new(authorizer),
        false,
        H2Config::default(),
        move |_| {
            dial_count.fetch_add(1, Ordering::SeqCst);
            async { Err::<tokio::io::DuplexStream, _>(EngineError::TargetConnectFailed) }
        },
        std::future::pending::<()>(),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
    let driver = tokio::spawn(connection);
    for name in [
        EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
        EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
    ] {
        for failure in [
            VersionHeaderFailure::Missing,
            VersionHeaderFailure::Duplicate,
            VersionHeaderFailure::Unsupported,
            VersionHeaderFailure::NonCanonical,
        ] {
            let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("1.1.1.1:443")
                .body(())
                .expect("request");
            attach_h2_versions(request.headers_mut()).expect("versions");
            match failure {
                VersionHeaderFailure::Missing => {
                    request.headers_mut().remove(name);
                }
                VersionHeaderFailure::Duplicate => {
                    request
                        .headers_mut()
                        .append(name, http::HeaderValue::from_static("0"));
                }
                VersionHeaderFailure::Unsupported => {
                    request
                        .headers_mut()
                        .insert(name, http::HeaderValue::from_static("1"));
                }
                VersionHeaderFailure::NonCanonical => {
                    request
                        .headers_mut()
                        .insert(name, http::HeaderValue::from_static("00"));
                }
            }
            attach_credential(&mut request, &credential()).expect("credential");
            client = client.ready().await.expect("ready");
            let (response, _) = client.send_request(request, true).expect("request send");
            let response = timeout(IO_TIMEOUT, response)
                .await
                .expect("response completion")
                .expect("response");
            assert_eq!(
                response.status(),
                http::StatusCode::NOT_FOUND,
                "{name}: {failure:?}"
            );
            assert_eq!(
                authorizations.load(Ordering::SeqCst),
                0,
                "{name}: {failure:?}"
            );
            assert_eq!(dials.load(Ordering::SeqCst), 0, "{name}: {failure:?}");
        }
    }
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://endpoint.test/")
        .header(EXPERIMENTAL_PROTOCOL_VERSION_HEADER, "1")
        .body(())
        .expect("site request");
    client = client.ready().await.expect("site ready");
    let (response, _) = client.send_request(request, true).expect("site send");
    let response = timeout(IO_TIMEOUT, response)
        .await
        .expect("site completion")
        .expect("site response");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    drop((response, client));
    driver.abort();
    assert!(matches!(driver.await, Err(error) if error.is_cancelled()));
    let result = timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join");
    assert!(
        matches!(result, Ok(()) | Err(EngineError::TransportUnavailable)),
        "{result:?}"
    );
}
