#![cfg(feature = "h3")]
#![forbid(unsafe_code)]

mod support;

#[path = "support/auth.rs"]
mod auth_support;

#[path = "support/lifecycle.rs"]
mod lifecycle_support;

#[path = "support/resolver.rs"]
mod resolver_support;

#[path = "support/native.rs"]
mod native_support;

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use ariad_core::{
    BindingId, BudgetLimits, DatagramOutcome, DeliveryMode, Destination, EngineError, MemoryBudget,
    NetworkEpoch, ResourceBudget,
};
use ariad_engine::{
    CloseMode, CloseOutcome, DatagramRequirements, Deadline, DefaultSocketFactory, EndpointPolicy,
    Engine, EngineConfig, EngineResources, H2Config, H2Session, H3Config, H3Incoming, H3ReadHalf,
    H3ServerSession, H3Session, H3WriteHalf, HostServices, NativeTlsConnector, ReadOutcome,
    SpkiPin, StaticAuthorizer, Stream, StreamOptions, check_h2_credential, serve_h2,
};
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use auth_support::credential;
use lifecycle_support::{assert_no_admission, assert_shutdown_complete, assert_tls_shutdown};
use resolver_support::FixedResolver;
use support::{CertificateFixture, HOSTNAME, TRUST_GROUP, endpoint, tcp_destination};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const PRINCIPAL: u64 = 17;

fn deadline() -> Deadline {
    Deadline::after(IO_TIMEOUT).expect("deadline")
}

fn udp_destination() -> Destination {
    Destination::parse("9.9.9.9:53").expect("UDP destination")
}

fn isolated_h2_config() -> H2Config {
    H2Config {
        process_budget: MemoryBudget::new(16 * 1024 * 1024).expect("process memory"),
        session_budget: MemoryBudget::new(4 * 1024 * 1024).expect("session memory"),
        process_flows: ResourceBudget::new(64).expect("process flows"),
        session_flows: ResourceBudget::new(64).expect("session flows"),
        process_opens: ResourceBudget::new(8).expect("process opens"),
        session_opens: ResourceBudget::new(8).expect("session opens"),
        ..H2Config::default()
    }
}

fn h3_config() -> H3Config {
    H3Config::from_h2_config(&isolated_h2_config()).expect("H3 config")
}

fn engine(certificate: &CertificateFixture, proxy_address: SocketAddr, pin: SpkiPin) -> Engine {
    engine_with_resources(certificate, proxy_address, pin).0
}

fn engine_with_resources(
    certificate: &CertificateFixture,
    proxy_address: SocketAddr,
    pin: SpkiPin,
) -> (Engine, Arc<EngineResources>) {
    let trust = certificate
        .policy()
        .with_spki_pins(vec![pin])
        .expect("pin policy");
    let services = HostServices::new(
        Arc::new(FixedResolver::new(proxy_address, None)),
        Arc::new(DefaultSocketFactory),
        vec![trust],
        4,
    )
    .expect("host services");
    let limits = BudgetLimits::lab_small();
    let resources = Arc::new(EngineResources::new(limits).expect("Engine resources"));
    let engine = Engine::with_host_services_and_resources(
        EngineConfig { limits },
        Arc::new(services),
        resources.clone(),
    )
    .expect("engine");
    (engine, resources)
}

fn assert_resources_released(resources: &EngineResources) {
    assert_no_admission(resources);
    assert_eq!(resources.application_memory_used(), 0);
}

async fn tcp_echo_targets(connection_count: usize) -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP target listener");
    let address = listener.local_addr().expect("TCP target address");
    let task = tokio::spawn(async move {
        let mut targets = JoinSet::new();
        for _ in 0..connection_count {
            let (mut socket, _) = listener.accept().await.expect("TCP target accept");
            targets.spawn(async move {
                let mut payload = Vec::new();
                socket
                    .read_to_end(&mut payload)
                    .await
                    .expect("TCP target request");
                assert!(payload.len() <= 64 * 1024);
                socket.write_all(&payload).await.expect("TCP target reply");
                socket.shutdown().await.expect("TCP target FIN");
                payload
            });
        }
        let mut payloads = Vec::new();
        while let Some(result) = targets.join_next().await {
            payloads.push(result.expect("TCP target join"));
        }
        payloads
    });
    (address, task)
}

async fn tcp_duplex_target(
    request_bytes: usize,
    response: Vec<u8>,
) -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("duplex target bind");
    let address = listener.local_addr().expect("duplex target address");
    let (request_received, wait_request_received) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("duplex target accept");
        let (mut reader, mut writer) = socket.into_split();
        let mut first = [0u8; 1];
        reader
            .read_exact(&mut first)
            .await
            .expect("first request byte");
        let receiving = async move {
            let mut request = first.to_vec();
            reader
                .take(request_bytes as u64)
                .read_to_end(&mut request)
                .await
                .expect("duplex target request");
            request
        };
        let sending = async move {
            writer
                .write_all(&response)
                .await
                .expect("independent target reply");
            writer.shutdown().await.expect("duplex target FIN");
        };
        let (request, ()) = tokio::join!(receiving, sending);
        request_received
            .send(())
            .expect("request completion signal");
        vec![request]
    });
    (address, task, wait_request_received)
}

async fn udp_echo_target(message_count: usize) -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP target bind");
    let address = socket.local_addr().expect("UDP target address");
    let task = tokio::spawn(async move {
        let mut payloads = Vec::new();
        let mut buffer = [0u8; 65_536];
        for _ in 0..message_count {
            let (length, peer) = socket
                .recv_from(&mut buffer)
                .await
                .expect("UDP target request");
            payloads.push(buffer[..length].to_vec());
            assert_eq!(
                socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("UDP target reply"),
                length
            );
        }
        payloads
    });
    (address, task)
}

async fn h3_write_all(stream: &mut H3WriteHalf, mut remaining: &[u8]) {
    while !remaining.is_empty() {
        let length = stream.write(remaining, deadline()).await.expect("H3 write");
        assert!(length > 0 && length <= remaining.len());
        remaining = &remaining[length..];
    }
}

async fn h3_read_all(stream: &mut H3ReadHalf) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut buffer = [0u8; 3];
    loop {
        match stream.read(&mut buffer, deadline()).await.expect("H3 read") {
            ReadOutcome::Data(length) => {
                assert!(length > 0 && length <= buffer.len());
                assert!(payload.len() + length <= 64 * 1024);
                payload.extend_from_slice(&buffer[..length]);
            }
            ReadOutcome::Eof => return payload,
            outcome => panic!("unexpected H3 read outcome: {outcome:?}"),
        }
    }
}

async fn stream_exchange(stream: Stream, payload: &[u8]) -> Vec<u8> {
    let (mut reader, mut writer) = stream.into_split();
    let sending = async move {
        let mut remaining = payload;
        while !remaining.is_empty() {
            let length = writer
                .write(remaining, deadline())
                .await
                .expect("stream write");
            assert!(length > 0 && length <= remaining.len());
            remaining = &remaining[length..];
        }
        writer.end_write(deadline()).await.expect("stream FIN");
    };
    let receiving = async move {
        let mut reply = Vec::new();
        let mut buffer = [0u8; 3];
        loop {
            match reader
                .read(&mut buffer, deadline())
                .await
                .expect("stream read")
            {
                ReadOutcome::Data(length) => {
                    assert!(length > 0 && length <= buffer.len());
                    assert!(reply.len() + length <= 64 * 1024);
                    reply.extend_from_slice(&buffer[..length]);
                }
                ReadOutcome::Eof => return reply,
                outcome => panic!("unexpected stream read outcome: {outcome:?}"),
            }
        }
    };
    let ((), reply) = tokio::join!(sending, receiving);
    reply
}

async fn relay_tcp(incoming: H3Incoming, target_address: SocketAddr) {
    let target_socket = TcpStream::connect(target_address)
        .await
        .expect("authorized TCP target dial");
    let stream = incoming
        .respond(StatusCode::OK, deadline())
        .await
        .expect("TCP response");
    let (mut request, mut response) = stream.into_split();
    let (mut target_read, mut target_write) = target_socket.into_split();
    let to_target = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match request
                .read(&mut buffer, deadline())
                .await
                .expect("TCP request body")
            {
                ReadOutcome::Data(length) => target_write
                    .write_all(&buffer[..length])
                    .await
                    .expect("TCP target write"),
                ReadOutcome::Eof => break,
                outcome => panic!("unexpected TCP request outcome: {outcome:?}"),
            }
        }
        target_write
            .shutdown()
            .await
            .expect("TCP target request FIN");
    };
    let from_target = async move {
        let mut buffer = [0u8; 4096];
        loop {
            let length = target_read
                .read(&mut buffer)
                .await
                .expect("TCP target read");
            if length == 0 {
                break;
            }
            h3_write_all(&mut response, &buffer[..length]).await;
        }
        response
            .end_write(deadline())
            .await
            .expect("TCP response FIN");
    };
    tokio::join!(to_target, from_target);
}

async fn relay_datagrams(
    incoming: H3Incoming,
    target: SocketAddr,
    message_count: usize,
    mut client_done: watch::Receiver<bool>,
) {
    let target_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("authorized UDP socket");
    target_socket
        .connect(target)
        .await
        .expect("authorized UDP target dial");
    let mut association = incoming
        .respond_datagram(77, deadline())
        .await
        .expect("datagram response");
    assert_eq!(association.delivery_mode(), DeliveryMode::UnreliableNative);
    let mut buffer = [0u8; 65_536];
    for _ in 0..message_count {
        let payload = association
            .recv(deadline())
            .await
            .expect("native datagram request");
        assert!(payload.len() <= association.max_payload());
        assert_eq!(
            target_socket
                .send(payload.as_bytes())
                .await
                .expect("UDP target write"),
            payload.len()
        );
        let length = target_socket
            .recv(&mut buffer)
            .await
            .expect("UDP target read");
        assert_eq!(&buffer[..length], payload.as_bytes());
        assert_eq!(
            association
                .send(&buffer[..length], deadline())
                .await
                .expect("native datagram reply"),
            DatagramOutcome::Queued
        );
    }
    // The client must receive the last reply before the server cancels the flow.
    while !*client_done.borrow_and_update() {
        client_done
            .changed()
            .await
            .expect("datagram completion signal");
    }
    association.close().expect("server datagram close");
}

struct H3Fixture {
    certificate: CertificateFixture,
    server_address: SocketAddr,
    authorized_requests: Arc<AtomicUsize>,
    client_done: watch::Sender<bool>,
    server: JoinHandle<()>,
    tcp_targets: JoinHandle<Vec<Vec<u8>>>,
    udp_target: Option<JoinHandle<Vec<Vec<u8>>>>,
    memory_budget: MemoryBudget,
    flow_budget: ResourceBudget,
    open_budget: ResourceBudget,
}

impl H3Fixture {
    async fn new(tcp_opens: usize, datagram_messages: Option<usize>) -> Self {
        let (tcp_address, tcp_targets) = tcp_echo_targets(tcp_opens).await;
        Self::with_tcp_target(tcp_opens, datagram_messages, tcp_address, tcp_targets).await
    }

    async fn with_tcp_target(
        tcp_opens: usize,
        datagram_messages: Option<usize>,
        tcp_address: SocketAddr,
        tcp_targets: JoinHandle<Vec<Vec<u8>>>,
    ) -> Self {
        let certificate = CertificateFixture::new(false);
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("exclusive H3 server socket");
        let address = socket.local_addr().expect("H3 server address");
        let tls = certificate.native_server();
        let config = h3_config();
        let memory_budget = config.h2.process_budget.clone();
        let flow_budget = config.h2.process_flows.clone();
        let open_budget = config.h2.process_opens.clone();
        let (udp_address, udp_target) = match datagram_messages {
            Some(messages) => {
                let (address, task) = udp_echo_target(messages).await;
                (Some(address), Some(task))
            }
            None => (None, None),
        };
        let authorized_requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&authorized_requests);
        let (client_done, mut client_done_receiver) = watch::channel(false);
        let server = tokio::spawn(async move {
            let mut session = H3ServerSession::accept(socket, &tls, config, deadline())
                .await
                .expect("H3 server readiness");
            let authorizer = StaticAuthorizer::new(credential(), PRINCIPAL);
            let mut handlers = JoinSet::new();
            for _ in 0..tcp_opens + usize::from(datagram_messages.is_some()) {
                let incoming = session
                    .incoming(deadline())
                    .await
                    .expect("H3 incoming request");
                let decision =
                    check_h2_credential(&incoming.request, &authorizer).expect("credential gate");
                assert_eq!(decision.principal, PRINCIPAL);
                observed.fetch_add(1, Ordering::SeqCst);
                if incoming.is_datagram() {
                    assert_eq!(
                        incoming.destination().expect("UDP destination"),
                        udp_destination()
                    );
                    let target = udp_address.expect("UDP target enabled");
                    let messages = datagram_messages.expect("UDP messages configured");
                    handlers.spawn(relay_datagrams(
                        incoming,
                        target,
                        messages,
                        client_done_receiver.clone(),
                    ));
                } else {
                    assert_eq!(
                        incoming.destination().expect("TCP destination"),
                        tcp_destination()
                    );
                    handlers.spawn(relay_tcp(incoming, tcp_address));
                }
            }
            while !*client_done_receiver.borrow_and_update() {
                client_done_receiver
                    .changed()
                    .await
                    .expect("client completion signal");
            }
            while let Some(result) = handlers.join_next().await {
                result.expect("H3 handler join");
            }
            session.cancel();
            assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
        });
        Self {
            certificate,
            server_address: address,
            authorized_requests,
            client_done,
            server,
            tcp_targets,
            udp_target,
            memory_budget,
            flow_budget,
            open_budget,
        }
    }

    async fn finish(
        self,
        mut expected_tcp_payloads: Vec<Vec<u8>>,
        expected_datagram_payloads: Vec<Vec<u8>>,
    ) {
        self.client_done.send_replace(true);
        timeout(IO_TIMEOUT, self.server)
            .await
            .expect("H3 server completion")
            .expect("H3 server task");
        let mut observed_tcp_payloads = timeout(IO_TIMEOUT, self.tcp_targets)
            .await
            .expect("TCP targets completion")
            .expect("TCP targets task");
        observed_tcp_payloads.sort();
        expected_tcp_payloads.sort();
        assert_eq!(observed_tcp_payloads, expected_tcp_payloads);
        if let Some(target) = self.udp_target {
            assert_eq!(
                timeout(IO_TIMEOUT, target)
                    .await
                    .expect("UDP target completion")
                    .expect("UDP target task"),
                expected_datagram_payloads
            );
        } else {
            assert!(expected_datagram_payloads.is_empty());
        }
        assert_eq!(self.memory_budget.used(), 0);
        assert_eq!(self.flow_budget.used(), 0);
        assert_eq!(self.open_budget.used(), 0);
    }
}

#[tokio::test]
async fn native_tls_h2_reaches_a_real_tcp_target_after_authentication() {
    let certificate = CertificateFixture::new(false);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("native TLS listener");
    let address = listener.local_addr().expect("native TLS address");
    let tls = certificate.native_server();
    let (target_address, target) = tcp_echo_targets(1).await;
    let dials = Arc::new(AtomicUsize::new(0));
    let observed_dials = Arc::clone(&dials);
    let server_config = isolated_h2_config();
    let server_memory_budget = server_config.process_budget.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("native TLS accept");
        let tls = tls
            .accept(socket, deadline())
            .await
            .expect("native TLS handshake");
        serve_h2(
            tls,
            Arc::new(StaticAuthorizer::new(credential(), PRINCIPAL)),
            false,
            server_config,
            move |destination| {
                let observed = Arc::clone(&observed_dials);
                async move {
                    assert_eq!(destination, tcp_destination());
                    observed.fetch_add(1, Ordering::SeqCst);
                    TcpStream::connect(target_address)
                        .await
                        .map_err(|_| EngineError::TargetConnectFailed)
                }
            },
            std::future::pending::<()>(),
        )
        .await
    });
    let trust = certificate.pinned_policy();
    let connector = NativeTlsConnector::new(trust).expect("native connector");
    let socket = TcpStream::connect(address)
        .await
        .expect("native client socket");
    let verified = connector
        .connect(
            &endpoint(HOSTNAME, BindingId::H2),
            socket,
            address,
            deadline(),
        )
        .await
        .expect("native verified channel");
    assert_eq!(verified.binding(), BindingId::H2);
    assert_eq!(verified.trust_group(), TRUST_GROUP);
    let client_config = isolated_h2_config();
    let memory_budget = client_config.process_budget.clone();
    let session =
        H2Session::handshake_with_deadline(verified.into_io(), true, client_config, deadline())
            .await
            .expect("native H2 ready");
    let mut stream = session
        .open_stream_with_deadline(&tcp_destination(), &credential(), deadline())
        .await
        .expect("native H2 CONNECT");
    let payload = b"native-tls-h2-echo";
    let mut remaining = payload.as_slice();
    while !remaining.is_empty() {
        let written = deadline()
            .run(stream.write(remaining))
            .await
            .expect("native H2 write");
        assert!(written > 0 && written <= remaining.len());
        remaining = &remaining[written..];
    }
    deadline()
        .run(stream.end_write())
        .await
        .expect("native H2 FIN");
    let mut response = Vec::new();
    let mut buffer = [0u8; 3];
    loop {
        match deadline()
            .run(stream.read(&mut buffer))
            .await
            .expect("native H2 read")
        {
            ReadOutcome::Data(length) => {
                assert!(length > 0 && length <= buffer.len());
                assert!(response.len() + length <= 64 * 1024);
                response.extend_from_slice(&buffer[..length]);
            }
            ReadOutcome::Eof => break,
            outcome => panic!("unexpected native H2 outcome: {outcome:?}"),
        }
    }
    assert_eq!(response.as_slice(), payload);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    drop(stream);
    session
        .close_with_deadline(deadline())
        .await
        .expect("native H2 close");
    let result = timeout(IO_TIMEOUT, server)
        .await
        .expect("native H2 server completion")
        .expect("native H2 server task");
    assert_tls_shutdown(result, None);
    assert_eq!(
        timeout(IO_TIMEOUT, target)
            .await
            .expect("native target completion")
            .expect("native target task"),
        vec![payload.to_vec()]
    );
    assert!(memory_budget.used() > 0);
    drop(session);
    assert_eq!(memory_budget.used(), 0);
    assert_eq!(server_memory_budget.used(), 0);
}

#[tokio::test]
async fn native_h3_session_reaches_a_real_tcp_target() {
    let fixture = H3Fixture::new(1, None).await;
    let trust = fixture.certificate.pinned_policy();
    let connector = NativeTlsConnector::new(trust).expect("H3 connector");
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("exclusive H3 client socket");
    let config = h3_config();
    let memory_budget = config.h2.process_budget.clone();
    let session = H3Session::connect(
        socket,
        &endpoint(HOSTNAME, BindingId::H3),
        fixture.server_address,
        &connector,
        config,
        deadline(),
    )
    .await
    .expect("H3 ready");
    assert_eq!(session.binding(), BindingId::H3);
    assert_eq!(session.trust_group(), TRUST_GROUP);
    assert!(session.extended_connect_enabled());
    let stream = session
        .open_tcp(&tcp_destination(), &credential(), deadline())
        .await
        .expect("H3 CONNECT");
    assert_eq!(stream.status(), StatusCode::OK);
    let payload = b"native-quic-h3-echo";
    let (mut reader, mut writer) = stream.into_split();
    let ((), reply) = tokio::join!(
        async move {
            h3_write_all(&mut writer, payload).await;
            writer.end_write(deadline()).await.expect("H3 request FIN");
        },
        h3_read_all(&mut reader),
    );
    assert_eq!(reply.as_slice(), payload);
    assert_eq!(fixture.authorized_requests.load(Ordering::SeqCst), 1);
    drop(reader);
    session.cancel();
    assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
    assert!(memory_budget.used() > 0);
    drop(session);
    assert_eq!(memory_budget.used(), 0);
    fixture.finish(vec![payload.to_vec()], Vec::new()).await;
}

#[tokio::test]
async fn native_h3_datagrams_keep_whole_messages_and_charge_empty_retained_payloads() {
    let payloads = vec![Vec::new(), b"one-native-message".to_vec(), vec![0xa5; 512]];
    let fixture = H3Fixture::new(0, Some(payloads.len())).await;
    let connector = NativeTlsConnector::new(fixture.certificate.policy()).expect("H3 connector");
    let config = h3_config();
    let memory_budget = config.h2.process_budget.clone();
    let flow_budget = config.h2.process_flows.clone();
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("exclusive H3 client socket");
    let session = H3Session::connect(
        socket,
        &endpoint(HOSTNAME, BindingId::H3),
        fixture.server_address,
        &connector,
        config,
        deadline(),
    )
    .await
    .expect("H3 ready");
    assert!(session.native_datagram_enabled());
    let proxy = format!("{HOSTNAME}:{}", fixture.server_address.port());
    let association = session
        .open_datagram(&proxy, &udp_destination(), &credential(), 12, deadline())
        .await
        .expect("native CONNECT-UDP");
    assert_eq!(association.delivery_mode(), DeliveryMode::UnreliableNative);
    assert_eq!(association.generation(), 12);
    assert!(association.max_payload() >= 512);
    let (mut sender, mut receiver) = association.into_split();
    for payload in &payloads {
        let (received, sent) =
            tokio::join!(receiver.recv(deadline()), sender.send(payload, deadline()));
        assert_eq!(sent.expect("native datagram send"), DatagramOutcome::Queued);
        let received = received.expect("native datagram recv");
        assert_eq!(received.as_bytes(), payload.as_slice());
        let retained = memory_budget.used();
        drop(received);
        assert!(
            memory_budget.used() < retained,
            "each payload owner, including an empty payload, holds a reservation"
        );
    }
    let oversized = vec![0u8; sender.max_payload() + 1];
    assert_eq!(
        sender.send(&oversized, deadline()).await,
        Err(EngineError::MessageTooLarge)
    );
    sender.close().expect("client datagram close");
    drop(sender);
    drop(receiver);
    session.cancel();
    assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
    assert_eq!(flow_budget.used(), 0);
    assert!(memory_budget.used() > 0);
    drop(session);
    assert_eq!(memory_budget.used(), 0);
    assert_eq!(fixture.authorized_requests.load(Ordering::SeqCst), 1);
    fixture.finish(Vec::new(), payloads).await;
}

#[tokio::test]
async fn native_h3_split_datagrams_receive_unsolicited_data_and_cancel_pending_recv() {
    let certificate = CertificateFixture::new(false);
    let (target_address, target) = udp_echo_target(1).await;
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP split server bind");
    let address = socket.local_addr().expect("UDP split server address");
    let tls = certificate.native_server();
    let server_config = h3_config();
    let server_memory = server_config.h2.process_budget.clone();
    let server_flows = server_config.h2.process_flows.clone();
    let server_opens = server_config.h2.process_opens.clone();
    let (observed_reset, wait_reset) = oneshot::channel();
    let (client_done, wait_client_done) = oneshot::channel();
    let (client_opened, wait_client_opened) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut session = H3ServerSession::accept(socket, &tls, server_config, deadline())
            .await
            .expect("UDP split server ready");
        let incoming = session
            .incoming(deadline())
            .await
            .expect("UDP split incoming");
        let authorizer = StaticAuthorizer::new(credential(), PRINCIPAL);
        assert_eq!(
            check_h2_credential(&incoming.request, &authorizer)
                .expect("UDP split authentication")
                .principal,
            PRINCIPAL
        );
        assert_eq!(
            incoming.destination().expect("UDP split destination"),
            udp_destination()
        );
        let target_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP split target socket");
        target_socket
            .connect(target_address)
            .await
            .expect("UDP split authorized target");
        let association = incoming
            .respond_datagram(77, deadline())
            .await
            .expect("UDP split response");
        let (mut sender, mut receiver) = association.into_split();
        // Native datagrams can arrive before response headers and are then discarded.
        wait_client_opened.await.expect("client association ready");
        assert_eq!(
            sender
                .send(b"peer-first", deadline())
                .await
                .expect("unsolicited datagram"),
            DatagramOutcome::Queued
        );
        let request = receiver
            .recv(deadline())
            .await
            .expect("split datagram request");
        let observed_request = request.as_bytes().to_vec();
        assert_eq!(
            target_socket
                .send(request.as_bytes())
                .await
                .expect("UDP split target write"),
            request.len()
        );
        let mut target_reply = [0u8; 64];
        let length = target_socket
            .recv(&mut target_reply)
            .await
            .expect("UDP split target reply");
        assert_eq!(&target_reply[..length], request.as_bytes());
        drop(request);
        assert_eq!(
            sender.send(b"", deadline()).await.expect("empty reply"),
            DatagramOutcome::Queued
        );
        let result = receiver
            .recv(deadline())
            .await
            .map(|payload| payload.as_bytes().to_vec());
        observed_reset
            .send((observed_request, result))
            .expect("UDP reset observation");
        drop(sender);
        drop(receiver);
        wait_client_done.await.expect("UDP client completion");
        session.cancel();
        assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
    });
    let connector = NativeTlsConnector::new(certificate.policy()).expect("UDP split trust");
    let config = h3_config();
    let memory = config.h2.process_budget.clone();
    let flows = config.h2.process_flows.clone();
    let opens = config.h2.process_opens.clone();
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP split client bind");
    let session = H3Session::connect(
        socket,
        &endpoint(HOSTNAME, BindingId::H3),
        address,
        &connector,
        config,
        deadline(),
    )
    .await
    .expect("UDP split client ready");
    let proxy = format!("{HOSTNAME}:{}", address.port());
    let association = session
        .open_datagram(&proxy, &udp_destination(), &credential(), 12, deadline())
        .await
        .expect("UDP split association");
    let (mut sender, mut receiver) = association.into_split();
    assert_eq!(sender.generation(), receiver.generation());
    assert_eq!(sender.delivery_mode(), receiver.delivery_mode());
    client_opened.send(()).expect("client association ready");
    assert_eq!(
        receiver
            .recv(deadline())
            .await
            .expect("unsolicited payload")
            .as_bytes(),
        b"peer-first"
    );
    let retained_empty = {
        let pending = receiver.recv(deadline());
        tokio::pin!(pending);
        assert!(poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await);
        assert_eq!(
            sender
                .send(b"client-payload", deadline())
                .await
                .expect("send alongside pending recv"),
            DatagramOutcome::Queued
        );
        pending.await.expect("retained empty payload")
    };
    assert!(retained_empty.is_empty());
    let control = sender.control();
    {
        let pending = receiver.recv(deadline());
        tokio::pin!(pending);
        assert!(poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await);
        control.close().expect("UDP control close");
        assert!(matches!(pending.await, Err(EngineError::ProtocolViolation)));
    }
    assert_eq!(
        sender.send(b"late", deadline()).await,
        Err(EngineError::ProtocolViolation)
    );
    let (request, reset) = timeout(IO_TIMEOUT, wait_reset)
        .await
        .expect("UDP wire reset deadline")
        .expect("UDP wire reset signal");
    assert_eq!(request.as_slice(), b"client-payload");
    assert_eq!(reset, Err(EngineError::RemoteReset));
    drop(sender);
    drop(receiver);
    drop(control);
    session.cancel();
    assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
    drop(session);
    assert_eq!(flows.used(), 0);
    assert_eq!(opens.used(), 0);
    assert!(
        memory.used() > 0,
        "an empty payload still owns its charged allocation"
    );
    drop(retained_empty);
    assert_eq!(memory.used(), 0);
    client_done.send(()).expect("UDP server completion signal");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("UDP split server completion")
        .expect("UDP split server task");
    assert_eq!(server_memory.used(), 0);
    assert_eq!(server_flows.used(), 0);
    assert_eq!(server_opens.used(), 0);
    assert_eq!(
        timeout(IO_TIMEOUT, target)
            .await
            .expect("UDP split target completion")
            .expect("UDP split target task"),
        vec![b"client-payload".to_vec()]
    );
}

#[tokio::test]
async fn engine_explicit_h3_uses_one_native_session_for_streams_and_datagrams() {
    let datagrams = vec![b"engine-native-datagram".to_vec()];
    let fixture = H3Fixture::new(2, Some(datagrams.len())).await;
    let engine = engine(
        &fixture.certificate,
        fixture.server_address,
        fixture.certificate.pin,
    );
    let mut policy = EndpointPolicy::single_binding(
        endpoint(HOSTNAME, BindingId::H3),
        fixture.server_address,
        NetworkEpoch::start(),
        BindingId::H3,
    )
    .expect("H3 policy");
    policy.require_unreliable = true;
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("Engine H3 session");
    assert_eq!(session.capabilities().binding, BindingId::H3);
    assert!(session.capabilities().extended_connect);
    assert_eq!(
        session.capabilities().datagram_delivery,
        DeliveryMode::Unsupported
    );
    let destination = tcp_destination();
    let (first, second) = tokio::join!(
        session.open_stream(
            &destination,
            StreamOptions {
                require_binding: Some(BindingId::H3)
            },
            deadline()
        ),
        session.open_stream(&destination, StreamOptions::default(), deadline()),
    );
    let first = first.expect("first Engine H3 stream");
    let second = second.expect("second Engine H3 stream");
    let first_payload = b"engine-h3-first";
    let second_payload = b"engine-h3-second";
    let (first_reply, second_reply) = tokio::join!(
        stream_exchange(first, first_payload),
        stream_exchange(second, second_payload),
    );
    assert_eq!(first_reply.as_slice(), first_payload);
    assert_eq!(second_reply.as_slice(), second_payload);
    let association = session
        .open_datagram_association(
            &udp_destination(),
            DatagramRequirements {
                require_unreliable: true,
            },
            deadline(),
        )
        .await
        .expect("Engine native association");
    assert_eq!(association.delivery_mode(), DeliveryMode::UnreliableNative);
    assert_eq!(
        session.capabilities().datagram_delivery,
        DeliveryMode::UnreliableNative
    );
    let (mut sender, mut receiver) = association.into_split();
    let (sent, received) = tokio::join!(
        sender.send(&datagrams[0], deadline()),
        receiver.recv(deadline())
    );
    assert_eq!(sent.expect("Engine datagram send"), DatagramOutcome::Queued);
    assert_eq!(
        received.expect("Engine datagram reply").as_bytes(),
        datagrams[0].as_slice()
    );
    sender.close().expect("Engine association close");
    drop(sender);
    drop(receiver);
    assert_eq!(fixture.authorized_requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        session
            .close(CloseMode::Immediate, deadline())
            .await
            .expect("Engine H3 close"),
        CloseOutcome::Forced
    );
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
    fixture
        .finish(
            vec![first_payload.to_vec(), second_payload.to_vec()],
            datagrams,
        )
        .await;
}

#[tokio::test]
async fn engine_h3_split_stream_transfers_independent_payloads_before_request_fin() {
    let request: Vec<u8> = (0..2 * 1024 * 1024 + 17)
        .map(|index| (index % 251) as u8)
        .collect();
    let response: Vec<u8> = (0..2 * 1024 * 1024 + 29)
        .map(|index| (index % 239) as u8 ^ 0xa5)
        .collect();
    assert!(request.len() > h3_config().h2.initial_connection_window as usize);
    assert!(response.len() > h3_config().h2.initial_connection_window as usize);
    let (target_address, target, request_received) =
        tcp_duplex_target(request.len(), response.clone()).await;
    let fixture = H3Fixture::with_tcp_target(1, None, target_address, target).await;
    let (engine, resources) = engine_with_resources(
        &fixture.certificate,
        fixture.server_address,
        fixture.certificate.pin,
    );
    let policy = EndpointPolicy::single_binding(
        endpoint(HOSTNAME, BindingId::H3),
        fixture.server_address,
        NetworkEpoch::start(),
        BindingId::H3,
    )
    .expect("duplex H3 policy");
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("duplex session");
    let stream = session
        .open_stream(&tcp_destination(), StreamOptions::default(), deadline())
        .await
        .expect("duplex stream");
    let (mut reader, mut writer) = stream.into_split();
    let (read_started, wait_read_started) = oneshot::channel();
    let (response_started, wait_response_started) = oneshot::channel();
    let response_bytes = response.len();
    let receiving = async move {
        let mut first = [0u8; 1];
        let outcome = {
            let pending = reader.read(&mut first, deadline());
            tokio::pin!(pending);
            assert!(
                poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await
            );
            read_started.send(()).expect("pending read signal");
            pending.await.expect("first response byte")
        };
        assert_eq!(outcome, ReadOutcome::Data(1));
        response_started.send(()).expect("early response signal");
        let mut reply = first.to_vec();
        let mut buffer = [0u8; 4096];
        loop {
            match reader
                .read(&mut buffer, deadline())
                .await
                .expect("duplex response")
            {
                ReadOutcome::Data(length) => {
                    assert!(length > 0 && length <= buffer.len());
                    assert!(reply.len() + length <= response_bytes);
                    reply.extend_from_slice(&buffer[..length]);
                }
                ReadOutcome::Eof => return reply,
                outcome => panic!("unexpected duplex response: {outcome:?}"),
            }
        }
    };
    let sending = async {
        wait_read_started
            .await
            .expect("reader is pending before write");
        assert_eq!(
            writer
                .write(&request[..1], deadline())
                .await
                .expect("request prefix"),
            1
        );
        wait_response_started
            .await
            .expect("response starts before remaining request and FIN");
        let mut remaining = &request[1..];
        while !remaining.is_empty() {
            let written = writer
                .write(remaining, deadline())
                .await
                .expect("duplex request");
            assert!(written > 0 && written <= remaining.len());
            remaining = &remaining[written..];
        }
        writer.end_write(deadline()).await.expect("request FIN");
        drop(writer);
    };
    let (reply, ()) = timeout(IO_TIMEOUT, async { tokio::join!(receiving, sending) })
        .await
        .expect("public full-duplex progress");
    assert_eq!(reply, response);
    // Queuing FIN does not acknowledge peer receipt before an immediate close.
    timeout(IO_TIMEOUT, request_received)
        .await
        .expect("target request completion")
        .expect("target request signal");
    assert_eq!(fixture.authorized_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        session
            .close(CloseMode::Immediate, deadline())
            .await
            .expect("duplex session close"),
        CloseOutcome::Forced
    );
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
    drop(session);
    drop(engine);
    assert_resources_released(&resources);
    fixture.finish(vec![request], Vec::new()).await;
}

#[tokio::test]
async fn engine_h3_control_cancels_pending_split_io_and_releases_permits() {
    let certificate = CertificateFixture::new(false);
    let (target_address, target) = tcp_echo_targets(1).await;
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("cancel server bind");
    let address = socket.local_addr().expect("cancel server address");
    let tls = certificate.native_server();
    let config = h3_config();
    let server_memory = config.h2.process_budget.clone();
    let server_flows = config.h2.process_flows.clone();
    let server_opens = config.h2.process_opens.clone();
    let (observed_reset, reset_received) = oneshot::channel();
    let (client_done, wait_client_done) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut session = H3ServerSession::accept(socket, &tls, config, deadline())
            .await
            .expect("cancel server ready");
        let incoming = session.incoming(deadline()).await.expect("cancel incoming");
        let authorizer = StaticAuthorizer::new(credential(), PRINCIPAL);
        assert_eq!(
            check_h2_credential(&incoming.request, &authorizer)
                .expect("cancel authentication")
                .principal,
            PRINCIPAL
        );
        assert_eq!(
            incoming.destination().expect("cancel destination"),
            tcp_destination()
        );
        let target_socket = TcpStream::connect(target_address)
            .await
            .expect("cancel authorized target");
        let stream = incoming
            .respond(StatusCode::OK, deadline())
            .await
            .expect("cancel response");
        let (mut reader, writer) = stream.into_split();
        let mut buffer = [0x5a; 1];
        let outcome = reader
            .read(&mut buffer, deadline())
            .await
            .expect("wire cancellation");
        observed_reset
            .send((outcome, buffer))
            .expect("wire reset observation");
        drop(target_socket);
        drop(reader);
        drop(writer);
        wait_client_done.await.expect("cancel client completion");
        session.cancel();
        assert_eq!(session.wait_closed().await, Err(EngineError::Cancelled));
    });
    let (engine, resources) = engine_with_resources(&certificate, address, certificate.pin);
    let policy = EndpointPolicy::single_binding(
        endpoint(HOSTNAME, BindingId::H3),
        address,
        NetworkEpoch::start(),
        BindingId::H3,
    )
    .expect("cancel policy");
    let session = engine
        .connect(&policy, credential(), deadline())
        .await
        .expect("cancel session");
    let stream = session
        .open_stream(&tcp_destination(), StreamOptions::default(), deadline())
        .await
        .expect("cancel stream");
    let (mut reader, mut writer) = stream.into_split();
    let control = reader.control();
    let mut buffer = [0x5a; 1];
    {
        let pending = reader.read(&mut buffer, deadline());
        tokio::pin!(pending);
        assert!(poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await);
        let pending_write = writer.write(b"cancel-before-acceptance", deadline());
        tokio::pin!(pending_write);
        assert!(
            poll_fn(|context| Poll::Ready(pending_write.as_mut().poll(context).is_pending())).await
        );
        control.cancel();
        let (read, write) = tokio::join!(pending, pending_write);
        assert_eq!(read, Ok(ReadOutcome::Cancelled));
        assert_eq!(write, Err(EngineError::Cancelled));
    }
    assert_eq!(buffer, [0x5a; 1]);
    assert_eq!(
        writer.write(b"late", deadline()).await,
        Err(EngineError::Cancelled)
    );
    assert_eq!(
        timeout(IO_TIMEOUT, reset_received)
            .await
            .expect("wire reset deadline")
            .expect("wire reset signal"),
        (ReadOutcome::Reset, [0x5a; 1])
    );
    drop(reader);
    drop(writer);
    drop(control);
    assert_eq!(
        session
            .close(CloseMode::Immediate, deadline())
            .await
            .expect("cancel session close"),
        CloseOutcome::Forced
    );
    let report = engine.shutdown_with_deadline(deadline()).await;
    assert_shutdown_complete(&report);
    drop(session);
    drop(engine);
    assert_resources_released(&resources);
    client_done
        .send(())
        .expect("cancel server completion signal");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("cancel server completion")
        .expect("cancel server task");
    assert_eq!(server_memory.used(), 0);
    assert_eq!(server_flows.used(), 0);
    assert_eq!(server_opens.used(), 0);
    assert_eq!(
        timeout(IO_TIMEOUT, target)
            .await
            .expect("cancel target completion")
            .expect("cancel target task"),
        vec![Vec::<u8>::new()]
    );
}

#[tokio::test]
async fn native_h3_identity_failure_precedes_every_credential_request() {
    for wrong_hostname in [true, false] {
        let certificate = CertificateFixture::new(false);
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("negative H3 server socket");
        let address = socket.local_addr().expect("negative H3 address");
        let tls = certificate.native_server();
        let incoming_count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&incoming_count);
        let server = tokio::spawn(async move {
            if let Ok(mut session) =
                H3ServerSession::accept(socket, &tls, h3_config(), deadline()).await
            {
                let observe_until = Deadline::after(Duration::from_millis(500))
                    .expect("negative observation deadline");
                if session.incoming(observe_until).await.is_ok() {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                session.cancel();
                let _ = session.wait_closed().await;
            }
        });
        let pin = if wrong_hostname {
            certificate.pin
        } else {
            let mut bytes = *certificate.pin.as_bytes();
            bytes[0] ^= 1;
            SpkiPin::from_bytes(bytes)
        };
        let engine = engine(&certificate, address, pin);
        let mut peer = endpoint(HOSTNAME, BindingId::H3);
        if wrong_hostname {
            peer.identity_hostname = "wrong.endpoint.test".to_owned();
        }
        let policy =
            EndpointPolicy::single_binding(peer, address, NetworkEpoch::start(), BindingId::H3)
                .expect("negative H3 policy");
        assert_eq!(
            engine
                .connect(&policy, credential(), deadline())
                .await
                .unwrap_err(),
            EngineError::PeerIdentityFailed
        );
        timeout(IO_TIMEOUT + Duration::from_secs(1), server)
            .await
            .expect("negative H3 server completion")
            .expect("negative H3 server task");
        assert_eq!(incoming_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            engine
                .shutdown_with_deadline(deadline())
                .await
                .pending_connects,
            0
        );
    }
}

async fn native_numeric_identity_handshake(
    certificate: &CertificateFixture,
    identity: &str,
    binding: BindingId,
) -> Result<(), EngineError> {
    let trust = certificate.pinned_policy();
    let connector = NativeTlsConnector::new(trust).expect("numeric identity connector");
    let tls = certificate.native_server();
    let peer = endpoint(identity, binding);
    match binding {
        BindingId::H2 => {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("numeric identity H2 listener");
            let address = listener.local_addr().expect("numeric identity H2 address");
            let socket = TcpStream::connect(address)
                .await
                .expect("numeric identity H2 client");
            let (server_result, result) = tokio::join!(
                async {
                    let (socket, _) = listener.accept().await.expect("numeric identity H2 accept");
                    tls.accept(socket, deadline()).await
                },
                connector.connect(&peer, socket, address, deadline()),
            );
            if result.is_ok() {
                let server = server_result.expect("numeric identity H2 server handshake");
                assert_eq!(
                    server.ssl().servername(boring::ssl::NameType::HOST_NAME),
                    None
                );
            }
            result.map(|_| ())
        }
        BindingId::H3 => {
            let socket = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("numeric identity H3 server socket");
            let address = socket.local_addr().expect("numeric identity H3 address");
            let client = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("numeric identity H3 client socket");
            let (server_result, result) = tokio::join!(
                H3ServerSession::accept(socket, &tls, h3_config(), deadline()),
                H3Session::connect(client, &peer, address, &connector, h3_config(), deadline()),
            );
            if result.is_ok() {
                assert!(
                    server_result.is_ok(),
                    "numeric identity H3 server handshake"
                );
            }
            if let Ok(session) = &result {
                session.cancel();
                assert_eq!(
                    timeout(IO_TIMEOUT, session.wait_closed())
                        .await
                        .expect("numeric identity H3 client shutdown"),
                    Err(EngineError::Cancelled)
                );
            }
            if let Ok(session) = server_result {
                session.cancel();
                let _ = timeout(IO_TIMEOUT, session.wait_closed())
                    .await
                    .expect("numeric identity H3 server shutdown");
            }
            result.map(|_| ())
        }
    }
}

#[tokio::test]
async fn native_h2_and_h3_accept_numeric_identity_with_matching_ip_san() {
    let identity = "192.0.2.1";
    let certificate = CertificateFixture::with_subject_alt_name(
        false,
        rcgen::SanType::IpAddress(identity.parse().expect("numeric IP identity")),
    );
    for binding in [BindingId::H2, BindingId::H3] {
        assert_eq!(
            native_numeric_identity_handshake(&certificate, identity, binding).await,
            Ok(()),
            "{binding:?}"
        );
    }
}

#[tokio::test]
async fn native_h2_and_h3_reject_numeric_identity_with_only_numeric_dns_san() {
    let identity = "192.0.2.1";
    let certificate = CertificateFixture::with_subject_alt_name(
        false,
        rcgen::SanType::DnsName(identity.try_into().expect("numeric DNS SAN")),
    );
    for binding in [BindingId::H2, BindingId::H3] {
        assert_eq!(
            native_numeric_identity_handshake(&certificate, identity, binding).await,
            Err(EngineError::PeerIdentityFailed),
            "{binding:?}"
        );
    }
}
