#![forbid(unsafe_code)]

#[path = "support/auth.rs"]
mod auth_support;

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ariad_core::{AuthzDecision, Destination, EngineError};
use ariad_engine::{
    H2Config, StaticAuthorizer, handle_h2_connect_authorized, handle_h2_connect_udp,
    is_connect_udp, serve_h2_with_handler,
};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use auth_support::credential;

const TARGET: &str = "echo.test:9";
const MAX_CONNECTIONS: usize = 16;
const UDP_PAYLOAD_LIMIT: usize = 1200;
const IPV4_UDP_HEADER_BYTES: usize = 28;
const CONSUMER_TIMEOUT: Duration = Duration::from_secs(90);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ObservedTraffic {
    endpoint_tcp_accepts: AtomicUsize,
    tcp_target_opens: AtomicUsize,
    udp_target_opens: AtomicUsize,
    tcp_bytes: AtomicUsize,
    udp_messages: AtomicUsize,
    empty_udp_messages: AtomicUsize,
}

#[derive(Default)]
struct ConnectionObservation {
    tcp_target_opens: AtomicUsize,
    udp_target_opens: AtomicUsize,
    tcp_bytes: AtomicUsize,
    handler_panicked: AtomicBool,
    handler_error: Mutex<Option<EngineError>>,
    relay_error: Mutex<Option<EngineError>>,
    echo_error: Mutex<Option<EngineError>>,
}

struct TrustRootFile {
    directory: PathBuf,
    certificate: PathBuf,
}

impl TrustRootFile {
    fn new(certificate: &[u8]) -> io::Result<Self> {
        for attempt in 0..32 {
            let directory = std::env::temp_dir()
                .join(format!("ariad-c-consumer-{}-{attempt}", std::process::id()));
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    let file = Self {
                        certificate: directory.join("ca.der"),
                        directory,
                    };
                    std::fs::write(&file.certificate, certificate)?;
                    return Ok(file);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary fixture directories are occupied",
        ))
    }
}

impl Drop for TrustRootFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.certificate);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

struct ConsumerProcess(Child);

impl ConsumerProcess {
    async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for ConsumerProcess {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while Instant::now() < deadline {
            match self.0.try_wait() {
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Ok(Some(_)) => return,
                Err(error) => {
                    eprintln!("consumer cleanup failed: {error}");
                    return;
                }
            }
        }
        eprintln!("consumer did not exit after termination");
    }
}

struct EndpointFixture {
    address: SocketAddr,
    traffic: Arc<ObservedTraffic>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), EngineError>>>,
}

impl EndpointFixture {
    async fn start(acceptor: TlsAcceptor, with_destroy_race: bool) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let traffic = Arc::new(ObservedTraffic::default());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve_endpoint(
            listener,
            acceptor,
            Arc::clone(&traffic),
            stopped,
            with_destroy_race,
        ));
        Ok(Self {
            address,
            traffic,
            stop: Some(stop),
            task: Some(task),
        })
    }

    async fn finish(mut self) -> Result<(), EngineError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let mut task = self.task.take().ok_or(EngineError::ProtocolViolation)?;
        match tokio::time::timeout(CLEANUP_TIMEOUT * 2, &mut task).await {
            Ok(result) => result.map_err(|_| EngineError::TransportUnavailable)?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(EngineError::DeadlineExceeded)
            }
        }
    }
}

impl Drop for EndpointFixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve_endpoint(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    traffic: Arc<ObservedTraffic>,
    mut stopped: oneshot::Receiver<()>,
    with_destroy_race: bool,
) -> Result<(), EngineError> {
    let (drain, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = &mut stopped => break Ok(()),
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {},
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(_)) | None => break Err(EngineError::TransportUnavailable),
                }
            }
            accepted = listener.accept() => {
                let (tcp, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => break Err(EngineError::TransportUnavailable),
                };
                let connection_index = traffic.endpoint_tcp_accepts.fetch_add(1, Ordering::Relaxed);
                if connection_index >= MAX_CONNECTIONS {
                    break Err(EngineError::ResourceLimitExceeded);
                }
                // The second TCP connection tests destruction with one idle stream.
                let destroys_idle_stream = with_destroy_race && connection_index == 1;
                let acceptor = acceptor.clone();
                let traffic = Arc::clone(&traffic);
                let connection_traffic = Arc::new(ConnectionObservation::default());
                let mut draining = drain.subscribe();
                let _ = connections.spawn(async move {
                    let tls = tokio::time::timeout(CLEANUP_TIMEOUT, acceptor.accept(tcp))
                        .await
                        .map_err(|_| EngineError::DeadlineExceeded)?
                        .map_err(|_| EngineError::TransportUnavailable)?;
                    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                        return Err(EngineError::ProtocolViolation);
                    }
                    let authorizer = Arc::new(StaticAuthorizer::new(
                        credential(),
                        7,
                    ));
                    let handler_traffic = Arc::clone(&connection_traffic);
                    let result = serve_h2_with_handler(
                        tls,
                        H2Config::default(),
                        move |request, respond, config| {
                            let authorizer = Arc::clone(&authorizer);
                            let traffic = Arc::clone(&traffic);
                            let connection_traffic = Arc::clone(&handler_traffic);
                            let outcome = Arc::clone(&connection_traffic);
                            observe_handler(async move {
                                if is_connect_udp(&request) {
                                    let (echo, echoed) = oneshot::channel();
                                    let dial_traffic = Arc::clone(&traffic);
                                    let dial_connection_traffic = Arc::clone(&connection_traffic);
                                    let relay = handle_h2_connect_udp(
                                        request, respond, authorizer, config,
                                        move |decision, target, deadline| async move {
                                            check_target(decision, &target)?;
                                            deadline.remaining()?;
                                            dial_traffic.udp_target_opens.fetch_add(1, Ordering::Relaxed);
                                            dial_connection_traffic.udp_target_opens.fetch_add(1, Ordering::Relaxed);
                                            let echo_socket = UdpSocket::bind("127.0.0.1:0")
                                                .await.map_err(|_| EngineError::TargetConnectFailed)?;
                                            let target_socket = UdpSocket::bind("127.0.0.1:0")
                                                .await.map_err(|_| EngineError::TargetConnectFailed)?;
                                            let address = echo_socket.local_addr()
                                                .map_err(|_| EngineError::TargetConnectFailed)?;
                                            target_socket.connect(address).await
                                                .map_err(|_| EngineError::TargetConnectFailed)?;
                                            echo_socket.connect(target_socket.local_addr()
                                                .map_err(|_| EngineError::TargetConnectFailed)?).await
                                                .map_err(|_| EngineError::TargetConnectFailed)?;
                                            let max_payload = loopback_udp_payload_limit()?;
                                            echo.send(echo_socket).map_err(|_| EngineError::Cancelled)?;
                                            Ok((target_socket, (), max_payload))
                                        },
                                    );
                                    let result = tokio::select! {
                                        result = relay => result,
                                        result = echo_udp(echoed, traffic) => result,
                                    };
                                    return expected_peer_reset(result);
                                }
                                let (echo, echoed) = oneshot::channel();
                                let dial_traffic = Arc::clone(&traffic);
                                let dial_connection_traffic = Arc::clone(&connection_traffic);
                                let relay = handle_h2_connect_authorized(
                                    request, respond, authorizer, false, config,
                                    move |decision, target, deadline| async move {
                                        check_target(decision, &target)?;
                                        deadline.remaining()?;
                                        dial_traffic.tcp_target_opens.fetch_add(1, Ordering::Relaxed);
                                        dial_connection_traffic.tcp_target_opens.fetch_add(1, Ordering::Relaxed);
                                        let (target, echo_stream) = tokio::io::duplex(4096);
                                        echo.send(echo_stream).map_err(|_| EngineError::Cancelled)?;
                                        Ok(target)
                                    },
                                );
                                let echo = echo_tcp(echoed, traffic, Arc::clone(&connection_traffic));
                                let (relayed, echoed) = tokio::join!(
                                    observe_result(relay, &connection_traffic.relay_error),
                                    observe_result(echo, &connection_traffic.echo_error),
                                );
                                expected_peer_reset(relayed)?;
                                echoed
                            }, outcome)
                        },
                        async move {
                            while !*draining.borrow() {
                                if draining.changed().await.is_err() {
                                    break;
                                }
                            }
                        },
                    ).await;
                    let checked = check_connection_result(result, destroys_idle_stream, &connection_traffic);
                    if let Err(error) = checked {
                        eprintln!("fixture connection {connection_index} failed: {error}; H2={result:?}; relay={:?}; handler={:?}; echo={:?}",
                            connection_traffic.relay_error.lock().unwrap_or_else(|error| error.into_inner()),
                            connection_traffic.handler_error.lock().unwrap_or_else(|error| error.into_inner()),
                            connection_traffic.echo_error.lock().unwrap_or_else(|error| error.into_inner()));
                    }
                    checked
                });
            }
        }
    };
    drain.send_replace(true);
    let finished = tokio::time::timeout(CLEANUP_TIMEOUT, async {
        while let Some(connection) = connections.join_next().await {
            connection.map_err(|_| EngineError::TransportUnavailable)??;
        }
        Ok(())
    })
    .await
    .map_err(|_| EngineError::DeadlineExceeded)
    .and_then(|result| result);
    connections.shutdown().await;
    result.and(finished)
}

async fn observe_handler<F>(
    handler: F,
    outcome: Arc<ConnectionObservation>,
) -> Result<(), EngineError>
where
    F: Future<Output = Result<(), EngineError>>,
{
    tokio::pin!(handler);
    observe_result(
        poll_fn(|cx| {
            match catch_unwind(AssertUnwindSafe(|| handler.as_mut().poll(cx))) {
                Ok(polled) => polled,
                Err(panic) => {
                    // The H2 task owner reports panic as a transport error.
                    outcome.handler_panicked.store(true, Ordering::Release);
                    resume_unwind(panic);
                }
            }
        }),
        &outcome.handler_error,
    )
    .await
}

async fn observe_result<F>(
    operation: F,
    error: &Mutex<Option<EngineError>>,
) -> Result<(), EngineError>
where
    F: Future<Output = Result<(), EngineError>>,
{
    let result = operation.await;
    if let Err(failure) = result {
        error
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert(failure);
    }
    result
}

fn check_connection_result(
    result: Result<(), EngineError>,
    destroys_idle_stream: bool,
    traffic: &ConnectionObservation,
) -> Result<(), EngineError> {
    if traffic.handler_panicked.load(Ordering::Acquire) {
        return Err(EngineError::TransportUnavailable);
    }
    if let Some(error) = *traffic
        .echo_error
        .lock()
        .unwrap_or_else(|error| error.into_inner())
    {
        return Err(error);
    }
    let expected_transport_close = destroys_idle_stream
        && traffic.tcp_target_opens.load(Ordering::Relaxed) == 1
        && traffic.udp_target_opens.load(Ordering::Relaxed) == 0
        && traffic.tcp_bytes.load(Ordering::Relaxed) == 0;
    let relay_error = *traffic
        .relay_error
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(error) = relay_error
        && !matches!(error, EngineError::RemoteReset | EngineError::Cancelled)
        && !(expected_transport_close && error == EngineError::TransportUnavailable)
    {
        return Err(error);
    }
    if let Some(error) = *traffic
        .handler_error
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        && (!expected_transport_close
            || error != EngineError::TransportUnavailable
            || relay_error != Some(EngineError::TransportUnavailable))
    {
        return Err(error);
    }
    match result {
        Err(EngineError::TransportUnavailable) if expected_transport_close => Ok(()),
        result => result,
    }
}

fn check_target(decision: AuthzDecision, target: &Destination) -> Result<(), EngineError> {
    if decision.principal != 7 || decision.quota_class != 0 || decision.valid_for.is_zero() {
        return Err(EngineError::AuthorizationUnavailable);
    }
    if !matches!(target, Destination::Domain { name, port } if name == "echo.test" && *port == 9) {
        return Err(EngineError::EgressDenied);
    }
    Ok(())
}

fn expected_peer_reset(result: Result<(), EngineError>) -> Result<(), EngineError> {
    // The consumer cancels idle streams and closes its UDP association with a reset.
    match result {
        Err(EngineError::RemoteReset | EngineError::Cancelled) => Ok(()),
        result => result,
    }
}

fn loopback_udp_payload_limit() -> Result<usize, EngineError> {
    // Both sockets use IPv4 loopback. This limit prevents IP fragmentation.
    let mtu: usize = std::fs::read_to_string("/sys/class/net/lo/mtu")
        .map_err(|_| EngineError::UnsupportedCapability)?
        .trim()
        .parse()
        .map_err(|_| EngineError::UnsupportedCapability)?;
    mtu.checked_sub(IPV4_UDP_HEADER_BYTES)
        .map(|payload| payload.min(UDP_PAYLOAD_LIMIT))
        .filter(|payload| *payload >= 6)
        .ok_or(EngineError::UnsupportedCapability)
}

async fn echo_tcp(
    stream: oneshot::Receiver<DuplexStream>,
    traffic: Arc<ObservedTraffic>,
    connection_traffic: Arc<ConnectionObservation>,
) -> Result<(), EngineError> {
    let stream = stream.await.map_err(|_| EngineError::Cancelled)?;
    let (mut read, mut write) = tokio::io::split(stream);
    let mut buffer = [0; 4096];
    loop {
        let bytes = read
            .read(&mut buffer)
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        if bytes == 0 {
            return write
                .shutdown()
                .await
                .map_err(|_| EngineError::TransportUnavailable);
        }
        write
            .write_all(&buffer[..bytes])
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        traffic.tcp_bytes.fetch_add(bytes, Ordering::Relaxed);
        connection_traffic
            .tcp_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

async fn echo_udp(
    socket: oneshot::Receiver<UdpSocket>,
    traffic: Arc<ObservedTraffic>,
) -> Result<(), EngineError> {
    let socket = socket.await.map_err(|_| EngineError::Cancelled)?;
    let mut buffer = [0; UDP_PAYLOAD_LIMIT];
    loop {
        let bytes = socket
            .recv(&mut buffer)
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        let sent = socket
            .send(&buffer[..bytes])
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        if sent != bytes {
            return Err(EngineError::TransferStalled);
        }
        traffic.udp_messages.fetch_add(1, Ordering::Relaxed);
        if bytes == 0 {
            traffic.empty_udp_messages.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[tokio::test]
async fn handler_panic_cannot_pass_as_expected_connection_close() {
    let traffic = Arc::new(ConnectionObservation::default());
    traffic.tcp_target_opens.store(1, Ordering::Relaxed);
    let mut task = tokio::spawn(observe_handler(
        async { panic!("fixture handler panic") },
        Arc::clone(&traffic),
    ));
    let failed = match tokio::time::timeout(CLEANUP_TIMEOUT, &mut task).await {
        Ok(result) => result.expect_err("handler panic must reach its task owner"),
        Err(_) => {
            task.abort();
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, &mut task).await;
            panic!("handler deadline");
        }
    };
    assert!(failed.is_panic());
    assert_eq!(
        check_connection_result(Err(EngineError::TransportUnavailable), true, &traffic),
        Err(EngineError::TransportUnavailable)
    );
}

#[tokio::test]
async fn echo_failure_survives_handler_abort_and_expected_connection_close() {
    let traffic = Arc::new(ConnectionObservation::default());
    traffic.tcp_target_opens.store(1, Ordering::Relaxed);
    let (failed, failure_seen) = oneshot::channel();
    let handler_traffic = Arc::clone(&traffic);
    let mut task = tokio::spawn(observe_handler(
        async move {
            let echo = async {
                let result = observe_result(
                    async { Err(EngineError::TransportUnavailable) },
                    &handler_traffic.echo_error,
                )
                .await;
                failed.send(()).expect("failure observer");
                result
            };
            let (relayed, echoed) =
                tokio::join!(std::future::pending::<Result<(), EngineError>>(), echo,);
            relayed?;
            echoed
        },
        Arc::clone(&traffic),
    ));
    let seen = tokio::time::timeout(CLEANUP_TIMEOUT, failure_seen).await;
    task.abort();
    let joined = tokio::time::timeout(CLEANUP_TIMEOUT, &mut task)
        .await
        .expect("handler cleanup deadline");
    assert!(joined.expect_err("handler was aborted").is_cancelled());
    seen.expect("echo failure deadline")
        .expect("echo failure observation");
    assert_eq!(
        check_connection_result(Err(EngineError::TransportUnavailable), true, &traffic),
        Err(EngineError::TransportUnavailable)
    );
}

#[tokio::test]
async fn relay_transport_close_is_allowed_only_in_the_destroy_scenario() {
    let traffic = Arc::new(ConnectionObservation::default());
    traffic.tcp_target_opens.store(1, Ordering::Relaxed);
    let handler_traffic = Arc::clone(&traffic);
    let result = observe_handler(
        async move {
            observe_result(
                async { Err(EngineError::TransportUnavailable) },
                &handler_traffic.relay_error,
            )
            .await
        },
        Arc::clone(&traffic),
    )
    .await;
    assert_eq!(result, Err(EngineError::TransportUnavailable));
    assert_eq!(check_connection_result(result, true, &traffic), Ok(()));
    assert_eq!(
        check_connection_result(result, false, &traffic),
        Err(EngineError::TransportUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "Requires Linux and a compiled, linked C consumer in ARIAD_C_CONSUMER"]
async fn linked_c_consumer_exercises_h2_tcp_and_udp() {
    let consumer = PathBuf::from(
        std::env::var_os("ARIAD_C_CONSUMER")
            .expect("ARIAD_C_CONSUMER must name the linked C binary"),
    );
    assert!(
        consumer.is_file(),
        "C consumer does not exist: {consumer:?}"
    );
    let signed =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let certificate = signed.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der()));
    let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .expect("TLS configuration");
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let trust_root = TrustRootFile::new(certificate.as_ref()).expect("temporary public trust root");

    for udp in [false, true] {
        let fixture = EndpointFixture::start(acceptor.clone(), !udp)
            .await
            .expect("fixture");
        let traffic = Arc::clone(&fixture.traffic);
        let mut command = Command::new(&consumer);
        command
            .arg(fixture.address.to_string())
            .arg("localhost")
            .arg(&trust_root.certificate)
            .arg(TARGET)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if udp {
            command.arg("--udp");
        }
        let mut process = ConsumerProcess(command.spawn().expect("start C consumer"));
        let status = tokio::time::timeout(CONSUMER_TIMEOUT, process.wait()).await;
        drop(process);
        let served = fixture.finish().await;
        assert!(
            status
                .expect("C consumer deadline")
                .expect("wait for C consumer")
                .success(),
            "C consumer failed (udp={udp}, server={served:?})"
        );
        served.expect("fixture server or cleanup failed");
        assert_eq!(
            traffic.endpoint_tcp_accepts.load(Ordering::Relaxed),
            if udp { 1 } else { 2 },
            "unexpected endpoint connection count (udp={udp})"
        );
        assert_eq!(
            traffic.tcp_target_opens.load(Ordering::Relaxed),
            if udp { 0 } else { 4 },
            "TCP target scenarios were not executed (udp={udp})"
        );
        assert_eq!(
            traffic.udp_target_opens.load(Ordering::Relaxed),
            usize::from(udp),
            "unexpected UDP target count (udp={udp})"
        );
        if udp {
            assert!(
                traffic.udp_messages.load(Ordering::Relaxed) >= 4,
                "UDP echo scenarios were not executed"
            );
            assert!(
                traffic.empty_udp_messages.load(Ordering::Relaxed) > 0,
                "zero-length UDP echo was not executed"
            );
        } else {
            assert!(
                traffic.tcp_bytes.load(Ordering::Relaxed) >= 256 * 1024,
                "large TCP echo was not executed"
            );
        }
    }
}
