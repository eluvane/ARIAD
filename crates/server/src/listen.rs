use std::fs::File;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use ariad_core::{
    AuthzDecision, BudgetLimits, DeadlineKind, Destination, EgressDecision, EngineError,
    MemoryBudget, ResourceBudget, ResourceReservation, ScopedMemoryReservation, decide_egress,
    lab_cap, normalize_ip,
};
use ariad_engine::{
    BootstrapResolver, Deadline, H2Config, StaticAuthorizer, SystemBootstrapResolver,
    handle_h2_connect_authorized, handle_h2_connect_udp, is_connect_udp, serve_h2_with_handler,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::admission::AdmitDecision;
use crate::config::LoadedConfig;
use crate::gate::{Control, RuntimeLimits, parse_control};

/// Matches an exact `Destination`, including its port. Performs no DNS lookup.
pub fn destination_allowed(allow: &[Destination], destination: &Destination) -> bool {
    allow.iter().any(|item| item == destination)
}

/// Operation limits for the listener. Established TCP tunnels have no lifetime cap.
/// Durations must be nonzero and fit a deadline. Address limits must be 1..=64.
#[derive(Clone, Copy, Debug)]
pub struct ServerOptions {
    /// Limit for each TLS or H2 handshake.
    pub handshake_timeout: Duration,
    /// Limit for authentication after the H2 handshake and each target opening,
    /// including DNS.
    pub open_timeout: Duration,
    /// Limit for connection and listener drain after the control command.
    pub drain_timeout: Duration,
    /// Maximum DNS answers before duplicate addresses are removed.
    pub max_resolved_addresses: usize,
}

/// A host UDP socket connected to the requested peer, with its payload limit.
pub struct OpenedUdpSocket {
    pub socket: UdpSocket,
    /// Maximum payload the host can send without IP fragmentation, in bytes.
    /// Excludes IP and UDP headers. Must be nonzero and at most
    /// [`BudgetLimits::UDP_PAYLOAD_ABSOLUTE_CEILING`].
    pub max_payload: usize,
}

/// One host UDP opening attempt. The future may be cancelled at its deadline.
pub type UdpConnection<'a> =
    Pin<Box<dyn Future<Output = Result<OpenedUdpSocket, EngineError>> + Send + 'a>>;

/// Opens the supplied IP and port without IP fragmentation.
/// The server calls this after authentication, exact allow-list matching, and
/// resolved address policy checks. The host must connect that peer, enforce the
/// supplied deadline, and bound work that survives cancellation.
/// The server checks the peer and payload limit. It trusts the host to prevent
/// fragmentation for every payload up to that limit.
pub trait UdpConnector: Send + Sync {
    fn connect(&self, address: SocketAddr, deadline: Deadline) -> UdpConnection<'_>;
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: lab_cap(DeadlineKind::TransportHandshake),
            open_timeout: lab_cap(DeadlineKind::TargetOpen),
            drain_timeout: lab_cap(DeadlineKind::GracefulDrain),
            max_resolved_addresses: 16,
        }
    }
}

impl ServerOptions {
    fn validate(self) -> Result<(), EngineError> {
        if self.handshake_timeout.is_zero()
            || self.open_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.max_resolved_addresses == 0
            || self.max_resolved_addresses > 64
        {
            return Err(EngineError::InvalidConfig);
        }
        for duration in [
            self.handshake_timeout,
            self.open_timeout,
            self.drain_timeout,
        ] {
            Deadline::after(duration)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ProcessBudgets {
    memory: MemoryBudget,
    handshakes: ResourceBudget,
    sessions: ResourceBudget,
    flows: ResourceBudget,
    opens: ResourceBudget,
    dials: ResourceBudget,
    // The file provider has one principal. Its flow cap spans every session.
    principal_flows: ResourceBudget,
}

struct TlsIdentity<'a> {
    cert: &'a Path,
    key: &'a Path,
}

struct ConnectionContext {
    loaded: Arc<LoadedConfig>,
    options: ServerOptions,
    budgets: ProcessBudgets,
    excluded: Arc<Vec<SocketAddr>>,
    udp_connector: Option<Arc<dyn UdpConnector>>,
}

struct TargetContext {
    loaded: Arc<LoadedConfig>,
    budgets: ProcessBudgets,
    session_memory: MemoryBudget,
    excluded: Arc<Vec<SocketAddr>>,
    options: ServerOptions,
}

impl TargetContext {
    async fn reserve_and_resolve(
        &self,
        destination: &Destination,
        decision: AuthzDecision,
        deadline: Deadline,
    ) -> Result<(TargetReservation, Deadline, Vec<SocketAddr>), EngineError> {
        let reservation = reserve_target(
            &self.budgets,
            &self.session_memory,
            self.options.max_resolved_addresses,
        )?;
        // DNS and all candidate attempts share the inherited opening deadline.
        let deadline = deadline.cap(self.options.open_timeout.min(decision.valid_for))?;
        let addresses = resolve_target(
            destination,
            self.loaded.allow_private,
            &self.excluded,
            self.options.max_resolved_addresses,
            deadline,
            &SystemBootstrapResolver,
        )
        .await?;
        Ok((reservation, deadline, addresses))
    }
}

impl ProcessBudgets {
    fn new(max_inflight: usize) -> Result<Self, EngineError> {
        if max_inflight == 0 {
            return Err(EngineError::InvalidConfig);
        }
        let limits = BudgetLimits::lab_small();
        let sessions = max_inflight.min(limits.active_sessions);
        let flow_limit = sessions
            .checked_mul(limits.active_flows_per_session)
            .ok_or(EngineError::InvalidConfig)?;
        Ok(Self {
            memory: MemoryBudget::new(limits.global_application_budget)?,
            handshakes: ResourceBudget::new(limits.pending_handshakes)?,
            sessions: ResourceBudget::new(sessions)?,
            flows: ResourceBudget::new(flow_limit)?,
            opens: ResourceBudget::new(limits.pending_handshakes)?,
            dials: ResourceBudget::new(limits.parallel_candidate_dials)?,
            principal_flows: ResourceBudget::new(limits.active_flows_per_session)?,
        })
    }

    fn h2_config(&self, options: ServerOptions) -> Result<H2Config, EngineError> {
        let config = H2Config {
            handshake_timeout: options.handshake_timeout,
            open_timeout: options.open_timeout,
            drain_timeout: options.drain_timeout,
            process_budget: self.memory.clone(),
            process_flows: self.flows.clone(),
            process_opens: self.opens.clone(),
            ..H2Config::default()
        };
        config.validate()?;
        Ok(config)
    }
}

/// Runs the listener with `request_timeout` as the handshake and target-open cap.
/// It does not cap an established TCP tunnel. See `run_with_options` for drain
/// behavior and the remaining limits.
pub async fn run(
    listen: &str,
    cert: &Path,
    key: &Path,
    loaded: LoadedConfig,
    control: Option<&str>,
    max_inflight: usize,
    request_timeout: Duration,
) -> Result<(), EngineError> {
    run_with_options(
        listen,
        cert,
        key,
        loaded,
        control,
        max_inflight,
        ServerOptions {
            handshake_timeout: request_timeout,
            open_timeout: request_timeout,
            ..ServerOptions::default()
        },
    )
    .await
}

/// Serves TLS 1.3/H2 using the loaded credential and exact destination allow list.
/// `listen` must be an IP socket address. `control`, when set, must be loopback.
/// TCP admission includes pending TLS connections and uses the lab-small session cap.
/// Control reload replaces only the TLS identity; failure keeps the old identity.
/// Control drain stops admission, sends H2 GOAWAY, and waits for active work.
/// Forced drain returns `DeadlineExceeded`. Dropping this future aborts its tasks.
/// CONNECT-UDP requires `run_with_udp_connector`; this entry point denies it.
/// TLS identity reads and parsing use a shared, bounded worker quota.
/// A cancelled load can retain its slot until the blocking worker returns.
pub async fn run_with_options(
    listen: &str,
    cert: &Path,
    key: &Path,
    loaded: LoadedConfig,
    control: Option<&str>,
    max_inflight: usize,
    options: ServerOptions,
) -> Result<(), EngineError> {
    run_listeners(
        listen,
        TlsIdentity { cert, key },
        loaded,
        control,
        max_inflight,
        options,
        None,
    )
    .await
}

/// Runs `run_with_options` with a host capability for CONNECT-UDP.
/// The connector receives only checked addresses and must satisfy `UdpConnector`.
#[expect(clippy::too_many_arguments, reason = "Preserve the public host API.")]
pub async fn run_with_udp_connector(
    listen: &str,
    cert: &Path,
    key: &Path,
    loaded: LoadedConfig,
    control: Option<&str>,
    max_inflight: usize,
    options: ServerOptions,
    udp_connector: Arc<dyn UdpConnector>,
) -> Result<(), EngineError> {
    run_listeners(
        listen,
        TlsIdentity { cert, key },
        loaded,
        control,
        max_inflight,
        options,
        Some(udp_connector),
    )
    .await
}

async fn run_listeners(
    listen: &str,
    identity: TlsIdentity<'_>,
    loaded: LoadedConfig,
    control: Option<&str>,
    max_inflight: usize,
    options: ServerOptions,
    udp_connector: Option<Arc<dyn UdpConnector>>,
) -> Result<(), EngineError> {
    let TlsIdentity { cert, key } = identity;
    options.validate()?;
    let addr: SocketAddr = listen.parse().map_err(|_| EngineError::InvalidConfig)?;
    let budgets = ProcessBudgets::new(max_inflight)?;
    let limits = Arc::new(Mutex::new(RuntimeLimits::new(budgets.sessions.limit())?));
    let acceptor = Arc::new(Mutex::new(load_acceptor(cert, key).await?));
    let control = match control {
        Some(control) => Some(control_listener(control).await?),
        None => None,
    };
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|_| EngineError::TransportUnavailable)?;
    let bound = listener
        .local_addr()
        .map_err(|_| EngineError::TransportUnavailable)?;
    println!("listen {bound}");
    let loaded = Arc::new(loaded);
    let mut excluded = vec![bound];
    if let Some(control) = &control {
        excluded.push(
            control
                .local_addr()
                .map_err(|_| EngineError::TransportUnavailable)?,
        );
    }
    let excluded = Arc::new(excluded);
    let (drain, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            if lock_limits(&limits)?.is_draining() {
                let _ = drain.send(true);
                return wait_until_idle(&limits, &mut connections, options.drain_timeout).await;
            }
            while let Some(result) = connections.try_join_next() {
                note_connection_result(&limits, result)?;
            }
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.map_err(|_| EngineError::TransportUnavailable)?;
                    let decision = lock_limits(&limits)?.try_accept();
                    if decision != AdmitDecision::Accepted {
                        continue;
                    }
                    let slot = ConnectionSlot(Arc::clone(&limits));
                    let handshake = match budgets.handshakes.try_acquire() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    let acceptor = lock_acceptor(&acceptor)?.clone();
                    let loaded = Arc::clone(&loaded);
                    let _ = connections.spawn(serve_runtime_connection(
                        tcp,
                        acceptor,
                        slot,
                        handshake,
                        drain.subscribe(),
                        ConnectionContext {
                            loaded,
                            options,
                            budgets: budgets.clone(),
                            excluded: Arc::clone(&excluded),
                            udp_connector: udp_connector.clone(),
                        },
                    ));
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = completed {
                        note_connection_result(&limits, result)?;
                    }
                }
                control = accept_control(control.as_ref()), if control.is_some() => {
                    let Ok((stream, _)) = control else {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    };
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        handle_control(stream, &acceptor, cert, key, &limits),
                    )
                    .await;
                }
            }
        }
    }
    .await;
    let _ = drain.send(true);
    connections.shutdown().await;
    result
}

fn note_connection_result(
    limits: &Mutex<RuntimeLimits>,
    result: Result<Result<(), EngineError>, tokio::task::JoinError>,
) -> Result<(), EngineError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => {
            lock_limits(limits)?.note_connection_failed();
            Ok(())
        }
        Err(_) => Err(EngineError::TransportUnavailable),
    }
}

fn note_h2_drain_result(
    limits: &Mutex<RuntimeLimits>,
    result: &Result<(), EngineError>,
    drain_started_at: Option<tokio::time::Instant>,
    drain_timeout: Duration,
) -> Result<(), EngineError> {
    // Handshake and handler deadlines use the same error as drain expiry.
    if *result == Err(EngineError::DeadlineExceeded)
        && drain_started_at.is_some_and(|started| started.elapsed() >= drain_timeout)
    {
        lock_limits(limits)?.note_forced_close(1);
    }
    Ok(())
}

// Holds one TCP admission from accept through TLS and the H2 connection lifetime.
struct ConnectionSlot(Arc<Mutex<RuntimeLimits>>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut limits = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        limits.finish();
    }
}

#[cfg(test)]
async fn serve_connection<I>(
    io: I,
    acceptor: TlsAcceptor,
    loaded: Arc<LoadedConfig>,
    slot: ConnectionSlot,
    request_timeout: Duration,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let options = ServerOptions {
        handshake_timeout: request_timeout,
        open_timeout: request_timeout,
        ..ServerOptions::default()
    };
    let budgets = ProcessBudgets::new(1)?;
    let handshake = budgets.handshakes.try_acquire()?;
    let (_sender, receiver) = watch::channel(false);
    serve_runtime_connection(
        io,
        acceptor,
        slot,
        handshake,
        receiver,
        ConnectionContext {
            loaded,
            options,
            budgets,
            excluded: Arc::new(Vec::new()),
            udp_connector: None,
        },
    )
    .await
}

async fn serve_runtime_connection<I>(
    io: I,
    acceptor: TlsAcceptor,
    slot: ConnectionSlot,
    handshake: ResourceReservation,
    shutdown: watch::Receiver<bool>,
    context: ConnectionContext,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ConnectionContext {
        loaded,
        options,
        budgets,
        excluded,
        udp_connector,
    } = context;
    let result = async {
        let tls = tokio::time::timeout(options.handshake_timeout, acceptor.accept(io))
            .await
            .map_err(|_| EngineError::DeadlineExceeded)?
            .map_err(|_| EngineError::TransportUnavailable)?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(EngineError::ProtocolViolation);
        }
        drop(handshake);
        let _session = budgets.sessions.try_acquire()?;
        let config = budgets.h2_config(options)?;
        let _memory = config
            .process_budget
            .try_acquire_scoped(&config.session_budget, 1024)?;
        let authorizer = Arc::new(StaticAuthorizer::new(loaded.credential(), loaded.principal));
        let mut drain_started_at = None;
        let served = serve_h2_with_handler(
            tls,
            config,
            move |request, respond, config| {
                let loaded = Arc::clone(&loaded);
                let budgets = budgets.clone();
                let authorizer = Arc::clone(&authorizer);
                let excluded = Arc::clone(&excluded);
                let udp_connector = udp_connector.clone();
                async move {
                    let allow_private = loaded.allow_private;
                    let target = TargetContext {
                        loaded,
                        budgets,
                        session_memory: config.session_budget.clone(),
                        excluded,
                        options,
                    };
                    if is_connect_udp(&request) {
                        return handle_h2_connect_udp(
                            request,
                            respond,
                            authorizer,
                            config,
                            move |decision, destination, deadline| {
                                udp_dial_authorized(
                                    destination,
                                    decision,
                                    target,
                                    deadline,
                                    udp_connector,
                                )
                            },
                        )
                        .await;
                    }
                    handle_h2_connect_authorized(
                        request,
                        respond,
                        authorizer,
                        allow_private,
                        config,
                        move |decision, destination, deadline| {
                            tcp_dial_authorized(destination, decision, target, deadline)
                        },
                    )
                    .await
                }
            },
            async {
                wait_for_drain(shutdown).await;
                drain_started_at = Some(tokio::time::Instant::now());
            },
        )
        .await;
        note_h2_drain_result(&slot.0, &served, drain_started_at, options.drain_timeout)?;
        served
    }
    .await;
    if result == Err(EngineError::DeadlineExceeded)
        && let Ok(mut limits) = slot.0.lock()
    {
        limits.note_timeout();
    }
    result
}

async fn wait_for_drain(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn wait_until_idle(
    limits: &Mutex<RuntimeLimits>,
    connections: &mut JoinSet<Result<(), EngineError>>,
    drain_timeout: Duration,
) -> Result<(), EngineError> {
    let idle = async {
        while let Some(result) = connections.join_next().await {
            note_connection_result(limits, result)?;
        }
        if lock_limits(limits)?.metrics().forced_closed != 0 {
            Err(EngineError::DeadlineExceeded)
        } else {
            Ok(())
        }
    };
    let result = match tokio::time::timeout(drain_timeout, idle).await {
        Ok(result) => result,
        Err(_) => {
            lock_limits(limits)?.note_forced_close(connections.len());
            Err(EngineError::DeadlineExceeded)
        }
    };
    connections.shutdown().await;
    let metrics = lock_limits(limits)?.metrics();
    let events = lock_limits(limits)?.events();
    println!(
        "accepted={} refused={} timed_out={} forced_closed={} connections_failed={} reloads_ok={} reloads_failed={} events={}",
        metrics.accepted,
        metrics.refused,
        metrics.timed_out,
        metrics.forced_closed,
        metrics.connections_failed,
        metrics.reloads_ok,
        metrics.reloads_failed,
        events.len()
    );
    result
}

async fn accept_control(
    listener: Option<&TcpListener>,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn control_listener(control: &str) -> Result<TcpListener, EngineError> {
    let addr: SocketAddr = control.parse().map_err(|_| EngineError::InvalidConfig)?;
    if !addr.ip().is_loopback() {
        return Err(EngineError::InvalidConfig);
    }
    TcpListener::bind(addr)
        .await
        .map_err(|_| EngineError::TransportUnavailable)
}

fn lock_limits(
    limits: &Mutex<RuntimeLimits>,
) -> Result<std::sync::MutexGuard<'_, RuntimeLimits>, EngineError> {
    limits.lock().map_err(|_| EngineError::TransportUnavailable)
}

fn lock_acceptor(
    acceptor: &Mutex<TlsAcceptor>,
) -> Result<std::sync::MutexGuard<'_, TlsAcceptor>, EngineError> {
    acceptor
        .lock()
        .map_err(|_| EngineError::TransportUnavailable)
}

/// Serves H2 over an existing channel with bounded handshake and target opening.
/// `request_timeout` does not limit established tunnels. See `serve_tls` for
/// transport and connector requirements.
#[cfg(test)]
pub async fn serve_within<I, F, Fut, T>(
    io: I,
    loaded: &LoadedConfig,
    dial: F,
    request_timeout: Duration,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Destination) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, EngineError>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = H2Config {
        handshake_timeout: request_timeout,
        open_timeout: request_timeout,
        ..H2Config::default()
    };
    serve_authorized(io, loaded, dial, config).await
}

/// Executes the first bounded control line and writes one response.
/// Reload installs a fully loaded TLS identity or retains the previous one.
/// The caller must restrict access and bound reads; this helper has no timeout.
pub async fn handle_control<S>(
    mut stream: S,
    acceptor: &Mutex<TlsAcceptor>,
    cert: &Path,
    key: &Path,
    limits: &Mutex<RuntimeLimits>,
) -> Result<(), EngineError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; crate::gate::CONTROL_CAP + 1];
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n);
        if buf[..filled].contains(&b'\n') {
            break;
        }
    }
    let command = match buf[..filled].iter().position(|byte| *byte == b'\n') {
        Some(end) => parse_control(&buf[..=end]),
        None if filled == buf.len() => Control::TooLarge,
        None => parse_control(&buf[..filled]),
    };
    buf.fill(0);
    let response = match command {
        Control::Reload => match load_acceptor(cert, key).await {
            Ok(next) => {
                *lock_acceptor(acceptor)? = next;
                lock_limits(limits)?.note_reload(true);
                "reload ok\n"
            }
            Err(_) => {
                lock_limits(limits)?.note_reload(false);
                "reload failed\n"
            }
        },
        Control::Drain => {
            lock_limits(limits)?.drain();
            "draining\n"
        }
        Control::Unknown | Control::TooLarge => "unknown\n",
    };
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| EngineError::TransportUnavailable)?;
    Ok(())
}

/// Serves H2 over an existing channel. TLS setup belongs to the caller.
/// For network use, the caller must complete TLS 1.3 and require h2 ALPN.
/// Each TCP CONNECT checks the credential, literal IP policy, and exact allow
/// entry before calling `dial`. For domains, `dial` must check all DNS answers
/// against egress policy before connecting a checked IP without another lookup.
/// Opening is bounded by the default H2 limits. An open tunnel has no lifetime cap.
pub async fn serve_tls<I, F, Fut, T>(
    io: I,
    loaded: &LoadedConfig,
    dial: F,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Destination) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, EngineError>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_authorized(io, loaded, dial, H2Config::default()).await
}

async fn serve_authorized<I, F, Fut, T>(
    io: I,
    loaded: &LoadedConfig,
    dial: F,
    config: H2Config,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Destination) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, EngineError>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let allow = Arc::new(loaded.allow.clone());
    let authorizer = Arc::new(StaticAuthorizer::new(loaded.credential(), loaded.principal));
    let allow_private = loaded.allow_private;
    let dial = Arc::new(dial);
    serve_h2_with_handler(
        io,
        config,
        move |request, respond, config| {
            let allow = Arc::clone(&allow);
            let authorizer = Arc::clone(&authorizer);
            let dial = Arc::clone(&dial);
            async move {
                handle_h2_connect_authorized(
                    request,
                    respond,
                    authorizer,
                    allow_private,
                    config,
                    move |_decision, destination, _deadline| {
                        let allowed = destination_allowed(&allow, &destination);
                        async move {
                            if !allowed {
                                return Err(EngineError::EgressDenied);
                            }
                            dial(destination).await
                        }
                    },
                )
                .await
            }
        },
        std::future::pending::<()>(),
    )
    .await
}

async fn load_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, EngineError> {
    static IDENTITY_LOADS: OnceLock<Result<ResourceBudget, EngineError>> = OnceLock::new();
    let budget = IDENTITY_LOADS
        .get_or_init(|| ResourceBudget::new(64))
        .as_ref()
        .map_err(|error| *error)?;
    let cert = cert.to_path_buf();
    let key = key.to_path_buf();
    run_identity_loader(budget, move || load_acceptor_blocking(&cert, &key)).await
}

async fn run_identity_loader<F>(
    budget: &ResourceBudget,
    load: F,
) -> Result<TlsAcceptor, EngineError>
where
    F: FnOnce() -> Result<TlsAcceptor, EngineError> + Send + 'static,
{
    let reservation = budget.try_acquire()?;
    // A timeout stops waiting, so the worker retains admission until file I/O and parsing finish.
    tokio::task::spawn_blocking(move || {
        let result = load();
        drop(reservation);
        result
    })
    .await
    .map_err(|_| EngineError::TransportUnavailable)?
}

fn load_acceptor_blocking(cert: &Path, key: &Path) -> Result<TlsAcceptor, EngineError> {
    let certificates = load_certs(cert)?;
    let private_key = load_key(key)?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| EngineError::InvalidConfig)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, EngineError> {
    let file = File::open(path).map_err(|_| EngineError::InvalidConfig)?;
    CertificateDer::pem_reader_iter(file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| EngineError::InvalidConfig)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, EngineError> {
    let file = File::open(path).map_err(|_| EngineError::InvalidConfig)?;
    PrivateKeyDer::from_pem_reader(file).map_err(|_| EngineError::InvalidConfig)
}

struct TargetReservation {
    _principal_flow: ResourceReservation,
    _target_memory: ScopedMemoryReservation,
}

struct BudgetedIo<T> {
    // Field order drops target I/O before releasing its reservation.
    inner: T,
    _reservation: TargetReservation,
}

impl<T: AsyncRead + Unpin> AsyncRead for BudgetedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BudgetedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn authorize_target(
    loaded: &LoadedConfig,
    decision: AuthzDecision,
    destination: &Destination,
) -> Result<(), EngineError> {
    if decision.principal != loaded.principal
        || decision.quota_class != 0
        || decision.valid_for.is_zero()
    {
        return Err(EngineError::AuthorizationUnavailable);
    }
    if !destination_allowed(&loaded.allow, destination) {
        return Err(EngineError::EgressDenied);
    }
    if destination.port() == 0 {
        return Err(EngineError::InvalidConfig);
    }
    Ok(())
}

fn reserve_target(
    budgets: &ProcessBudgets,
    session_memory: &MemoryBudget,
    max_addresses: usize,
) -> Result<TargetReservation, EngineError> {
    let memory_cost = max_addresses
        .checked_mul(std::mem::size_of::<SocketAddr>())
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or(EngineError::ResourceLimitExceeded)?;
    Ok(TargetReservation {
        _principal_flow: budgets.principal_flows.try_acquire()?,
        _target_memory: budgets
            .memory
            .try_acquire_scoped(session_memory, memory_cost)?,
    })
}

fn checked_address(
    address: SocketAddr,
    allow_private: bool,
    excluded: &[SocketAddr],
) -> Result<SocketAddr, EngineError> {
    if address.port() == 0 || matches!(address, SocketAddr::V6(ip) if ip.scope_id() != 0) {
        return Err(EngineError::EgressDenied);
    }
    let address = SocketAddr::new(normalize_ip(address.ip()), address.port());
    if decide_egress(allow_private, address.ip()) != EgressDecision::Allow {
        return Err(EngineError::EgressDenied);
    }
    if excluded.iter().any(|own| {
        // Wildcard listeners have no complete interface list. Deny their port.
        own.port() == address.port()
            && (own.ip().is_unspecified() || normalize_ip(own.ip()) == address.ip())
    }) {
        return Err(EngineError::EgressDenied);
    }
    Ok(address)
}

fn checked_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    port: u16,
    allow_private: bool,
    excluded: &[SocketAddr],
    max_addresses: usize,
) -> Result<Vec<SocketAddr>, EngineError> {
    let mut checked = Vec::new();
    checked
        .try_reserve_exact(max_addresses)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    // Reject mixed DNS answers before any target connection can open.
    for (count, address) in addresses.into_iter().enumerate() {
        if count >= max_addresses {
            return Err(EngineError::ResourceLimitExceeded);
        }
        if address.port() != port {
            return Err(EngineError::EgressDenied);
        }
        let address = checked_address(address, allow_private, excluded)?;
        if !checked.contains(&address) {
            checked.push(address);
        }
    }
    if checked.is_empty() {
        return Err(EngineError::TargetResolutionFailed);
    }
    Ok(checked)
}

async fn resolve_target(
    destination: &Destination,
    allow_private: bool,
    excluded: &[SocketAddr],
    max_addresses: usize,
    deadline: Deadline,
    resolver: &dyn BootstrapResolver,
) -> Result<Vec<SocketAddr>, EngineError> {
    deadline.remaining()?;
    match destination {
        Destination::Ip { addr, port } => checked_addresses(
            [SocketAddr::new(*addr, *port)],
            *port,
            allow_private,
            excluded,
            max_addresses,
        ),
        Destination::Domain { name, port } => {
            let dns_deadline = deadline.cap(lab_cap(DeadlineKind::BootstrapDns))?;
            let addresses = dns_deadline
                .run(resolver.resolve(name, *port, max_addresses))
                .await
                .map_err(|error| {
                    if error == EngineError::EndpointResolutionFailed {
                        EngineError::TargetResolutionFailed
                    } else {
                        error
                    }
                })?;
            checked_addresses(addresses, *port, allow_private, excluded, max_addresses)
        }
    }
}

async fn connect_addresses<T, F, Fut>(
    addresses: Vec<SocketAddr>,
    allow_private: bool,
    excluded: &[SocketAddr],
    dials: &ResourceBudget,
    deadline: Deadline,
    connect: F,
) -> Result<T, EngineError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, EngineError>>,
{
    // Parallel target opens can duplicate external effects. Keep attempts serial.
    for address in addresses
        .into_iter()
        .take(BudgetLimits::lab_small().candidate_attempts)
    {
        deadline.remaining()?;
        let address = checked_address(address, allow_private, excluded)?;
        let _dial = dials.try_acquire()?;
        match deadline.run(connect(address)).await {
            Ok(target) => return Ok(target),
            Err(EngineError::TargetConnectFailed) => {}
            Err(error) => return Err(error),
        }
    }
    Err(EngineError::TargetConnectFailed)
}

async fn tcp_dial_authorized(
    destination: Destination,
    decision: AuthzDecision,
    context: TargetContext,
    deadline: Deadline,
) -> Result<BudgetedIo<TcpStream>, EngineError> {
    // Complete authorization before DNS or target socket I/O.
    authorize_target(&context.loaded, decision, &destination)?;
    let (reservation, deadline, addresses) = context
        .reserve_and_resolve(&destination, decision, deadline)
        .await?;
    let inner = connect_addresses(
        addresses,
        context.loaded.allow_private,
        &context.excluded,
        &context.budgets.dials,
        deadline,
        |address| async move {
            TcpStream::connect(address)
                .await
                .map_err(|_| EngineError::TargetConnectFailed)
        },
    )
    .await?;
    Ok(BudgetedIo {
        inner,
        _reservation: reservation,
    })
}

async fn udp_dial_authorized(
    destination: Destination,
    decision: AuthzDecision,
    context: TargetContext,
    deadline: Deadline,
    udp_connector: Option<Arc<dyn UdpConnector>>,
) -> Result<(UdpSocket, TargetReservation, usize), EngineError> {
    // Check authorization and host capability before DNS or target socket I/O.
    authorize_target(&context.loaded, decision, &destination)?;
    let udp_connector = udp_connector.ok_or(EngineError::UnsupportedCapability)?;
    let (reservation, deadline, addresses) = context
        .reserve_and_resolve(&destination, decision, deadline)
        .await?;
    let opened = connect_addresses(
        addresses,
        context.loaded.allow_private,
        &context.excluded,
        &context.budgets.dials,
        deadline,
        |address| {
            let udp_connector = Arc::clone(&udp_connector);
            let excluded = Arc::clone(&context.excluded);
            let allow_private = context.loaded.allow_private;
            async move {
                let opened = udp_connector.connect(address, deadline).await?;
                if opened.max_payload == 0
                    || opened.max_payload > BudgetLimits::UDP_PAYLOAD_ABSOLUTE_CEILING
                {
                    return Err(EngineError::UnsupportedCapability);
                }
                let peer = opened
                    .socket
                    .peer_addr()
                    .map_err(|_| EngineError::TargetConnectFailed)?;
                if checked_address(peer, allow_private, &excluded)? != address {
                    return Err(EngineError::EgressDenied);
                }
                Ok(opened)
            }
        },
    )
    .await?;
    Ok((opened.socket, reservation, opened.max_payload))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ariad_core::Credential;
    use ariad_engine::{
        BootstrapResolution, ClientRoundtrip, H2Session, ReadOutcome, client_roundtrip,
    };

    use super::*;
    use crate::config::load;
    use crate::config::test_support::{self, TempDir};

    #[tokio::test]
    async fn cancelled_identity_wait_keeps_worker_admission_until_return() {
        let budget = ResourceBudget::new(1).expect("identity budget");
        let worker_budget = budget.clone();
        let (started, waiting_started) = tokio::sync::oneshot::channel();
        let (release, waiting_release) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            run_identity_loader(&worker_budget, move || {
                started.send(()).expect("worker started");
                waiting_release
                    .recv_timeout(Duration::from_secs(3))
                    .expect("release worker");
                Err(EngineError::InvalidConfig)
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), waiting_started)
            .await
            .expect("start watchdog")
            .expect("worker started");
        task.abort();
        let Err(cancelled) = task.await else {
            panic!("cancelled wait must stop");
        };
        assert!(cancelled.is_cancelled());
        assert_eq!(budget.used(), 1);
        assert_eq!(
            run_identity_loader(&budget, || Err(EngineError::InvalidConfig))
                .await
                .err(),
            Some(EngineError::ResourceLimitExceeded)
        );
        release.send(()).expect("release worker");
        tokio::time::timeout(Duration::from_secs(2), async {
            while budget.used() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("release watchdog");
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn panicked_identity_loader_reports_failure_and_releases_admission() {
        let budget = ResourceBudget::new(1).expect("identity budget");
        assert_eq!(
            run_identity_loader(&budget, || panic!("identity loader panic"))
                .await
                .err(),
            Some(EngineError::TransportUnavailable)
        );
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn allow_list_matches_only_the_configured_target() {
        let allowed = Destination::parse("1.1.1.1:9").expect("allow");
        let other_port = Destination::parse("1.1.1.1:443").expect("port");
        let other_host = Destination::parse("8.8.8.8:9").expect("host");
        let allow = [allowed.clone()];
        assert!(destination_allowed(&allow, &allowed));
        assert!(!destination_allowed(&allow, &other_port));
        assert!(!destination_allowed(&allow, &other_host));
    }

    #[test]
    fn h2_configs_share_process_budgets_and_isolate_session_budgets() {
        let budgets = ProcessBudgets::new(2).expect("process");
        let options = ServerOptions {
            handshake_timeout: Duration::from_secs(7),
            open_timeout: Duration::from_secs(11),
            drain_timeout: Duration::from_secs(13),
            ..ServerOptions::default()
        };
        let first = budgets.h2_config(options).expect("first connection");
        let second = budgets.h2_config(options).expect("second connection");
        for config in [&first, &second] {
            assert_eq!(config.handshake_timeout, options.handshake_timeout);
            assert_eq!(config.open_timeout, options.open_timeout);
            assert_eq!(config.drain_timeout, options.drain_timeout);
        }
        let memory = first
            .process_budget
            .try_acquire_scoped(&first.session_budget, 1024)
            .expect("memory");
        assert_eq!(first.session_budget.used(), 1024);
        assert_eq!(second.session_budget.used(), 0);
        assert_eq!(second.process_budget.used(), 1024);
        assert_eq!(budgets.memory.used(), 1024);
        drop(memory);
        assert_eq!(first.session_budget.used(), 0);
        assert_eq!(budgets.memory.used(), 0);

        for (first_process, first_session, second_process, second_session, shared) in [
            (
                &first.process_flows,
                &first.session_flows,
                &second.process_flows,
                &second.session_flows,
                &budgets.flows,
            ),
            (
                &first.process_opens,
                &first.session_opens,
                &second.process_opens,
                &second.session_opens,
                &budgets.opens,
            ),
        ] {
            let slot = first_process
                .try_acquire_scoped(first_session)
                .expect("slot");
            assert_eq!(first_session.used(), 1);
            assert_eq!(second_session.used(), 0);
            assert_eq!(second_process.used(), 1);
            assert_eq!(shared.used(), 1);
            drop(slot);
            assert_eq!(first_session.used(), 0);
            assert_eq!(shared.used(), 0);
        }
    }

    #[test]
    fn resolved_addresses_enforce_all_answers_and_local_listener_policy() {
        let public = "1.1.1.1:443".parse().expect("public");
        for denied in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.169.254:443",
            "[::ffff:127.0.0.1]:443",
        ] {
            assert_eq!(
                checked_addresses(
                    [public, denied.parse().expect("denied")],
                    443,
                    false,
                    &[],
                    16
                ),
                Err(EngineError::EgressDenied)
            );
        }
        assert_eq!(
            checked_addresses([public, public], 443, false, &[], 1),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(
            checked_addresses([public], 443, false, &[public], 16),
            Err(EngineError::EgressDenied)
        );
        assert_eq!(
            checked_addresses(
                [public],
                443,
                false,
                &["0.0.0.0:443".parse().expect("listener")],
                16
            ),
            Err(EngineError::EgressDenied)
        );
        assert_eq!(
            checked_addresses(
                ["[::ffff:1.1.1.1]:443".parse().expect("mapped"), public],
                443,
                false,
                &[],
                16
            ),
            Ok(vec![public])
        );
    }

    #[test]
    fn authorization_scope_and_target_guards_fail_closed() {
        let loaded = sample_config("ariad-listen-principal");
        let destination = Destination::parse("1.1.1.1:9").expect("target");
        for decision in [
            AuthzDecision {
                principal: 2,
                quota_class: 0,
                valid_for: Duration::from_secs(60),
            },
            AuthzDecision {
                principal: 1,
                quota_class: 1,
                valid_for: Duration::from_secs(60),
            },
            AuthzDecision {
                principal: 1,
                quota_class: 0,
                valid_for: Duration::ZERO,
            },
        ] {
            assert_eq!(
                authorize_target(&loaded, decision, &destination),
                Err(EngineError::AuthorizationUnavailable)
            );
        }
        let budgets = ProcessBudgets::new(2).expect("process");
        let first_session = MemoryBudget::new(4096).expect("first");
        let second_session = MemoryBudget::new(4096).expect("second");
        let first = reserve_target(&budgets, &first_session, 16).expect("guard");
        let second = reserve_target(&budgets, &second_session, 16).expect("guard");
        assert_eq!(budgets.principal_flows.used(), 2);
        assert_eq!(
            budgets.memory.used(),
            first_session.used() + second_session.used()
        );
        drop(first);
        drop(second);
        assert_eq!(budgets.principal_flows.used(), 0);
        assert_eq!(budgets.memory.used(), 0);
    }

    struct RejectingUdpConnector(Arc<AtomicUsize>);

    impl UdpConnector for RejectingUdpConnector {
        fn connect(&self, _address: SocketAddr, _deadline: Deadline) -> UdpConnection<'_> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(EngineError::TargetConnectFailed)
            })
        }
    }

    #[tokio::test]
    async fn udp_requires_host_capability_and_checks_acl_before_host_call() {
        let loaded = Arc::new(sample_config("ariad-listen-udp-host"));
        let budgets = ProcessBudgets::new(1).expect("budgets");
        let session = MemoryBudget::new(4 * 1024 * 1024).expect("session");
        let destination = Destination::parse("1.1.1.1:9").expect("target");
        let decision = AuthzDecision {
            principal: 1,
            quota_class: 0,
            valid_for: Duration::from_secs(60),
        };
        let deadline = Deadline::after(Duration::from_secs(1)).expect("deadline");
        let result = udp_dial_authorized(
            destination.clone(),
            decision,
            TargetContext {
                loaded: Arc::clone(&loaded),
                budgets: budgets.clone(),
                session_memory: session.clone(),
                excluded: Arc::new(Vec::new()),
                options: ServerOptions::default(),
            },
            deadline,
            None,
        )
        .await;
        assert!(matches!(result, Err(EngineError::UnsupportedCapability)));
        assert_eq!(budgets.principal_flows.used(), 0);
        assert_eq!(session.used(), 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn UdpConnector> = Arc::new(RejectingUdpConnector(Arc::clone(&calls)));
        let result = udp_dial_authorized(
            destination.clone(),
            decision,
            TargetContext {
                loaded: Arc::clone(&loaded),
                budgets: budgets.clone(),
                session_memory: session.clone(),
                excluded: Arc::new(vec!["1.1.1.1:9".parse().expect("own listener")]),
                options: ServerOptions::default(),
            },
            deadline,
            Some(Arc::clone(&provider)),
        )
        .await;
        assert!(matches!(result, Err(EngineError::EgressDenied)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let result = udp_dial_authorized(
            destination,
            decision,
            TargetContext {
                loaded,
                budgets: budgets.clone(),
                session_memory: session.clone(),
                excluded: Arc::new(Vec::new()),
                options: ServerOptions::default(),
            },
            deadline,
            Some(provider),
        )
        .await;
        assert!(matches!(result, Err(EngineError::TargetConnectFailed)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(budgets.dials.used(), 0);
        assert_eq!(budgets.principal_flows.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[tokio::test]
    async fn connect_attempts_share_one_deadline_and_recheck_each_address() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dials = ResourceBudget::new(1).expect("dial budget");
        let addresses = vec![
            "1.1.1.1:443".parse().expect("first"),
            "8.8.8.8:443".parse().expect("second"),
        ];
        let deadline = Deadline::after(Duration::from_millis(60)).expect("deadline");
        let result =
            connect_addresses::<(), _, _>(addresses, false, &[], &dials, deadline, |address| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if address.ip() == "1.1.1.1".parse::<IpAddr>().expect("ip") {
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        Err(EngineError::TargetConnectFailed)
                    } else {
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        Ok(())
                    }
                }
            })
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        assert!(calls.load(Ordering::SeqCst) <= 2);
        assert_eq!(dials.used(), 0);
        let calls = AtomicUsize::new(0);
        assert_eq!(
            connect_addresses::<(), _, _>(
                vec!["127.0.0.1:443".parse().expect("denied")],
                true,
                &[],
                &dials,
                Deadline::after(Duration::from_secs(1)).expect("deadline"),
                |_address| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }
            )
            .await,
            Err(EngineError::EgressDenied)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_connect_releases_actual_dial_permit() {
        let dials = ResourceBudget::new(1).expect("budget");
        let entered = Arc::new(tokio::sync::Notify::new());
        let task = {
            let dials = dials.clone();
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                connect_addresses::<(), _, _>(
                    vec!["1.1.1.1:443".parse().expect("target")],
                    false,
                    &[],
                    &dials,
                    Deadline::after(Duration::from_secs(1)).expect("deadline"),
                    move |_address| {
                        let entered = Arc::clone(&entered);
                        async move {
                            entered.notify_one();
                            std::future::pending::<Result<(), EngineError>>().await
                        }
                    },
                )
                .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("started");
        assert_eq!(dials.used(), 1);
        task.abort();
        assert!(task.await.expect_err("cancelled").is_cancelled());
        assert_eq!(dials.used(), 0);
    }

    #[tokio::test]
    async fn opened_stream_survives_its_open_timeout() {
        let loaded = sample_config("ariad-listen-long-lived");
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let (targets, mut opened_target) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            serve_within(
                server_io,
                &loaded,
                move |_destination| {
                    let targets = targets.clone();
                    async move {
                        let (local, remote) = tokio::io::duplex(1024);
                        targets
                            .send(remote)
                            .await
                            .map_err(|_| EngineError::TargetConnectFailed)?;
                        Ok(local)
                    }
                },
                Duration::from_millis(100),
            )
            .await
        });
        let session = H2Session::handshake(client_io, true)
            .await
            .expect("session");
        let mut stream = session
            .open_stream(
                &Destination::parse("1.1.1.1:9").expect("target"),
                &Credential::from_bytes([0xab; Credential::BYTE_LEN]),
            )
            .await
            .expect("stream");
        assert_eq!(stream.status().as_u16(), 200);
        let mut target = opened_target.recv().await.expect("target");
        assert_eq!(stream.write(b"ping").await.expect("write"), 4);
        stream.end_write().await.expect("half close");
        let mut input = [0u8; 4];
        target.read_exact(&mut input).await.expect("request");
        assert_eq!(&input, b"ping");
        tokio::time::sleep(Duration::from_millis(250)).await;
        target.write_all(b"pong").await.expect("reply");
        target.shutdown().await.expect("reply eof");
        let mut output = [0u8; 4];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut output))
                .await
                .expect("read deadline")
                .expect("read"),
            ReadOutcome::Data(4)
        );
        assert_eq!(&output, b"pong");
        assert_eq!(
            stream.read(&mut output).await.expect("eof"),
            ReadOutcome::Eof
        );
        drop(stream);
        session.close(Duration::from_secs(1)).await.expect("close");
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server deadline")
            .expect("join")
            .expect("server");
    }

    struct MockResolver {
        answers: Vec<SocketAddr>,
        calls: Arc<AtomicUsize>,
    }

    impl BootstrapResolver for MockResolver {
        fn resolve<'a>(
            &'a self,
            hostname: &'a str,
            port: u16,
            _max_addresses: usize,
        ) -> BootstrapResolution<'a> {
            Box::pin(async move {
                assert_eq!(hostname, "example.com");
                assert_eq!(port, 443);
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.answers.clone())
            })
        }
    }

    #[tokio::test]
    async fn domain_resolution_runs_after_authentication_and_exact_allow_policy() {
        for (credential, allowed, expected_dns, expected_status) in [
            ([0xcd; Credential::BYTE_LEN], true, 0, 403),
            ([0xab; Credential::BYTE_LEN], false, 0, 502),
            ([0xab; Credential::BYTE_LEN], true, 1, 200),
        ] {
            let mut loaded = sample_config("ariad-listen-auth-dns");
            if allowed {
                loaded.allow = vec![Destination::parse("example.com:443").expect("domain")];
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver = Arc::new(MockResolver {
                answers: vec!["1.1.1.1:443".parse().expect("answer")],
                calls: Arc::clone(&calls),
            });
            let (client, server) = tokio::io::duplex(32 * 1024);
            let served = tokio::spawn(async move {
                serve_tls(server, &loaded, move |destination| {
                    let resolver = Arc::clone(&resolver);
                    async move {
                        resolve_target(
                            &destination,
                            false,
                            &[],
                            16,
                            Deadline::after(Duration::from_secs(1))?,
                            resolver.as_ref(),
                        )
                        .await?;
                        let (local, mut remote) = tokio::io::duplex(64);
                        remote
                            .shutdown()
                            .await
                            .map_err(|_| EngineError::TargetConnectFailed)?;
                        Ok(local)
                    }
                })
                .await
            });
            let result = client_roundtrip(
                client,
                &Destination::parse("example.com:443").expect("domain"),
                &Credential::from_bytes(credential),
                true,
                b"",
            )
            .await
            .expect("roundtrip");
            assert_eq!(result.status.as_u16(), expected_status);
            assert_eq!(calls.load(Ordering::SeqCst), expected_dns);
            let result = tokio::time::timeout(Duration::from_secs(1), served)
                .await
                .expect("server deadline")
                .expect("join");
            // The roundtrip owner closes its transport after receiving the response.
            assert!(
                matches!(result, Ok(()) | Err(EngineError::TransportUnavailable)),
                "{result:?}"
            );
        }
    }

    #[test]
    fn invalid_startup_is_rejected_before_socket_io() {
        let dir = TempDir::new("ariad-listen-startup");
        let signed = sample_identity();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, signed.cert.pem()).expect("cert");
        std::fs::write(&key, signed.key_pair.serialize_pem()).expect("key");
        // No I/O driver: reaching a socket operation would fail this test.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        for (cert, key, control, max_inflight) in [
            (cert.as_path(), key.as_path(), None, 0),
            (Path::new(""), key.as_path(), None, 1),
            (cert.as_path(), Path::new(""), None, 1),
            (cert.as_path(), key.as_path(), Some("invalid"), 1),
            (cert.as_path(), key.as_path(), Some("0.0.0.0:0"), 1),
        ] {
            let result = runtime.block_on(run(
                "127.0.0.1:0",
                cert,
                key,
                sample_config("ariad-listen-startup-config"),
                control,
                max_inflight,
                Duration::from_secs(1),
            ));
            assert_eq!(result, Err(EngineError::InvalidConfig));
        }
    }

    #[tokio::test]
    async fn serve_tls_does_not_dial_outside_the_allow_list() {
        let loaded = sample_config("ariad-listen");

        let (client, server) = tokio::io::duplex(8 * 1024);
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_task = Arc::clone(&dials);
        let served = tokio::spawn(async move {
            serve_tls(server, &loaded, move |_destination| {
                let dials_task = Arc::clone(&dials_task);
                async move {
                    dials_task.fetch_add(1, Ordering::SeqCst);
                    let (local, _remote) = tokio::io::duplex(64);
                    Ok::<_, EngineError>(local)
                }
            })
            .await
        });
        let ClientRoundtrip { status, reply } = client_roundtrip(
            client,
            &Destination::parse("8.8.8.8:9").expect("other"),
            &Credential::from_bytes([0xab; Credential::BYTE_LEN]),
            true,
            b"ping",
        )
        .await
        .expect("roundtrip");
        assert_eq!(status.as_u16(), 502);
        assert!(reply.is_empty());
        served.await.expect("join").expect("serve");
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn silent_connection_hits_the_deadline() {
        let loaded = sample_config("ariad-listen-deadline");
        let (client, server) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();
        let served = serve_within(
            server,
            &loaded,
            |_destination| async {
                std::future::pending::<Result<tokio::io::DuplexStream, EngineError>>().await
            },
            std::time::Duration::from_millis(50),
        );
        let error = served.await.expect_err("deadline");
        let elapsed = started.elapsed();
        assert_eq!(error, EngineError::DeadlineExceeded);
        assert!(elapsed >= std::time::Duration::from_millis(40));
        assert!(elapsed < std::time::Duration::from_secs(2));
        drop(client);
    }

    #[tokio::test]
    async fn silent_tls_handshake_counts_timeout_and_releases_slot() {
        let loaded = Arc::new(sample_config("ariad-listen-tls-deadline"));
        let limits = sample_admitted_limits();
        let (mut client, server) = tokio::io::duplex(1024);
        let result = serve_connection(
            server,
            sample_acceptor(),
            loaded,
            ConnectionSlot(Arc::clone(&limits)),
            Duration::from_millis(20),
        )
        .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        {
            let limits = limits.lock().expect("limits");
            assert_eq!(limits.inflight(), 0);
            assert_eq!(limits.metrics().timed_out, 1);
            assert_eq!(limits.events(), vec!["accepted", "timed-out"]);
        }
        assert_eq!(client.read(&mut [0u8; 1]).await.expect("closed"), 0);
    }

    #[tokio::test]
    async fn tls_requires_h2_alpn_before_serving_http2() {
        let signed = sample_identity();
        let certificate = signed.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key.into())
            .expect("identity");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("root");
        let loaded = Arc::new(sample_config("ariad-listen-alpn"));
        for offer_h2 in [false, true] {
            let mut client_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            if offer_h2 {
                client_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let limits = sample_admitted_limits();
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let client = async {
                let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
                let tls = connector.connect(name, client_io).await.expect("handshake");
                let expected = offer_h2.then_some(b"h2".as_slice());
                assert_eq!(tls.get_ref().1.alpn_protocol(), expected);
                client_roundtrip(
                    tls,
                    &Destination::parse("1.1.1.1:9").expect("target"),
                    &Credential::from_bytes([0xcd; Credential::BYTE_LEN]),
                    true,
                    b"ping",
                )
                .await
            };
            let server = serve_connection(
                server_io,
                acceptor.clone(),
                Arc::clone(&loaded),
                ConnectionSlot(Arc::clone(&limits)),
                Duration::from_secs(1),
            );
            let (client_result, server_result) = tokio::join!(client, server);
            if offer_h2 {
                let response = client_result.expect("http2");
                assert_eq!(response.status.as_u16(), 403);
                assert!(response.reply.is_empty());
                assert_eq!(server_result, Ok(()));
            } else {
                assert!(client_result.is_err());
                assert_eq!(server_result, Err(EngineError::ProtocolViolation));
            }
            let limits = limits.lock().expect("limits");
            assert_eq!(limits.inflight(), 0);
            assert_eq!(limits.metrics().timed_out, 0);
        }
    }

    #[test]
    fn unpolled_connection_releases_slot() {
        let loaded = Arc::new(sample_config("ariad-listen-unpolled"));
        let limits = sample_admitted_limits();
        let (_client, server) = tokio::io::duplex(1024);
        let connection = serve_connection(
            server,
            sample_acceptor(),
            loaded,
            ConnectionSlot(Arc::clone(&limits)),
            Duration::from_secs(10),
        );
        drop(connection);
        assert_eq!(limits.lock().expect("limits").inflight(), 0);
    }

    #[tokio::test]
    async fn drain_deadline_cancels_connections_and_releases_slots() {
        let limits = sample_admitted_limits();
        limits.lock().expect("limits").drain();
        let slot = ConnectionSlot(Arc::clone(&limits));
        let (mut client, server) = tokio::io::duplex(16);
        let mut connections = JoinSet::new();
        let _ = connections.spawn(async move {
            let _slot = slot;
            let _server = server;
            std::future::pending::<Result<(), EngineError>>().await
        });
        assert_eq!(
            wait_until_idle(&limits, &mut connections, Duration::from_millis(20)).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert!(connections.is_empty());
        assert_eq!(limits.lock().expect("limits").inflight(), 0);
        assert_eq!(limits.lock().expect("limits").metrics().forced_closed, 1);
        assert_eq!(client.read(&mut [0u8; 1]).await.expect("closed"), 0);
    }

    #[tokio::test]
    async fn tls_timeout_during_drain_is_not_a_forced_tunnel_close() {
        let loaded = Arc::new(sample_config("ariad-listen-drain-handshake"));
        let limits = sample_admitted_limits();
        limits.lock().expect("limits").drain();
        let budgets = ProcessBudgets::new(1).expect("budgets");
        let handshake = budgets.handshakes.try_acquire().expect("handshake");
        let (_sender, receiver) = watch::channel(true);
        let (_client, server) = tokio::io::duplex(1024);
        let options = ServerOptions {
            handshake_timeout: Duration::from_millis(20),
            ..ServerOptions::default()
        };
        let mut connections = JoinSet::new();
        let _ = connections.spawn(serve_runtime_connection(
            server,
            sample_acceptor(),
            ConnectionSlot(Arc::clone(&limits)),
            handshake,
            receiver,
            ConnectionContext {
                loaded,
                options,
                budgets,
                excluded: Arc::new(Vec::new()),
                udp_connector: None,
            },
        ));
        assert_eq!(
            wait_until_idle(&limits, &mut connections, Duration::from_secs(1)).await,
            Ok(())
        );
        let limits = limits.lock().expect("limits");
        assert_eq!(limits.inflight(), 0);
        assert_eq!(limits.metrics().timed_out, 1);
        assert_eq!(limits.metrics().forced_closed, 0);
    }

    #[tokio::test]
    async fn h2_handshake_timeout_during_drain_is_not_a_forced_close() {
        let signed = sample_identity();
        let certificate = signed.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let mut server_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key.into())
                .expect("identity");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("root");
        let mut client_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let limits = sample_admitted_limits();
        limits.lock().expect("limits").drain();
        let budgets = ProcessBudgets::new(1).expect("budgets");
        let handshake = budgets.handshakes.try_acquire().expect("handshake");
        let (_sender, receiver) = watch::channel(true);
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let mut connections = JoinSet::new();
        let _ = connections.spawn(serve_runtime_connection(
            server_io,
            acceptor,
            ConnectionSlot(Arc::clone(&limits)),
            handshake,
            receiver,
            ConnectionContext {
                loaded: Arc::new(sample_config("ariad-listen-drain-h2-handshake")),
                options: ServerOptions {
                    handshake_timeout: Duration::from_secs(1),
                    ..ServerOptions::default()
                },
                budgets: budgets.clone(),
                excluded: Arc::new(Vec::new()),
                udp_connector: None,
            },
        ));
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let tls = tokio::time::timeout(Duration::from_secs(2), connector.connect(name, client_io))
            .await
            .expect("TLS deadline")
            .expect("TLS");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(
            wait_until_idle(&limits, &mut connections, Duration::from_secs(3)).await,
            Ok(())
        );
        assert!(connections.is_empty());
        {
            let limits = limits.lock().expect("limits");
            assert_eq!(limits.inflight(), 0);
            assert_eq!(limits.metrics().timed_out, 1);
            assert_eq!(limits.metrics().forced_closed, 0);
        }
        assert_eq!(budgets.handshakes.used(), 0);
        assert_eq!(budgets.sessions.used(), 0);
        assert_eq!(budgets.memory.used(), 0);
        drop(tls);
    }

    #[tokio::test]
    async fn early_handler_deadline_during_drain_is_not_a_forced_close() {
        let limits = Arc::new(Mutex::new(RuntimeLimits::new(1).expect("cap")));
        let handler_started = Arc::new(tokio::sync::Notify::new());
        let finish_handler = Arc::new(tokio::sync::Notify::new());
        let (shutdown, receiver) = watch::channel(false);
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let served = {
            let limits = Arc::clone(&limits);
            let handler_started = Arc::clone(&handler_started);
            let finish = Arc::clone(&finish_handler);
            tokio::spawn(async move {
                let drain_timeout = Duration::from_secs(5);
                let mut drain_started_at = None;
                let result = serve_h2_with_handler(
                    server_io,
                    H2Config {
                        drain_timeout,
                        ..H2Config::default()
                    },
                    move |request, respond, _config| {
                        let handler_started = Arc::clone(&handler_started);
                        let finish = Arc::clone(&finish);
                        async move {
                            handler_started.notify_one();
                            finish.notified().await;
                            drop(request);
                            drop(respond);
                            Err(EngineError::DeadlineExceeded)
                        }
                    },
                    async {
                        wait_for_drain(receiver).await;
                        drain_started_at = Some(tokio::time::Instant::now());
                        finish_handler.notify_one();
                    },
                )
                .await;
                assert!(drain_started_at.is_some());
                note_h2_drain_result(&limits, &result, drain_started_at, drain_timeout)
                    .expect("metrics");
                result
            })
        };
        let session = H2Session::handshake(client_io, true)
            .await
            .expect("session");
        let destination = Destination::parse("1.1.1.1:9").expect("target");
        let credential = Credential::from_bytes([0xab; Credential::BYTE_LEN]);
        let opening = session.open_stream(&destination, &credential);
        tokio::pin!(opening);
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                () = handler_started.notified() => {}
                _ = &mut opening => panic!("handler must remain pending until drain"),
            }
        })
        .await
        .expect("handler deadline");
        shutdown.send(true).expect("drain");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), served)
                .await
                .expect("server deadline")
                .expect("join"),
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(limits.lock().expect("limits").metrics().forced_closed, 0);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut opening)
                .await
                .expect("opening deadline")
                .is_err()
        );
        session.close(Duration::from_secs(1)).await.expect("close");
    }

    #[tokio::test]
    async fn failed_connection_task_cancels_the_remaining_slots() {
        let limits = Arc::new(Mutex::new(RuntimeLimits::new(2).expect("cap")));
        let mut connections = JoinSet::new();
        for panics in [false, true] {
            assert_eq!(
                limits.lock().expect("limits").try_accept(),
                AdmitDecision::Accepted
            );
            let slot = ConnectionSlot(Arc::clone(&limits));
            let _ = connections.spawn(async move {
                let _slot = slot;
                assert!(!panics, "connection failed");
                std::future::pending::<Result<(), EngineError>>().await
            });
        }
        assert_eq!(
            wait_until_idle(&limits, &mut connections, Duration::from_secs(1)).await,
            Err(EngineError::TransportUnavailable)
        );
        assert!(connections.is_empty());
        assert_eq!(limits.lock().expect("limits").inflight(), 0);
    }

    #[tokio::test]
    async fn control_uses_only_the_first_line() {
        for command in [b"drain\n".as_slice(), b"drain\nignored".as_slice()] {
            let acceptor = Mutex::new(sample_acceptor());
            let limits = Mutex::new(RuntimeLimits::new(1).expect("cap"));
            let (mut client, server) = tokio::io::duplex(128);
            client.write_all(command).await.expect("write");
            handle_control(
                server,
                &acceptor,
                Path::new("unused-cert"),
                Path::new("unused-key"),
                &limits,
            )
            .await
            .expect("control");
            let mut response = [0u8; 32];
            let n = client.read(&mut response).await.expect("read");
            assert_eq!(&response[..n], b"draining\n");
            assert!(limits.lock().expect("limits").is_draining());
        }
    }

    #[tokio::test]
    async fn control_eof_obeys_the_inclusive_byte_limit() {
        for length in [crate::gate::CONTROL_CAP, crate::gate::CONTROL_CAP + 1] {
            let acceptor = Mutex::new(sample_acceptor());
            let limits = Mutex::new(RuntimeLimits::new(1).expect("cap"));
            let (mut client, server) = tokio::io::duplex(128);
            let mut command = vec![b' '; length];
            command[..5].copy_from_slice(b"drain");
            client.write_all(&command).await.expect("write");
            client.shutdown().await.expect("eof");
            handle_control(
                server,
                &acceptor,
                Path::new("unused-cert"),
                Path::new("unused-key"),
                &limits,
            )
            .await
            .expect("control");
            let mut response = [0u8; 32];
            let n = client.read(&mut response).await.expect("read");
            let allowed = length == crate::gate::CONTROL_CAP;
            let expected = if allowed {
                b"draining\n".as_slice()
            } else {
                b"unknown\n".as_slice()
            };
            assert_eq!(&response[..n], expected);
            assert_eq!(limits.lock().expect("limits").is_draining(), allowed);
        }
    }

    #[tokio::test]
    async fn bad_reload_keeps_the_previous_acceptor() {
        let dir = TempDir::new("ariad-reload");
        let signed = sample_identity();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let original = signed.cert.der().clone();
        std::fs::write(&cert, signed.cert.pem()).expect("cert");
        std::fs::write(&key, signed.key_pair.serialize_pem()).expect("key");
        let current = load_acceptor(&cert, &key).await.expect("identity");
        let slot = Mutex::new(current);
        std::fs::write(&key, b"not-a-key").expect("bad key");
        let limits = Mutex::new(RuntimeLimits::new(2).expect("cap"));
        let (mut client, server) = tokio::io::duplex(256);
        let handled = handle_control(server, &slot, &cert, &key, &limits);
        client.write_all(b"reload\n").await.expect("write");
        handled.await.expect("control");
        let mut response = [0u8; 32];
        let n = client.read(&mut response).await.expect("read");
        assert_eq!(&response[..n], b"reload failed\n");
        assert_eq!(limits.lock().expect("limits").metrics().reloads_failed, 1);
        assert_eq!(limits.lock().expect("limits").metrics().reloads_ok, 0);
        let acceptor = slot.lock().expect("acceptor").clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(original).expect("root");
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (client_result, server_result) = tokio::join!(
            connector.connect(name, client_io),
            acceptor.accept(server_io),
        );
        client_result.expect("handshake");
        server_result.expect("accept");
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        let mut state = 0x1234_5678u32;
        for _ in 0..256 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let mut buf = [0u8; 40];
            for byte in &mut buf {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 16) as u8;
            }
            let text = String::from_utf8_lossy(&buf);
            let _ = Destination::parse(&text);
            let _ = ariad_engine::request_route("GET", &text);
            let _ = parse_control(&buf);
        }
        assert_eq!(parse_control(b"nope"), crate::gate::Control::Unknown);
        let header = b"GET / HTTP/1.1\r\nX-Forwarded-For: 1.1.1.1\r\n\r\n";
        assert_eq!(parse_control(header), crate::gate::Control::Unknown);
    }

    fn sample_identity() -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert")
    }

    fn sample_admitted_limits() -> Arc<Mutex<RuntimeLimits>> {
        let limits = Arc::new(Mutex::new(RuntimeLimits::new(1).expect("cap")));
        assert_eq!(
            limits.lock().expect("limits").try_accept(),
            AdmitDecision::Accepted
        );
        limits
    }

    fn sample_acceptor() -> TlsAcceptor {
        let signed = sample_identity();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![signed.cert.der().clone()], key.into())
            .expect("identity");
        TlsAcceptor::from(Arc::new(config))
    }

    fn sample_config(name: &str) -> LoadedConfig {
        let dir = TempDir::new(name);
        let cred = test_support::credential_hex();
        let text = test_support::config_text(false, "{ host = \"1.1.1.1\", port = 9 }", "");
        let config = test_support::write_config(&dir, &text, format!("{cred}\n").as_bytes());
        load(&config).expect("load")
    }
}
