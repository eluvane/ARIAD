#![forbid(unsafe_code)]

//! Rust embedding entry points and the types needed to use them.
//!
//! [`PinnedH2Builder`] configures a fixed H2/TLS endpoint. Hosts with multiple
//! endpoints or bootstrap DNS can use [`HostServices`] and [`EndpointPolicy`]
//! with the reexported [`Engine`] constructors.
//!
//! Construction does not start network work or create a Tokio runtime. The host
//! must drive a runtime with I/O and time enabled while using sessions and retain
//! it until asynchronous engine shutdown completes.

use std::net::SocketAddr;
use std::sync::Arc;

pub use ariad_core::{
    BindingId, BudgetLimits, Credential, DatagramOutcome, DeliveryMode, Destination,
    EndpointAddressHints, EndpointDescriptor, EngineError, FlowGeneration, FlowId, NetworkEpoch,
    SessionPhase,
};
pub use ariad_engine::{
    Association, AssociationControl, AssociationRecvHalf, AssociationSendHalf, BootstrapResolution,
    BootstrapResolver, CloseMode, CloseOutcome, DatagramOptions, DatagramPayload,
    DatagramRequirements, Deadline, DefaultSocketFactory, DialCandidate, EndpointPolicy, Engine,
    EngineConfig, EngineResources, HostServices, NegotiatedCapabilities, ReadOutcome, Session,
    ShutdownReport, SocketFactory, SpkiPin, Stream, StreamControl, StreamOptions, StreamReadHalf,
    StreamWriteHalf, SystemBootstrapResolver, TrustPolicy,
};

/// Configures an H2/TLS engine for one address and certificate DNS identity.
///
/// Defaults match [`pinned_h2_engine`]. The supplied address controls routing;
/// certificate-chain, validity and DNS-name checks remain enabled.
#[must_use]
pub struct PinnedH2Builder {
    address: SocketAddr,
    identity_hostname: String,
    trust_root_der: Vec<u8>,
    limits: BudgetLimits,
    socket_factory: Arc<dyn SocketFactory>,
    resources: Option<Arc<EngineResources>>,
}

impl PinnedH2Builder {
    /// Maximum trust-root input length, checked before endpoint and DER validation.
    pub const MAX_TRUST_ROOT_INPUT_BYTES: usize = 64 * 1024;

    /// Stores unvalidated inputs with lab limits and the default socket factory.
    /// Validation runs in [`Self::build`].
    pub fn new(
        address: SocketAddr,
        identity_hostname: impl Into<String>,
        trust_root_der: Vec<u8>,
    ) -> Self {
        Self {
            address,
            identity_hostname: identity_hostname.into(),
            trust_root_der,
            limits: BudgetLimits::lab_small(),
            socket_factory: Arc::new(DefaultSocketFactory),
            resources: None,
        }
    }

    /// Uses host-selected limits, validated when the engine is built.
    pub fn with_limits(mut self, limits: BudgetLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Uses the host's socket creation and preparation hooks before dialing.
    /// Construction does not call the factory. The default factory has no
    /// routing-loop protection; a host needing it must supply this hook.
    pub fn with_socket_factory(mut self, socket_factory: Arc<dyn SocketFactory>) -> Self {
        self.socket_factory = socket_factory;
        self
    }

    /// Shares transport quotas with engines using the same pool.
    /// Application-memory, active-session and pending-handshake limits must match
    /// the pool. A mismatch returns [`EngineError::InvalidConfig`] from `build`.
    pub fn with_resources(mut self, resources: Arc<EngineResources>) -> Self {
        self.resources = Some(resources);
        self
    }

    /// Validates configuration and creates the engine and one-address policy.
    ///
    /// Requires one nonempty DER certificate within
    /// [`TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES`].
    /// Invalid trust material returns [`EngineError::InvalidConfig`]; inputs above
    /// [`Self::MAX_TRUST_ROOT_INPUT_BYTES`] return [`EngineError::MessageTooLarge`].
    /// Construction needs no runtime, DNS lookup, socket operation, or TLS handshake.
    pub fn build(self) -> Result<(Engine, EndpointPolicy), EngineError> {
        if self.trust_root_der.is_empty() {
            return Err(EngineError::InvalidConfig);
        }
        if self.trust_root_der.len() > Self::MAX_TRUST_ROOT_INPUT_BYTES {
            return Err(EngineError::MessageTooLarge);
        }
        let trust_group = 1;
        let endpoint = EndpointDescriptor {
            id: 1,
            generation: 1,
            identity_hostname: self.identity_hostname,
            trust_group,
            bindings: vec![BindingId::H2],
            ech_required: false,
        };
        let policy = EndpointPolicy::single(endpoint, self.address, NetworkEpoch::start())?;
        let trust = TrustPolicy::from_der_roots(trust_group, vec![self.trust_root_der])?;
        let services = Arc::new(HostServices::new(
            Arc::new(SystemBootstrapResolver),
            self.socket_factory,
            vec![trust],
            1,
        )?);
        let config = EngineConfig {
            limits: self.limits,
        };
        let engine = match self.resources {
            Some(resources) => {
                Engine::with_host_services_and_resources(config, services, resources)?
            }
            None => Engine::with_host_services(config, services)?,
        };
        Ok((engine, policy))
    }
}

/// Creates an H2/TLS engine for a fixed address and certificate DNS identity.
///
/// Returns an engine and its one-address H2 policy without network I/O. The
/// policy retains the supplied address; the hostname supplies TLS identity.
/// Trust material is validated by [`PinnedH2Builder::build`].
///
/// Uses lab limits and the default socket factory. Use [`PinnedH2Builder`] for
/// host limits, shared resources, or routing-loop protection hooks. The caller
/// must drive a Tokio runtime with I/O and time enabled for connections and retain
/// it through asynchronous engine shutdown.
pub fn pinned_h2_engine(
    address: SocketAddr,
    identity_hostname: String,
    trust_root_der: Vec<u8>,
) -> Result<(Engine, EndpointPolicy), EngineError> {
    PinnedH2Builder::new(address, identity_hostname, trust_root_der).build()
}

/// Verifies one echo flow in a new session and closes it.
///
/// Calls [`echo_in_session`] after connecting. Success returns the verified
/// payload length after graceful close. An empty payload returns
/// [`EngineError::InvalidConfig`] before connecting.
///
/// All operations share the supplied absolute deadline. Cleanup follows
/// [`close_after_operation`].
pub async fn echo_once(
    engine: &Engine,
    policy: &EndpointPolicy,
    credential: Credential,
    destination: &Destination,
    payload: &[u8],
    deadline: Deadline,
) -> Result<usize, EngineError> {
    if payload.is_empty() {
        return Err(EngineError::InvalidConfig);
    }
    let session = engine.connect(policy, credential, deadline).await?;
    let exchange_result = echo_in_session(&session, destination, payload, deadline).await;
    close_after_operation(&session, exchange_result, deadline).await
}

/// Closes a session and preserves the result of a completed operation.
///
/// Uses graceful close after success and immediate close after failure, under
/// the supplied absolute deadline. Operation errors take precedence over close
/// errors. Forced close after success returns [`EngineError::DeadlineExceeded`].
/// The caller still owns engine shutdown.
pub async fn close_after_operation<T>(
    session: &Session,
    operation_result: Result<T, EngineError>,
    deadline: Deadline,
) -> Result<T, EngineError> {
    let mode = if operation_result.is_ok() {
        CloseMode::Graceful
    } else {
        CloseMode::Immediate
    };
    let close_result = session.close(mode, deadline).await;
    match (operation_result, close_result) {
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(CloseOutcome::Graceful)) => Ok(value),
        (Ok(_), Ok(CloseOutcome::Forced)) => Err(EngineError::DeadlineExceeded),
    }
}

/// Shuts down an engine and preserves the result of a completed operation.
///
/// Awaits shutdown under the supplied absolute deadline, including after failure.
/// Operation errors take precedence over cleanup failures. Failed session cleanup
/// returns [`EngineError::TransportUnavailable`]. Otherwise, forced sessions or
/// pending connects return [`EngineError::DeadlineExceeded`].
pub async fn shutdown_after_operation<T>(
    engine: &Engine,
    operation_result: Result<T, EngineError>,
    deadline: Deadline,
) -> Result<T, EngineError> {
    let report = engine.shutdown_with_deadline(deadline).await;
    let value = operation_result?;
    if report.failed_sessions != 0 {
        return Err(EngineError::TransportUnavailable);
    }
    if report.forced_sessions != 0 || report.pending_connects != 0 {
        return Err(EngineError::DeadlineExceeded);
    }
    Ok(value)
}

/// Verifies one echo flow on a session that the caller can reuse.
///
/// Opens a TCP stream, writes bounded prefixes, verifies each reply before
/// writing the next prefix, ends writes, and requires clean EOF. Success returns
/// the verified payload length. An empty payload returns
/// [`EngineError::InvalidConfig`] before opening a stream. Replies use a 16 KiB
/// stack buffer. All operations share the supplied absolute deadline.
///
/// The target must echo each prefix before receiving the next one. This helper
/// does not close the session. The caller owns session close and engine shutdown
/// on both success and failure. Accepted payload is never replayed.
pub async fn echo_in_session(
    session: &Session,
    destination: &Destination,
    payload: &[u8],
    deadline: Deadline,
) -> Result<usize, EngineError> {
    if payload.is_empty() {
        return Err(EngineError::InvalidConfig);
    }
    let mut stream = session
        .open_stream(destination, StreamOptions::default(), deadline)
        .await?;
    let mut reply = [0u8; 16 * 1024];
    let mut verified_bytes = 0;
    while verified_bytes < payload.len() {
        let chunk_end = verified_bytes + (payload.len() - verified_bytes).min(reply.len());
        let accepted_bytes = stream
            .write(&payload[verified_bytes..chunk_end], deadline)
            .await?;
        if accepted_bytes == 0 || accepted_bytes > chunk_end - verified_bytes {
            return Err(EngineError::ProtocolViolation);
        }
        let mut chunk_reply_bytes = 0;
        while chunk_reply_bytes < accepted_bytes {
            let outcome = stream
                .read(&mut reply[..accepted_bytes - chunk_reply_bytes], deadline)
                .await?;
            match outcome {
                ReadOutcome::Data(count)
                    if count > 0 && count <= accepted_bytes - chunk_reply_bytes =>
                {
                    if reply[..count]
                        != payload[verified_bytes + chunk_reply_bytes
                            ..verified_bytes + chunk_reply_bytes + count]
                    {
                        return Err(EngineError::ProtocolViolation);
                    }
                    chunk_reply_bytes += count;
                }
                other => return Err(read_failure(other)),
            }
        }
        verified_bytes += accepted_bytes;
    }
    stream.end_write(deadline).await?;
    match stream.read(&mut reply, deadline).await? {
        ReadOutcome::Eof => Ok(verified_bytes),
        other => Err(read_failure(other)),
    }
}

fn read_failure(outcome: ReadOutcome) -> EngineError {
    match outcome {
        ReadOutcome::Cancelled => EngineError::Cancelled,
        ReadOutcome::Reset => EngineError::RemoteReset,
        ReadOutcome::Truncated | ReadOutcome::Eof => EngineError::TruncatedStream,
        ReadOutcome::Data(_) | ReadOutcome::Waiting => EngineError::ProtocolViolation,
    }
}
