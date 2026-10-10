#![forbid(unsafe_code)]

use std::any::Any;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ariad_core::{
    AuthzDecision, BudgetLimits, Credential, Destination, EngineError, MemoryBudget,
    ResourceBudget, ResourceReservation, ScopedMemoryReservation, ScopedResourceReservation,
    validate_ip_target,
};
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;
use tokio::time::timeout_at;

use crate::connect::{
    EXPERIMENTAL_CREDENTIAL_HEADER, attach_credential, attach_h2_versions, connect_template,
    validate_h2_versions,
};
use crate::dir::ReadOutcome;
use crate::host::{Authorizer, StaticAuthorizer};
use crate::{Deadline, retained_bytes_charge};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const DEFAULT_REPLY_LIMIT_BYTES: usize = 16 * 1024;
const DATA_FRAME_BUDGET: usize = 25_600;
const MAX_WINDOW: u32 = (1 << 31) - 1;
const HEADER_FIELD_OVERHEAD_BYTES: usize = 32;
const TERMINAL_PROBE_EVENTS_PER_POLL: usize = 64;

/// HTTP/2 flow control, admission limits, memory budgets, and phase timeouts.
///
/// Clones share their budgets. Default memory, header, and session admission
/// limits use [`BudgetLimits::lab_small`]. Defaults share process budgets and
/// create new session budgets.
#[derive(Clone, Debug)]
pub struct H2Config {
    /// Stream receive window and maximum send buffer size, in bytes.
    /// Must be in `1..=2_147_483_647` and fit the session budget with its control reserve.
    pub direction_buffer_bytes: usize,
    /// Memory reservation for connection control state, in bytes.
    pub control_reserve_bytes: usize,
    /// Decoded header bytes, including pseudo-headers and per-field HTTP/2 overhead.
    pub max_header_bytes: usize,
    /// Decoded header field count, including pseudo-headers.
    pub max_header_count: usize,
    /// Local flow limit and advertised concurrent stream limit.
    pub max_concurrent_streams: usize,
    /// Client pending-open limit. The session open budget must not exceed it.
    pub max_pending_opens: usize,
    /// Connection receive window, in bytes.
    pub initial_connection_window: u32,
    /// Header compression table limit, in bytes.
    pub header_table_bytes: u32,
    /// Handshake time limit, also used to cap a supplied handshake deadline.
    pub handshake_timeout: Duration,
    /// Limit for a client open, server authorization, or a target dial.
    pub open_timeout: Duration,
    /// Graceful drain time limit. Abort cleanup is awaited after expiry.
    pub drain_timeout: Duration,
    /// Shared memory budget across sessions. Its limit must cover the session budget.
    pub process_budget: MemoryBudget,
    /// Memory budget for this connection and its retained stream data.
    pub session_budget: MemoryBudget,
    /// Shared admission budget for stream flows across sessions.
    pub process_flows: ResourceBudget,
    /// Admission budget for stream flows in this session.
    pub session_flows: ResourceBudget,
    /// Shared budget for pending client opens and server target dials.
    pub process_opens: ResourceBudget,
    /// Budget for pending client opens and target dials in this session.
    pub session_opens: ResourceBudget,
}

impl Default for H2Config {
    fn default() -> Self {
        static PROCESS_MEMORY: OnceLock<MemoryBudget> = OnceLock::new();
        static PROCESS_FLOWS: OnceLock<ResourceBudget> = OnceLock::new();
        static PROCESS_OPENS: OnceLock<ResourceBudget> = OnceLock::new();
        let limits = BudgetLimits::lab_small();
        Self {
            direction_buffer_bytes: limits.stream_queue_per_direction,
            control_reserve_bytes: limits.control_reserve,
            max_header_bytes: limits.decoded_header_bytes,
            max_header_count: limits.decoded_header_fields,
            max_concurrent_streams: limits.active_flows_per_session,
            max_pending_opens: limits.pending_egress_opens,
            initial_connection_window: 1024 * 1024,
            header_table_bytes: 4096,
            handshake_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            process_budget: PROCESS_MEMORY
                .get_or_init(|| {
                    MemoryBudget::new(limits.global_application_budget)
                        .expect("nonzero default limit")
                })
                .clone(),
            session_budget: MemoryBudget::new(limits.session_application_budget)
                .expect("nonzero default limit"),
            process_flows: PROCESS_FLOWS
                .get_or_init(|| ResourceBudget::new(4096).expect("nonzero default limit"))
                .clone(),
            session_flows: ResourceBudget::new(limits.active_flows_per_session)
                .expect("nonzero default limit"),
            process_opens: PROCESS_OPENS
                .get_or_init(|| ResourceBudget::new(512).expect("nonzero default limit"))
                .clone(),
            session_opens: ResourceBudget::new(limits.pending_egress_opens)
                .expect("nonzero default limit"),
        }
    }
}

impl H2Config {
    /// Checks protocol ranges, budget relationships, and nonzero phase timeouts.
    pub fn validate(&self) -> Result<(), EngineError> {
        let phase_timeouts = [
            self.handshake_timeout,
            self.open_timeout,
            self.drain_timeout,
        ];
        if self.direction_buffer_bytes == 0
            || self.direction_buffer_bytes > MAX_WINDOW as usize
            || self.max_header_bytes == 0
            || self.max_header_bytes > u32::MAX as usize
            || self.max_header_count == 0
            || self.max_concurrent_streams == 0
            || self.max_concurrent_streams > u32::MAX as usize
            || self.max_pending_opens == 0
            || self.max_pending_opens > self.max_concurrent_streams
            || self.session_opens.limit() > self.max_pending_opens
            || self.initial_connection_window == 0
            || self.initial_connection_window > MAX_WINDOW
            || self.header_table_bytes as usize > self.max_header_bytes
            || phase_timeouts.iter().any(Duration::is_zero)
            || self.control_reserve_bytes == 0
            || self
                .direction_buffer_bytes
                .checked_add(self.control_reserve_bytes)
                .is_none_or(|required| required > self.session_budget.limit())
            || self.session_budget.limit() > self.process_budget.limit()
            || phase_timeouts
                .iter()
                .any(|timeout| Deadline::after(*timeout).is_err())
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }

    pub(crate) fn reserve_memory(
        &self,
        bytes: usize,
    ) -> Result<ScopedMemoryReservation, EngineError> {
        self.process_budget
            .try_acquire_scoped(&self.session_budget, bytes)
    }

    pub(crate) fn reserve_flow(&self) -> Result<ScopedResourceReservation, EngineError> {
        self.process_flows.try_acquire_scoped(&self.session_flows)
    }

    pub(crate) fn reserve_open(&self) -> Result<ScopedResourceReservation, EngineError> {
        self.process_opens.try_acquire_scoped(&self.session_opens)
    }
}

#[derive(Clone, Copy)]
enum DriverState {
    Running,
    Finished(Result<(), EngineError>),
}

struct OwnedDriver<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    connection: Option<h2::client::Connection<I, Bytes>>,
    finished: watch::Sender<DriverState>,
    result: Option<Result<(), EngineError>>,
    control: Option<ScopedMemoryReservation>,
    flows: Arc<Mutex<FlowRegistry>>,
    _metadata: Arc<ScopedMemoryReservation>,
}

impl<I> Drop for OwnedDriver<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn drop(&mut self) {
        self.connection.take();
        // Publish completion after IO and network admission permits are released.
        let mut registry = self.flows.lock().unwrap_or_else(|error| error.into_inner());
        registry.closed = true;
        for flow in registry.flows.drain(..).filter_map(|flow| flow.upgrade()) {
            flow.release();
        }
        drop(registry);
        self.control.take();
        // Task abort drops the future without unwinding. A panic is a transport failure.
        let result = self.result.unwrap_or_else(|| {
            Err(if std::thread::panicking() {
                EngineError::TransportUnavailable
            } else {
                EngineError::Cancelled
            })
        });
        let _ = self.finished.send(DriverState::Finished(result));
    }
}

struct SessionOwner {
    client: Mutex<Option<h2::client::SendRequest<Bytes>>>,
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
    abort: tokio::task::AbortHandle,
    state: watch::Receiver<DriverState>,
    accepting: AtomicBool,
    cancelled: AtomicBool,
    closed: AtomicBool,
    flow_slots: ResourceBudget,
    outstanding_flows: Arc<AtomicUsize>,
    pending_opens: ResourceBudget,
    activity: Arc<Notify>,
    flows: Arc<Mutex<FlowRegistry>>,
    config: H2Config,
    _memory: Arc<ScopedMemoryReservation>,
}

impl SessionOwner {
    fn abort_connection(&self) {
        self.accepting.store(false, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
        self.client
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        self.abort.abort();
        self.activity.notify_waiters();
    }

    fn driver_result(&self) -> Option<Result<(), EngineError>> {
        match *self.state.borrow() {
            DriverState::Running => None,
            DriverState::Finished(result) => Some(result),
        }
    }

    async fn join_driver(&self) {
        let task = self
            .driver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(task) = task {
            let _ = task.await;
        } else {
            // One closer takes the task handle. Others observe driver cleanup through the channel.
            let mut state = self.state.clone();
            loop {
                if matches!(*state.borrow(), DriverState::Finished(_)) {
                    break;
                }
                if state.changed().await.is_err() {
                    break;
                }
            }
        }
    }
}

impl Drop for SessionOwner {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

struct ActiveStream {
    resources: Arc<ActiveResources>,
}

struct ActiveResources {
    // Open completion, driver cleanup, and stream drop take each permit under this mutex.
    permits: Mutex<ActivePermits>,
    activity: Arc<Notify>,
    outstanding_flows: Arc<AtomicUsize>,
}

struct ActivePermits {
    local_flow: Option<ResourceReservation>,
    scoped_flow: Option<ScopedResourceReservation>,
    local_open: Option<ResourceReservation>,
    scoped_open: Option<ScopedResourceReservation>,
}

// Registration and driver cleanup use the same mutex. Once closed, registration
// rejects the open and drops its permits instead of adding a flow after cleanup.
struct FlowRegistry {
    closed: bool,
    flows: Vec<Weak<ActiveResources>>,
}

impl ActiveResources {
    fn release(&self) {
        let mut permits = self
            .permits
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        permits.local_flow.take();
        permits.scoped_flow.take();
        permits.local_open.take();
        permits.scoped_open.take();
        drop(permits);
        self.activity.notify_waiters();
    }

    fn release_open(&self) {
        let mut permits = self
            .permits
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        permits.local_open.take();
        permits.scoped_open.take();
    }
}

impl Drop for ActiveResources {
    fn drop(&mut self) {
        // This owner can outlive permits already returned by driver cleanup.
        self.outstanding_flows.fetch_sub(1, Ordering::AcqRel);
        self.activity.notify_waiters();
    }
}

impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.resources.release();
    }
}

struct CloseGuard {
    owner: Arc<SessionOwner>,
    armed: bool,
}

impl Drop for CloseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.owner.abort_connection();
        }
    }
}

/// A shared HTTP/2 client connection driven by a background task.
///
/// Clones and open streams retain the connection owner. Dropping the last owner
/// requests driver abort; use `close` to await driver cleanup.
#[derive(Clone)]
pub struct H2Session {
    owner: Arc<SessionOwner>,
}

impl H2Session {
    /// Completes the control handshake and starts a driver with default settings.
    ///
    /// The caller must verify the IO peer before setting `peer_verified`.
    /// A false value is rejected before any preface is sent. Completion waits for
    /// initial peer SETTINGS and a PONG.
    pub async fn handshake<I>(io: I, peer_verified: bool) -> Result<Self, EngineError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::handshake_with_config(io, peer_verified, H2Config::default()).await
    }

    /// Uses the configured handshake timeout and the peer check required by
    /// [`Self::handshake`].
    pub async fn handshake_with_config<I>(
        io: I,
        peer_verified: bool,
        config: H2Config,
    ) -> Result<Self, EngineError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let deadline = Deadline::after(config.handshake_timeout)?;
        Self::handshake_with_deadline(io, peer_verified, config, deadline).await
    }

    /// Uses the earlier of `deadline` and the configured handshake timeout.
    ///
    /// The peer check from [`Self::handshake`] applies. Dropping the pending
    /// handshake releases the IO; no driver owns it before the control handshake completes.
    pub async fn handshake_with_deadline<I>(
        io: I,
        peer_verified: bool,
        config: H2Config,
        deadline: Deadline,
    ) -> Result<Self, EngineError>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !peer_verified {
            return Err(EngineError::PeerIdentityFailed);
        }
        config.validate()?;
        let deadline = deadline.cap(config.handshake_timeout)?;
        let control = config.reserve_memory(config.control_reserve_bytes)?;
        let registry_capacity = config
            .max_concurrent_streams
            .min(config.session_flows.limit());
        let registry_bytes = registry_capacity
            .checked_mul(std::mem::size_of::<Weak<ActiveResources>>())
            .ok_or(EngineError::ResourceLimitExceeded)?;
        // The fixed allowance covers Arc, watch, notification, and counter storage.
        let owner_bytes = std::mem::size_of::<SessionOwner>()
            .checked_add(1024)
            .and_then(|bytes| bytes.checked_add(registry_bytes))
            .ok_or(EngineError::ResourceLimitExceeded)?;
        let owner_memory = Arc::new(config.reserve_memory(owner_bytes)?);
        let mut registry = Vec::new();
        registry
            .try_reserve_exact(registry_capacity)
            .map_err(|_| EngineError::ResourceLimitExceeded)?;
        if registry.capacity() > registry_capacity {
            return Err(EngineError::ResourceLimitExceeded);
        }
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(config.direction_buffer_bytes as u32)
            .initial_connection_window_size(config.initial_connection_window)
            .max_frame_size(MAX_FRAME_BYTES as u32)
            .max_header_list_size(config.max_header_bytes as u32)
            .header_table_size(config.header_table_bytes)
            .max_concurrent_streams(config.max_concurrent_streams as u32)
            .initial_max_send_streams(config.max_concurrent_streams)
            .max_send_buffer_size(config.direction_buffer_bytes)
            .max_concurrent_reset_streams(config.max_concurrent_streams)
            .max_pending_accept_reset_streams(config.max_concurrent_streams)
            .max_local_error_reset_streams(Some(config.max_concurrent_streams))
            .data_frame_budget(DATA_FRAME_BUDGET)
            .enable_push(false);
        let (client, mut connection) = deadline
            .run(async { builder.handshake(io).await.map_err(map_h2) })
            .await?;
        let mut ping = connection
            .ping_pong()
            .ok_or(EngineError::TransportUnavailable)?;
        // Initial peer SETTINGS must precede the PONG. No task owns IO before this proof.
        deadline.run(async {
            tokio::select! {
                result = &mut connection => Err(result.err().map(map_h2).unwrap_or(EngineError::TransportUnavailable)),
                result = ping.ping(h2::Ping::opaque()) => result.map_err(map_h2),
            }
        }).await?;
        let (finished, state) = watch::channel(DriverState::Running);
        let flows = Arc::new(Mutex::new(FlowRegistry {
            closed: false,
            flows: registry,
        }));
        let driver_flows = Arc::clone(&flows);
        let driver_metadata = Arc::clone(&owner_memory);
        deadline.remaining()?;
        let driver = tokio::spawn(async move {
            let mut owned = OwnedDriver {
                connection: Some(connection),
                finished,
                result: None,
                control: Some(control),
                flows: driver_flows,
                _metadata: driver_metadata,
            };
            owned.result = Some(match owned.connection.as_mut() {
                Some(connection) => connection.await.map_err(map_h2),
                None => Err(EngineError::TransportUnavailable),
            });
        });
        let owner = Arc::new(SessionOwner {
            client: Mutex::new(Some(client)),
            abort: driver.abort_handle(),
            driver: Mutex::new(Some(driver)),
            state,
            accepting: AtomicBool::new(true),
            cancelled: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            flow_slots: ResourceBudget::new(config.max_concurrent_streams)?,
            outstanding_flows: Arc::new(AtomicUsize::new(0)),
            pending_opens: ResourceBudget::new(config.max_pending_opens)?,
            activity: Arc::new(Notify::new()),
            flows,
            config,
            _memory: owner_memory,
        });
        Ok(Self { owner })
    }

    /// Opens a CONNECT stream using the configured open timeout.
    ///
    /// A response completes the open. Inspect [`H2Connect::status`] for admission;
    /// non-OK responses are returned as streams.
    pub async fn open_stream(
        &self,
        destination: &Destination,
        credential: &Credential,
    ) -> Result<H2Connect, EngineError> {
        let deadline = Deadline::after(self.owner.config.open_timeout)?;
        self.open_stream_with_deadline(destination, credential, deadline)
            .await
    }

    /// Opens a CONNECT stream with the deadline and cancellation rules of
    /// [`Self::open_request_with_deadline`].
    pub async fn open_stream_with_deadline(
        &self,
        destination: &Destination,
        credential: &Credential,
        deadline: Deadline,
    ) -> Result<H2Connect, EngineError> {
        self.open_request_with_deadline(connect_template(destination)?, credential, deadline)
            .await
    }

    /// Sends a caller-built HTTP/2 request with the credential header.
    ///
    /// CONNECT version headers must already be valid. The configured open timeout
    /// applies, and non-OK response statuses are returned to the caller.
    pub async fn open_request(
        &self,
        request: Request<()>,
        credential: &Credential,
    ) -> Result<H2Connect, EngineError> {
        let deadline = Deadline::after(self.owner.config.open_timeout)?;
        self.open_request_with_deadline(request, credential, deadline)
            .await
    }

    /// Sends a request using the earlier of `deadline` and the configured open timeout.
    ///
    /// The request rules of [`Self::open_request`] apply. Dropping the pending
    /// future resets any submitted stream and returns its admission permits.
    pub async fn open_request_with_deadline(
        &self,
        mut request: Request<()>,
        credential: &Credential,
        deadline: Deadline,
    ) -> Result<H2Connect, EngineError> {
        let config = &self.owner.config;
        let deadline = deadline.cap(config.open_timeout)?;
        if request.method() == Method::CONNECT {
            validate_h2_versions(request.headers())?;
        }
        attach_credential(&mut request, credential)?;
        *request.version_mut() = Version::HTTP_2;
        check_request_headers(&request, config)?;
        self.check_open()?;
        let permits = ActivePermits {
            local_flow: Some(self.owner.flow_slots.try_acquire()?),
            scoped_flow: Some(config.reserve_flow()?),
            local_open: Some(self.owner.pending_opens.try_acquire()?),
            scoped_open: Some(config.reserve_open()?),
        };
        self.owner
            .outstanding_flows
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| EngineError::ResourceLimitExceeded)?;
        let active = ActiveStream {
            resources: Arc::new(ActiveResources {
                permits: Mutex::new(permits),
                activity: Arc::clone(&self.owner.activity),
                outstanding_flows: Arc::clone(&self.owner.outstanding_flows),
            }),
        };
        {
            let mut registry = self
                .owner
                .flows
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if registry.closed {
                return Err(EngineError::TransportUnavailable);
            }
            registry.flows.retain(|flow| flow.strong_count() != 0);
            if registry.flows.len() == registry.flows.capacity() {
                return Err(EngineError::ResourceLimitExceeded);
            }
            registry.flows.push(Arc::downgrade(&active.resources));
        }
        let client = self
            .owner
            .client
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .cloned()
            .ok_or(EngineError::Cancelled)?;
        let mut client = deadline
            .run(async { client.ready().await.map_err(map_h2) })
            .await?;
        self.check_open()?;
        deadline.remaining()?;
        let (response, send) = client.send_request(request, false).map_err(map_h2)?;
        let mut pending_open = ResetOnDrop { send: Some(send) };
        let response = deadline
            .run(async { response.await.map_err(map_h2) })
            .await?;
        check_response_headers(&response, config)?;
        if response.status() == StatusCode::OK {
            validate_h2_versions(response.headers())?;
        }
        // Weak controls retain the Arc allocation after its stream owner drops.
        let half_bytes = std::mem::size_of::<H2ReadHalf>()
            .checked_add(std::mem::size_of::<H2WriteHalf>())
            .ok_or(EngineError::ResourceLimitExceeded)?;
        let handle_charge = std::mem::size_of::<H2Connect>()
            .max(half_bytes)
            .checked_add(std::mem::size_of::<H2StreamShared>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ScopedMemoryReservation>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or(EngineError::ResourceLimitExceeded)?;
        let handle_memory = config.reserve_memory(handle_charge)?;
        let response_memory = config.reserve_memory(retained_header_charge(response.headers())?)?;
        deadline.remaining()?;
        let (parts, recv) = response.into_parts();
        active.resources.release_open();
        Ok(H2Connect {
            shared: Arc::new(H2StreamShared {
                owner: Arc::clone(&self.owner),
                state: Mutex::new(H2StreamState {
                    active: Some(active),
                    send: pending_open.send.take(),
                    recv: Some(recv),
                    pending_read: Bytes::new(),
                    terminal_read_queue: TerminalReadQueue::new(),
                    terminal_probe_events: 0,
                    deferred_read_error: None,
                    write_closed: false,
                    read_state: ReadState::Open,
                    read_abandoned: false,
                    write_waiter: None,
                }),
                changed: Notify::new(),
                _handle_memory: Arc::new(handle_memory),
            }),
            status: parts.status,
            response_headers: parts.headers,
            response_memory: Some(response_memory),
            reset_on_drop: true,
        })
    }

    /// Reports whether the live, accepting connection enables extended CONNECT.
    ///
    /// This snapshot can become stale before an open and does not reserve admission.
    pub fn extended_connect_enabled(&self) -> bool {
        self.owner.accepting.load(Ordering::Acquire)
            && self.owner.driver_result().is_none()
            && self
                .owner
                .client
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_some_and(h2::client::SendRequest::is_extended_connect_protocol_enabled)
    }

    /// Reports driver failure or loss of a connection that still accepts opens.
    /// A completed clean close suppresses this error.
    pub fn driver_error(&self) -> Option<EngineError> {
        if self.owner.closed.load(Ordering::Acquire) {
            return None;
        }
        match self.owner.driver_result() {
            Some(Ok(())) if self.owner.accepting.load(Ordering::Acquire) => {
                Some(EngineError::TransportUnavailable)
            }
            Some(Err(error)) => Some(error),
            Some(Ok(())) | None => None,
        }
    }

    pub fn config(&self) -> &H2Config {
        &self.owner.config
    }

    /// Reports pending opens or flows that have not been released locally.
    /// Driver failure can return admission permits before these flows are released.
    pub fn has_outstanding_flows(&self) -> bool {
        self.owner.outstanding_flows.load(Ordering::Acquire) != 0
    }

    /// Waits for the driver result or loss of its completion channel.
    ///
    /// Normal completion is reported after IO and network admission permits are
    /// released. Retained stream data and metadata keep their memory charges.
    /// Loss of the completion channel returns `TransportUnavailable`.
    pub async fn wait_closed(&self) -> Result<(), EngineError> {
        let mut state = self.owner.state.clone();
        loop {
            if let DriverState::Finished(result) = *state.borrow() {
                return result;
            }
            state
                .changed()
                .await
                .map_err(|_| EngineError::TransportUnavailable)?;
        }
    }

    /// Rejects new opens and requests driver abort without waiting for cleanup.
    ///
    /// Use `close` to await IO release. Stream buffers are discarded when those
    /// streams next observe session cancellation.
    pub fn cancel(&self) {
        self.owner.abort_connection();
    }

    /// Stops admission and drains flows within `timeout`, capped by `drain_timeout`.
    ///
    /// Drain expiry aborts and joins the driver before returning `DeadlineExceeded`.
    /// Cleanup is awaited after expiry. Dropping a pending close requests abort and
    /// leaves cleanup to the driver.
    pub async fn close(&self, timeout: Duration) -> Result<(), EngineError> {
        self.close_with_deadline(Deadline::after(timeout)?).await
    }

    /// Applies [`Self::close`] using the earlier of `deadline` and `drain_timeout`.
    /// A completed clean close can be called again. Session cancellation returns
    /// `Cancelled` after driver cleanup.
    pub async fn close_with_deadline(&self, deadline: Deadline) -> Result<(), EngineError> {
        let driver_error_on_entry = if matches!(self.owner.driver_result(), Some(Ok(())))
            && self.owner.outstanding_flows.load(Ordering::Acquire) == 0
        {
            None
        } else {
            self.driver_error()
        };
        self.owner.accepting.store(false, Ordering::Release);
        let mut guard = CloseGuard {
            owner: Arc::clone(&self.owner),
            armed: true,
        };
        if self.owner.cancelled.load(Ordering::Acquire) {
            self.owner.join_driver().await;
            guard.armed = false;
            return Err(EngineError::Cancelled);
        }
        if self.owner.closed.load(Ordering::Acquire) {
            self.owner.join_driver().await;
            guard.armed = false;
            return Ok(());
        }
        let deadline = match deadline.cap(self.owner.config.drain_timeout) {
            Ok(deadline) => deadline,
            Err(error) => {
                self.owner.abort_connection();
                self.owner.join_driver().await;
                guard.armed = false;
                return Err(error);
            }
        };
        let drain = async {
            let mut driver = self.owner.state.clone();
            loop {
                let changed = self.owner.activity.notified();
                tokio::pin!(changed);
                // Register before checking state so a release before the await is observed.
                changed.as_mut().enable();
                if self.owner.flow_slots.used() == 0 || self.owner.driver_result().is_some() {
                    return;
                }
                tokio::select! {
                    _ = changed => {}
                    _ = driver.changed() => {}
                }
            }
        };
        let drained = deadline
            .run(async {
                drain.await;
                Ok(())
            })
            .await
            .is_ok();
        let driver_error = driver_error_on_entry.or_else(|| match self.owner.driver_result() {
            Some(Err(EngineError::Cancelled)) if !self.owner.cancelled.load(Ordering::Acquire) => {
                None
            }
            Some(Err(error)) => Some(error),
            Some(Ok(())) if self.has_outstanding_flows() => Some(EngineError::TransportUnavailable),
            _ => None,
        });
        let mut forced = !drained;
        if forced {
            self.owner.abort_connection();
        } else {
            self.owner
                .client
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            // Only deadline expiry forces abort. Preserve the driver result for classification.
            if deadline
                .run(async { Ok(self.wait_closed().await) })
                .await
                .is_err()
            {
                forced = true;
                self.owner.abort_connection();
            }
        }
        self.owner.join_driver().await;
        let driver_error = driver_error.or_else(|| match self.owner.driver_result() {
            Some(Err(EngineError::Cancelled)) if !self.owner.cancelled.load(Ordering::Acquire) => {
                None
            }
            Some(Err(error)) => Some(error),
            _ => None,
        });
        if !forced && driver_error.is_none() {
            self.owner.closed.store(true, Ordering::Release);
        }
        guard.armed = false;
        if forced {
            Err(EngineError::DeadlineExceeded)
        } else {
            driver_error.map_or(Ok(()), Err)
        }
    }

    fn check_open(&self) -> Result<(), EngineError> {
        if self.owner.cancelled.load(Ordering::Acquire) {
            return Err(EngineError::Cancelled);
        }
        if !self.owner.accepting.load(Ordering::Acquire) {
            return Err(EngineError::ProtocolViolation);
        }
        if let Some(result) = self.owner.driver_result() {
            return Err(result.err().unwrap_or(EngineError::TransportUnavailable));
        }
        Ok(())
    }
}

struct ResetOnDrop {
    send: Option<h2::SendStream<Bytes>>,
}

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Some(send) = self.send.as_mut() {
            send.send_reset(h2::Reason::CANCEL);
        }
    }
}

/// A CONNECT response status and reply collected by the round-trip helpers.
#[derive(Debug)]
pub struct ClientRoundtrip {
    pub status: StatusCode,
    pub reply: Bytes,
}

enum ReadState {
    Open,
    Eof,
    Reset,
    Cancelled,
    Failed,
}

struct H2StreamState {
    active: Option<ActiveStream>,
    send: Option<h2::SendStream<Bytes>>,
    recv: Option<RecvStream>,
    pending_read: Bytes,
    terminal_read_queue: TerminalReadQueue,
    terminal_probe_events: usize,
    deferred_read_error: Option<EngineError>,
    write_closed: bool,
    read_state: ReadState,
    read_abandoned: bool,
    write_waiter: Option<Waker>,
}

struct TerminalReadQueue {
    chunks: VecDeque<Bytes>,
    bytes: usize,
    memory: Option<ScopedMemoryReservation>,
}

impl TerminalReadQueue {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            memory: None,
        }
    }

    fn push(
        &mut self,
        chunk: &[u8],
        pending_bytes: usize,
        config: &H2Config,
    ) -> Result<(), EngineError> {
        let queued_bytes = self
            .bytes
            .checked_add(chunk.len())
            .ok_or(EngineError::ResourceLimitExceeded)?;
        if pending_bytes
            .checked_add(queued_bytes)
            .is_none_or(|bytes| bytes > config.direction_buffer_bytes)
        {
            return Err(EngineError::ResourceLimitExceeded);
        }
        if self.chunks.len() == self.chunks.capacity() {
            let capacity = self
                .chunks
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or(EngineError::ResourceLimitExceeded)?
                .min(config.direction_buffer_bytes);
            let charge = capacity
                .checked_mul(std::mem::size_of::<Bytes>())
                .ok_or(EngineError::ResourceLimitExceeded)?;
            let memory = config.reserve_memory(charge)?;
            let mut chunks = VecDeque::new();
            chunks
                .try_reserve_exact(capacity)
                .map_err(|_| EngineError::ResourceLimitExceeded)?;
            if chunks.capacity() > capacity {
                return Err(EngineError::ResourceLimitExceeded);
            }
            while let Some(chunk) = self.chunks.pop_front() {
                chunks.push_back(chunk);
            }
            self.chunks = chunks;
            self.memory = Some(memory);
        }
        let retained = budgeted_bytes(chunk, config)?;
        self.chunks.push_back(retained);
        self.bytes = queued_bytes;
        Ok(())
    }

    fn pop(&mut self) -> Option<Bytes> {
        let chunk = self.chunks.pop_front()?;
        self.bytes -= chunk.len();
        if self.chunks.is_empty() {
            self.clear();
        }
        Some(chunk)
    }

    fn clear(&mut self) {
        self.chunks = VecDeque::new();
        self.bytes = 0;
        self.memory.take();
    }
}

struct H2StreamShared {
    owner: Arc<SessionOwner>,
    state: Mutex<H2StreamState>,
    changed: Notify,
    _handle_memory: Arc<ScopedMemoryReservation>,
}

/// One response-backed HTTP/2 stream that can be consumed into independent halves.
///
/// Writes require an OK response. Dropping an unfinished combined handle requests
/// a CANCEL reset. The handle retains its session and charged stream metadata.
pub struct H2Connect {
    shared: Arc<H2StreamShared>,
    status: StatusCode,
    response_headers: HeaderMap,
    response_memory: Option<ScopedMemoryReservation>,
    reset_on_drop: bool,
}

/// An independently readable response half with shared reset and cancellation.
///
/// Dropping it discards unread data and leaves the writer usable. Response headers
/// and their memory charge stay with this half until terminal observation or drop.
pub struct H2ReadHalf {
    shared: Arc<H2StreamShared>,
    status: StatusCode,
    response_headers: HeaderMap,
    response_memory: Option<ScopedMemoryReservation>,
}

/// An independently writable request half with shared reset and cancellation.
///
/// Dropping an open writer attempts END_STREAM. Transport loss closes writes and
/// preserves unread data. Reset, cancellation, and probe limit errors discard it.
/// Dropping a pending write returns unsubmitted send capacity without a reset.
pub struct H2WriteHalf {
    shared: Arc<H2StreamShared>,
    status: StatusCode,
}

/// A cancellation handle that retains metadata charge without owning the flow.
#[derive(Clone)]
pub struct H2StreamControl {
    shared: Weak<H2StreamShared>,
    _memory: Arc<ScopedMemoryReservation>,
}

/// Performs [`H2Session::handshake`] and opens one CONNECT stream.
/// The caller must verify the IO peer before setting `peer_verified`.
pub async fn open_h2<I>(
    io: I,
    destination: &Destination,
    credential: &Credential,
    peer_verified: bool,
) -> Result<H2Connect, EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    H2Session::handshake(io, peer_verified)
        .await?
        .open_stream(destination, credential)
        .await
}

impl H2Connect {
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns response headers retained through EOF. Reset, cancellation, and
    /// stream failure clear them.
    pub fn response_headers(&self) -> &HeaderMap {
        self.shared.visible_headers(&self.response_headers)
    }

    /// Returns a control that can interrupt independently pending read and write.
    pub fn control(&self) -> H2StreamControl {
        self.shared.control()
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub(crate) fn reserve_metadata(
        &self,
        bytes: usize,
    ) -> Result<ScopedMemoryReservation, EngineError> {
        self.shared.owner.config.reserve_memory(bytes)
    }

    /// Consumes this handle into independently pollable read and write owners.
    /// Reset and cancellation on either owner affect both directions.
    pub fn into_split(mut self) -> (H2ReadHalf, H2WriteHalf) {
        self.reset_on_drop = false;
        (
            H2ReadHalf {
                shared: Arc::clone(&self.shared),
                status: self.status,
                response_headers: std::mem::take(&mut self.response_headers),
                response_memory: self.response_memory.take(),
            },
            H2WriteHalf {
                shared: Arc::clone(&self.shared),
                status: self.status,
            },
        )
    }

    /// Queues at most one bounded DATA fragment after waiting for send credit.
    ///
    /// Returns the bytes accepted by h2; the caller retains responsibility for
    /// the remainder. Dropping a pending write does not reset the stream. Queued
    /// data is not rolled back, and success does not establish peer receipt.
    /// Requires nonempty input and an open write half with an OK response.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, EngineError> {
        let result = self.shared.write(self.status, bytes).await;
        self.release_terminal_headers();
        result
    }

    /// Queues END_STREAM for the write half. Reads remain available until receive
    /// EOF; both halves must finish before flow admission is released normally.
    /// Further writes and repeated calls are rejected.
    pub async fn end_write(&mut self) -> Result<(), EngineError> {
        let result = self.shared.end_write(self.status).await;
        self.release_terminal_headers();
        result
    }

    /// Waits for data or a receive outcome and returns credit for copied bytes.
    ///
    /// EOF closes only the read half. Reads drain retained bytes before reporting
    /// transport loss. Stream reset or cancellation discards unread bytes and
    /// returns its matching outcome. The first observation of session cancellation
    /// returns `EngineError::Cancelled`; later reads return `ReadOutcome::Cancelled`.
    /// Distinguishing reset from GOAWAY may retain queued DATA. The probe returns
    /// `ResourceLimitExceeded` if its memory or bounded DATA-event limit is exceeded.
    /// Use a nonempty output buffer while the read half is open.
    pub async fn read(&mut self, out: &mut [u8]) -> Result<ReadOutcome, EngineError> {
        let result = self.shared.read(out).await;
        self.release_terminal_headers();
        result
    }

    /// Requests a CANCEL reset and discards unread bytes and response headers.
    /// Later reads return `Reset`; writes and repeated resets are rejected.
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Reset)?;
        self.release_terminal_headers();
        Ok(())
    }

    /// Requests the same wire reset as `reset`, but later reads return `Cancelled`.
    /// Discards unread bytes and response headers without waiting for peer acknowledgment.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Cancelled)?;
        self.release_terminal_headers();
        Ok(())
    }

    fn release_terminal_headers(&mut self) {
        self.shared
            .release_terminal_headers(&mut self.response_headers, &mut self.response_memory);
    }
}

impl Drop for H2Connect {
    fn drop(&mut self) {
        if self.reset_on_drop {
            self.shared.abort_unfinished();
        }
    }
}

impl H2ReadHalf {
    /// Returns the CONNECT response status.
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns headers through EOF, or an empty map after reset, cancellation, or failure.
    pub fn response_headers(&self) -> &HeaderMap {
        self.shared.visible_headers(&self.response_headers)
    }

    /// Returns a control for both directions without retaining flow admission.
    pub fn control(&self) -> H2StreamControl {
        self.shared.control()
    }

    /// Reads with the receive and cancellation semantics of [`H2Connect::read`].
    pub async fn read(&mut self, out: &mut [u8]) -> Result<ReadOutcome, EngineError> {
        let result = self.shared.read(out).await;
        self.release_terminal_headers();
        result
    }

    /// Resets both directions with the semantics of [`H2Connect::reset`].
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Reset)?;
        self.release_terminal_headers();
        Ok(())
    }

    /// Cancels both directions with the semantics of [`H2Connect::cancel`].
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Cancelled)?;
        self.release_terminal_headers();
        Ok(())
    }

    pub(crate) fn release_terminal_headers(&mut self) {
        self.shared
            .release_terminal_headers(&mut self.response_headers, &mut self.response_memory);
    }
}

impl Drop for H2ReadHalf {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock_state();
            let released = state
                .pending_read
                .len()
                .checked_add(state.terminal_read_queue.bytes)
                .ok_or(EngineError::ResourceLimitExceeded)
                .and_then(|unread| {
                    if unread == 0 {
                        return Ok(());
                    }
                    state
                        .recv
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .flow_control()
                        .release_capacity(unread)
                        .map_err(map_h2)
                });
            if let Err(error) = released {
                state.fail_stream(error);
            }
            state.discard_read_buffers();
            state.recv.take();
            state.read_abandoned = true;
            state.release_finished();
        }
        self.shared.changed.notify_waiters();
    }
}

impl H2WriteHalf {
    /// Returns the CONNECT response status.
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a control for both directions without retaining flow admission.
    pub fn control(&self) -> H2StreamControl {
        self.shared.control()
    }

    /// Writes with the partial acceptance and drop semantics of [`H2Connect::write`].
    pub async fn write(&mut self, bytes: &[u8]) -> Result<usize, EngineError> {
        self.shared.write(self.status, bytes).await
    }

    /// Queues request END_STREAM while leaving reads available.
    pub async fn end_write(&mut self) -> Result<(), EngineError> {
        self.shared.end_write(self.status).await
    }

    /// Resets both directions with the semantics of [`H2Connect::reset`].
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Reset)
    }

    /// Cancels both directions with the semantics of [`H2Connect::cancel`].
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.shared.reset(ReadState::Cancelled)
    }
}

impl Drop for H2WriteHalf {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock_state();
            if !state.write_closed && state.terminal_error().is_none() {
                match state.send_data(Bytes::new(), true) {
                    Ok(()) => {
                        state.write_closed = true;
                        state.release_finished();
                    }
                    Err(error) => {
                        let terminal = state.poll_write_ready(
                            &mut Context::from_waker(Waker::noop()),
                            &self.shared.owner,
                        );
                        let resolved = match terminal {
                            Poll::Ready(Err(resolved)) => resolved,
                            Poll::Ready(Ok(())) | Poll::Pending => error,
                        };
                        state.fail_write(resolved);
                        if terminal.is_ready() {
                            state.release_finished();
                        }
                    }
                }
            }
        }
        self.shared.changed.notify_waiters();
    }
}

impl H2StreamControl {
    /// Requests CANCEL reset on both halves; later reads report `Reset`.
    /// Returns `Cancelled` when both stream owners have already dropped.
    pub fn reset(&self) -> Result<(), EngineError> {
        self.shared
            .upgrade()
            .ok_or(EngineError::Cancelled)?
            .reset(ReadState::Reset)
    }

    /// Requests CANCEL reset on both halves; later reads report `Cancelled`.
    /// Returns `Cancelled` when both stream owners have already dropped.
    pub fn cancel(&self) -> Result<(), EngineError> {
        self.shared
            .upgrade()
            .ok_or(EngineError::Cancelled)?
            .reset(ReadState::Cancelled)
    }
}

struct CapacityReservation<'a> {
    // Keep assigned credit until DATA is queued or this operation is dropped.
    shared: &'a H2StreamShared,
}

impl Drop for CapacityReservation<'_> {
    fn drop(&mut self) {
        let mut state = self.shared.lock_state();
        if let Some(send) = state.send.as_mut() {
            send.reserve_capacity(0);
        }
        state.write_waiter = None;
    }
}

impl H2StreamShared {
    fn control(self: &Arc<Self>) -> H2StreamControl {
        H2StreamControl {
            shared: Arc::downgrade(self),
            _memory: Arc::clone(&self._handle_memory),
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, H2StreamState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn is_terminal(&self) -> bool {
        self.lock_state().terminal_error().is_some()
    }

    fn visible_headers<'a>(&self, headers: &'a HeaderMap) -> &'a HeaderMap {
        if self.is_terminal() {
            static EMPTY: OnceLock<HeaderMap> = OnceLock::new();
            EMPTY.get_or_init(HeaderMap::new)
        } else {
            headers
        }
    }

    fn release_terminal_headers(
        &self,
        headers: &mut HeaderMap,
        memory: &mut Option<ScopedMemoryReservation>,
    ) {
        if self.is_terminal() {
            *headers = HeaderMap::new();
            memory.take();
        }
    }

    fn reset(&self, read_state: ReadState) -> Result<(), EngineError> {
        {
            let mut state = self.lock_state();
            if state.terminal_error().is_some() {
                return Err(EngineError::ProtocolViolation);
            }
            if let Some(mut send) = state.send.take() {
                send.send_reset(h2::Reason::CANCEL);
            }
            state.discard_read_buffers();
            state.recv.take();
            state.read_state = read_state;
            state.write_closed = true;
            state.active.take();
        }
        self.changed.notify_waiters();
        Ok(())
    }

    fn abort_unfinished(&self) {
        {
            let mut state = self.lock_state();
            if !state.finished() {
                state.fail_stream(EngineError::Cancelled);
            }
        }
        self.changed.notify_waiters();
    }

    async fn write(&self, status: StatusCode, bytes: &[u8]) -> Result<usize, EngineError> {
        let wanted = bytes
            .len()
            .min(MAX_FRAME_BYTES)
            .min(self.owner.config.direction_buffer_bytes);
        {
            let mut state = self.lock_state();
            if !state.can_write(status) || bytes.is_empty() {
                return Err(EngineError::ProtocolViolation);
            }
            if let Err(error) = state.check_cancellation(&self.owner) {
                drop(state);
                self.changed.notify_waiters();
                return Err(error);
            }
            state
                .send
                .as_mut()
                .ok_or(EngineError::ProtocolViolation)?
                .reserve_capacity(wanted);
        }
        let _capacity = CapacityReservation { shared: self };
        let capacity = self
            .wait_for_io(|cx| self.lock_state().poll_capacity(cx, &self.owner))
            .await;
        let capacity = match capacity {
            Ok(capacity) => capacity,
            Err(error) => {
                let error = self.resolve_write_error(error).await;
                self.changed.notify_waiters();
                return Err(error);
            }
        };
        let n = wanted.min(capacity);
        let retained = budgeted_bytes(&bytes[..n], &self.owner.config)?;
        let result = {
            let mut state = self.lock_state();
            if let Some(error) = state.terminal_error() {
                Err(error)
            } else {
                state.send_data(retained, false).map(|()| n)
            }
        };
        let result = match result {
            Err(error) => Err(self.resolve_write_error(error).await),
            result => result,
        };
        if result.is_err() {
            self.changed.notify_waiters();
        }
        result
    }

    async fn end_write(&self, status: StatusCode) -> Result<(), EngineError> {
        if !self.lock_state().can_write(status) {
            return Err(EngineError::ProtocolViolation);
        }
        if let Err(error) = self.write_ready().await {
            self.lock_state().release_finished();
            return Err(error);
        }
        let result = {
            let mut state = self.lock_state();
            if !state.can_write(status) {
                return Err(EngineError::ProtocolViolation);
            }
            state.check_cancellation(&self.owner).and_then(|()| {
                state.send_data(Bytes::new(), true)?;
                state.write_closed = true;
                state.release_finished();
                Ok(())
            })
        };
        let result = match result {
            Err(error) => Err(self.resolve_write_error(error).await),
            result => result,
        };
        self.changed.notify_waiters();
        result
    }

    async fn resolve_write_error(&self, error: EngineError) -> EngineError {
        let error = if error == EngineError::TransportUnavailable {
            self.write_ready().await.err().unwrap_or(error)
        } else {
            error
        };
        let mut state = self.lock_state();
        let error = state.fail_write(error);
        state.release_finished();
        error
    }

    async fn wait_for_io<T>(&self, mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Register before polling so changes during a pending poll are observed.
            changed.as_mut().enable();
            tokio::select! {
                result = poll_fn(|cx| {
                    let result = poll(cx);
                    if result.is_ready() {
                        self.changed.notify_waiters();
                    }
                    result
                }) => return result,
                _ = &mut changed => {}
            }
        }
    }

    async fn write_ready(&self) -> Result<(), EngineError> {
        let _capacity = CapacityReservation { shared: self };
        self.wait_for_io(|cx| {
            let mut state = self.lock_state();
            state.write_waiter = Some(cx.waker().clone());
            let result = state.poll_write_ready(cx, &self.owner);
            drop(state);
            result
        })
        .await
    }

    async fn read(&self, out: &mut [u8]) -> Result<ReadOutcome, EngineError> {
        self.wait_for_io(|cx| self.lock_state().poll_read(cx, out, &self.owner))
            .await
    }
}

impl Drop for H2StreamShared {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        if !state.finished()
            && let Some(send) = state.send.as_mut()
        {
            send.send_reset(h2::Reason::CANCEL);
        }
    }
}

impl H2StreamState {
    fn terminal_error(&self) -> Option<EngineError> {
        match self.read_state {
            ReadState::Reset => Some(EngineError::RemoteReset),
            ReadState::Cancelled => Some(EngineError::Cancelled),
            ReadState::Failed => Some(EngineError::TransportUnavailable),
            ReadState::Open | ReadState::Eof => None,
        }
    }

    fn can_write(&self, status: StatusCode) -> bool {
        status == StatusCode::OK && !self.write_closed && self.terminal_error().is_none()
    }

    fn discard_read_buffers(&mut self) {
        self.pending_read = Bytes::new();
        self.terminal_read_queue.clear();
        self.deferred_read_error = None;
    }

    fn check_cancellation(&mut self, owner: &SessionOwner) -> Result<(), EngineError> {
        if matches!(self.read_state, ReadState::Reset | ReadState::Cancelled) {
            return Ok(());
        }
        if owner.cancelled.load(Ordering::Acquire) {
            self.discard_read_buffers();
            self.send.take();
            self.recv.take();
            self.read_state = ReadState::Cancelled;
            self.active.take();
            return Err(EngineError::Cancelled);
        }
        Ok(())
    }

    fn poll_write_ready(
        &mut self,
        cx: &mut Context<'_>,
        owner: &SessionOwner,
    ) -> Poll<Result<(), EngineError>> {
        self.check_cancellation(owner)?;
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        if let Some(error) = self.deferred_read_error {
            return Poll::Ready(Err(self.fail_write(error)));
        }
        let send = self.send.as_mut().ok_or(EngineError::ProtocolViolation)?;
        match send.poll_reset(cx) {
            Poll::Ready(Ok(_)) if self.recv.is_some() => {
                match self.poll_terminal_read(cx, &owner.config) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(self.fail_stream(error)));
                    }
                    Poll::Ready(Ok(())) => {}
                }
                let error = self
                    .terminal_error()
                    .or(self.deferred_read_error)
                    .unwrap_or(EngineError::ProtocolViolation);
                return Poll::Ready(Err(self.fail_write(error)));
            }
            Poll::Ready(Ok(_)) => {
                // Without RecvStream, h2 0.4.18 exposes only a reset-or-GOAWAY reason.
                let error = owner
                    .driver_result()
                    .map(|result| result.err().unwrap_or(EngineError::TransportUnavailable))
                    .unwrap_or(EngineError::RemoteReset);
                return Poll::Ready(Err(self.fail_write(error)));
            }
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(self.fail_write(map_h2(error))));
            }
            Poll::Pending => {}
        }
        if let Some(Err(error)) = owner.driver_result() {
            return Poll::Ready(Err(self.fail_write(error)));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
        owner: &SessionOwner,
    ) -> Poll<Result<usize, EngineError>> {
        self.write_waiter = Some(cx.waker().clone());
        match self.poll_write_ready(cx, owner) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let send = self.send.as_mut().ok_or(EngineError::ProtocolViolation)?;
        match poll_send_capacity(send, cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail_write(error))),
            result => result,
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut [u8],
        owner: &SessionOwner,
    ) -> Poll<Result<ReadOutcome, EngineError>> {
        loop {
            self.check_cancellation(owner)?;
            if self.deferred_read_error.is_none()
                && let Some(send) = self.send.as_mut()
            {
                // h2 reset and capacity polls share one send waker. Preserve a waiting writer.
                let reset_waker = self.write_waiter.as_ref().unwrap_or(cx.waker());
                let mut reset_context = Context::from_waker(reset_waker);
                if matches!(send.poll_reset(&mut reset_context), Poll::Ready(Ok(_))) {
                    // poll_reset loses the error kind. Recv errors follow queued DATA.
                    match self.poll_terminal_read(cx, &owner.config) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(self.fail_stream(error)));
                        }
                    }
                }
            }
            match self.read_state {
                ReadState::Reset => return Poll::Ready(Ok(ReadOutcome::Reset)),
                ReadState::Cancelled => return Poll::Ready(Ok(ReadOutcome::Cancelled)),
                ReadState::Failed => return Poll::Ready(Err(EngineError::TransportUnavailable)),
                ReadState::Eof if self.pending_read.is_empty() => {
                    self.release_finished();
                    return Poll::Ready(Ok(ReadOutcome::Eof));
                }
                ReadState::Open | ReadState::Eof => {}
            }
            if out.is_empty() {
                return Poll::Ready(Err(EngineError::ProtocolViolation));
            }
            if !self.pending_read.is_empty() {
                return Poll::Ready(self.copy_pending(out).map(ReadOutcome::Data));
            }
            if let Some(chunk) = self.terminal_read_queue.pop() {
                self.pending_read = chunk;
                return Poll::Ready(self.copy_pending(out).map(ReadOutcome::Data));
            }
            if let Some(error) = self.deferred_read_error.take() {
                return Poll::Ready(Err(self.fail_stream(error)));
            }
            let recv = self.recv.as_mut().ok_or(EngineError::ProtocolViolation)?;
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    let ended = recv.is_end_stream();
                    if chunk.is_empty() {
                        if ended {
                            self.read_state = ReadState::Eof;
                            self.release_finished();
                            return Poll::Ready(Ok(ReadOutcome::Eof));
                        }
                        continue;
                    }
                    if chunk.len() > owner.config.direction_buffer_bytes {
                        return Poll::Ready(Err(
                            self.fail_stream(EngineError::ResourceLimitExceeded)
                        ));
                    }
                    self.pending_read = match budgeted_bytes(&chunk, &owner.config) {
                        Ok(retained) => retained,
                        Err(error) => return Poll::Ready(Err(self.fail_stream(error))),
                    };
                    return Poll::Ready(self.copy_pending(out).map(ReadOutcome::Data));
                }
                Poll::Ready(Some(Err(error))) => {
                    if error.is_reset() {
                        self.fail_stream(EngineError::RemoteReset);
                        return Poll::Ready(Ok(ReadOutcome::Reset));
                    }
                    return Poll::Ready(Err(self.fail_stream(map_h2(error))));
                }
                Poll::Ready(None) => {
                    match recv.poll_trailers(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(trailers))) => {
                            if let Err(error) = check_header_limits(&trailers, &[], &owner.config) {
                                return Poll::Ready(Err(self.fail_stream(error)));
                            }
                        }
                        Poll::Ready(Ok(None)) => {}
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(self.fail_stream(map_h2(error))));
                        }
                    }
                    self.read_state = ReadState::Eof;
                    self.release_finished();
                    return Poll::Ready(Ok(ReadOutcome::Eof));
                }
            }
        }
    }

    fn poll_terminal_read(
        &mut self,
        cx: &mut Context<'_>,
        config: &H2Config,
    ) -> Poll<Result<(), EngineError>> {
        for _ in 0..TERMINAL_PROBE_EVENTS_PER_POLL {
            let recv = self.recv.as_mut().ok_or(EngineError::ProtocolViolation)?;
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    self.terminal_probe_events = self
                        .terminal_probe_events
                        .checked_add(1)
                        .filter(|events| *events <= config.direction_buffer_bytes)
                        .ok_or(EngineError::ResourceLimitExceeded)?;
                    if !chunk.is_empty() {
                        self.terminal_read_queue
                            .push(&chunk, self.pending_read.len(), config)?;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.record_terminal_read_error(error);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    match recv.poll_trailers(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(trailers))) => {
                            check_header_limits(&trailers, &[], config)?;
                            continue;
                        }
                        Poll::Ready(Ok(None)) => {}
                        Poll::Ready(Err(error)) => {
                            self.record_terminal_read_error(error);
                            return Poll::Ready(Ok(()));
                        }
                    }
                    // With a ready send reason, h2 0.4.18 preserves receive EOF only for reset.
                    // Recheck this distinction when updating h2.
                    self.fail_stream(EngineError::RemoteReset);
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn record_terminal_read_error(&mut self, error: h2::Error) {
        let error = map_h2(error);
        if error == EngineError::RemoteReset {
            self.fail_stream(error);
        } else {
            self.deferred_read_error = Some(error);
        }
    }

    fn copy_pending(&mut self, out: &mut [u8]) -> Result<usize, EngineError> {
        let n = out.len().min(self.pending_read.len());
        out[..n].copy_from_slice(&self.pending_read[..n]);
        // Return credit only for copied bytes.
        self.recv
            .as_mut()
            .ok_or(EngineError::ProtocolViolation)?
            .flow_control()
            .release_capacity(n)
            .map_err(map_h2)?;
        consume_retained_bytes(&mut self.pending_read, n);
        Ok(n)
    }

    fn send_data(&mut self, bytes: Bytes, end_stream: bool) -> Result<(), EngineError> {
        let send = self.send.as_mut().ok_or(EngineError::ProtocolViolation)?;
        if let Err(error) = send.send_data(bytes, end_stream) {
            return Err(map_h2(error));
        }
        Ok(())
    }

    fn finished(&self) -> bool {
        self.write_closed
            && (matches!(self.read_state, ReadState::Eof) || self.read_abandoned)
            && self.pending_read.is_empty()
            && self.terminal_read_queue.chunks.is_empty()
    }

    fn release_finished(&mut self) {
        if self.finished() {
            self.active.take();
            self.send.take();
            self.recv.take();
        }
    }

    fn fail_write(&mut self, error: EngineError) -> EngineError {
        if error == EngineError::TransportUnavailable {
            // Keep the receive data and send handle until the reader resolves its outcome.
            self.write_closed = true;
            error
        } else {
            self.fail_stream(error)
        }
    }

    fn fail_stream(&mut self, error: EngineError) -> EngineError {
        self.discard_read_buffers();
        self.write_closed = true;
        self.read_state = match error {
            EngineError::RemoteReset => ReadState::Reset,
            EngineError::Cancelled => ReadState::Cancelled,
            _ => ReadState::Failed,
        };
        if let Some(mut send) = self.send.take() {
            send.send_reset(h2::Reason::CANCEL);
        }
        self.recv.take();
        self.active.take();
        error
    }
}

pub(crate) fn poll_send_capacity(
    send: &mut h2::SendStream<Bytes>,
    cx: &mut Context<'_>,
) -> Poll<Result<usize, EngineError>> {
    if send.capacity() != 0 {
        return Poll::Ready(Ok(send.capacity()));
    }
    match send.poll_capacity(cx) {
        Poll::Ready(Some(Ok(n))) => Poll::Ready(Ok(n)),
        Poll::Ready(Some(Err(error))) => Poll::Ready(Err(map_h2(error))),
        Poll::Ready(None) => Poll::Ready(Err(EngineError::TransportUnavailable)),
        Poll::Pending => Poll::Pending,
    }
}

fn consume_retained_bytes(bytes: &mut Bytes, n: usize) {
    // A remaining slice retains the full memory charge.
    if n == bytes.len() {
        *bytes = Bytes::new();
    } else {
        *bytes = bytes.slice(n..);
    }
}

/// Sends a payload, half-closes the request, and collects at most 16 KiB of reply.
/// Non-OK responses return an empty reply without sending the payload.
pub async fn client_roundtrip<I>(
    io: I,
    destination: &Destination,
    credential: &Credential,
    peer_verified: bool,
    payload: &[u8],
) -> Result<ClientRoundtrip, EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    client_roundtrip_with_limit(
        io,
        destination,
        credential,
        peer_verified,
        payload,
        DEFAULT_REPLY_LIMIT_BYTES,
    )
    .await
}

/// Runs the round trip with a caller-supplied reply limit, in bytes.
///
/// A larger reply returns `ResourceLimitExceeded`. Collection memory is reserved
/// before transfer and remains charged while the returned `Bytes` owner is retained.
/// Non-OK responses return an empty reply without sending the payload.
pub async fn client_roundtrip_with_limit<I>(
    io: I,
    destination: &Destination,
    credential: &Credential,
    peer_verified: bool,
    payload: &[u8],
    max_reply_bytes: usize,
) -> Result<ClientRoundtrip, EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let opened = open_h2(io, destination, credential, peer_verified).await?;
    if opened.status != StatusCode::OK {
        return Ok(ClientRoundtrip {
            status: opened.status,
            reply: Bytes::new(),
        });
    }
    let config = opened.shared.owner.config.clone();
    let status = opened.status;
    let collector_charge = retained_bytes_charge::<RetainedBytes>(max_reply_bytes)?;
    let mut collector = config.reserve_memory(collector_charge)?;
    let mut reply = Vec::new();
    reply
        .try_reserve_exact(max_reply_bytes)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    if retained_bytes_charge::<RetainedBytes>(reply.capacity())? > collector.bytes() {
        return Err(EngineError::ResourceLimitExceeded);
    }
    let mut read_buffer = allocate_read_buffer(&config)?;
    let (mut reader, mut writer) = opened.into_split();
    let control = writer.control();
    let write = async {
        let mut rest = payload;
        while !rest.is_empty() {
            let n = writer.write(rest).await?;
            rest = &rest[n..];
        }
        writer.end_write().await?;
        Ok::<_, EngineError>(())
    };
    let read = async {
        loop {
            match reader.read(&mut read_buffer.bytes).await? {
                ReadOutcome::Data(n) => {
                    let new_len = reply
                        .len()
                        .checked_add(n)
                        .ok_or(EngineError::ResourceLimitExceeded)?;
                    if new_len > max_reply_bytes {
                        return Err(EngineError::ResourceLimitExceeded);
                    }
                    reply.extend_from_slice(&read_buffer.bytes[..n]);
                }
                ReadOutcome::Eof => return Ok::<_, EngineError>(()),
                ReadOutcome::Reset => return Err(EngineError::RemoteReset),
                ReadOutcome::Cancelled => return Err(EngineError::Cancelled),
                ReadOutcome::Truncated => return Err(EngineError::TruncatedStream),
                ReadOutcome::Waiting => return Err(EngineError::TransportUnavailable),
            }
        }
    };
    if let Err(error) = tokio::try_join!(write, read) {
        let _ = control.cancel();
        return Err(error);
    }
    let reply = reply.into_boxed_slice();
    collector.shrink_to(retained_bytes_charge::<RetainedBytes>(reply.len())?)?;
    let reply = Bytes::from_owner(RetainedBytes {
        bytes: reply,
        _reservation: collector,
    });
    Ok(ClientRoundtrip { status, reply })
}

struct RetainedBytes {
    bytes: Box<[u8]>,
    _reservation: ScopedMemoryReservation,
}

impl AsRef<[u8]> for RetainedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn budgeted_bytes(bytes: &[u8], config: &H2Config) -> Result<Bytes, EngineError> {
    let charge = retained_bytes_charge::<RetainedBytes>(bytes.len())?;
    let reservation = config.reserve_memory(charge)?;
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    if retained_bytes_charge::<RetainedBytes>(retained.capacity())? > reservation.bytes() {
        return Err(EngineError::ResourceLimitExceeded);
    }
    retained.extend_from_slice(bytes);
    // h2 can retain DATA slices after send_data returns. Nonempty slices keep this charge.
    let retained = retained.into_boxed_slice();
    Ok(Bytes::from_owner(RetainedBytes {
        bytes: retained,
        _reservation: reservation,
    }))
}

fn allocate_read_buffer(config: &H2Config) -> Result<RetainedBytes, EngineError> {
    let len = config.direction_buffer_bytes.min(4096);
    let reservation = config.reserve_memory(len)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    if bytes.capacity() > reservation.bytes() {
        return Err(EngineError::ResourceLimitExceeded);
    }
    bytes.resize(len, 0);
    Ok(RetainedBytes {
        bytes: bytes.into_boxed_slice(),
        _reservation: reservation,
    })
}

pub(crate) fn check_header_limits(
    headers: &HeaderMap,
    pseudo_headers: &[(&str, &str)],
    config: &H2Config,
) -> Result<(), EngineError> {
    check_header_limits_with_bounds(
        headers,
        pseudo_headers,
        config.max_header_count,
        config.max_header_bytes,
    )
}

pub(crate) fn check_header_limits_with_bounds(
    headers: &HeaderMap,
    pseudo_headers: &[(&str, &str)],
    max_header_count: usize,
    max_header_bytes: usize,
) -> Result<(), EngineError> {
    let (count, bytes) = pseudo_headers
        .iter()
        .map(|&(name, value)| (name, value.as_bytes()))
        .chain(
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
        )
        .try_fold((0usize, 0usize), |(count, bytes), (name, value)| {
            let count = count
                .checked_add(1)
                .ok_or(EngineError::ResourceLimitExceeded)?;
            let bytes = bytes
                .checked_add(HEADER_FIELD_OVERHEAD_BYTES)
                .and_then(|sum| sum.checked_add(name.len()))
                .and_then(|sum| sum.checked_add(value.len()))
                .ok_or(EngineError::ResourceLimitExceeded)?;
            Ok::<_, EngineError>((count, bytes))
        })?;
    if count > max_header_count || bytes > max_header_bytes {
        return Err(EngineError::ResourceLimitExceeded);
    }
    Ok(())
}

fn check_request_headers<B>(request: &Request<B>, config: &H2Config) -> Result<(), EngineError> {
    let mut pseudo_headers = vec![(":method", request.method().as_str())];
    if let Some(scheme) = request.uri().scheme_str() {
        pseudo_headers.push((":scheme", scheme));
    }
    if let Some(authority) = request.uri().authority() {
        pseudo_headers.push((":authority", authority.as_str()));
    }
    if let Some(path) = request.uri().path_and_query() {
        pseudo_headers.push((":path", path.as_str()));
    }
    if let Some(protocol) = request.extensions().get::<h2::ext::Protocol>() {
        pseudo_headers.push((":protocol", protocol.as_str()));
    }
    check_header_limits(request.headers(), &pseudo_headers, config)
}

fn check_response_headers<B>(response: &Response<B>, config: &H2Config) -> Result<(), EngineError> {
    check_header_limits(
        response.headers(),
        &[(":status", response.status().as_str())],
        config,
    )
}

fn retained_header_charge(headers: &HeaderMap) -> Result<usize, EngineError> {
    // Include hash buckets, duplicate-value nodes, and owned header byte storage.
    let field_bytes = headers.iter().try_fold(0usize, |bytes, (name, value)| {
        bytes
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
            .ok_or(EngineError::ResourceLimitExceeded)
    })?;
    field_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(headers.capacity().checked_mul(128)?))
        .and_then(|bytes| bytes.checked_add(headers.len().checked_mul(128)?))
        .ok_or(EngineError::ResourceLimitExceeded)
}

/// Serves concurrent CONNECT flows with per-stream authorization and target dialing.
/// The shutdown future uses the drain rules of [`serve_h2_with_handler`].
pub async fn serve_h2<I, A, F, Fut, T, S>(
    io: I,
    authorizer: Arc<A>,
    allow_private: bool,
    config: H2Config,
    dial: F,
    shutdown: S,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: Authorizer + Send + Sync + 'static,
    F: Fn(Destination) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<T, EngineError>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Future<Output = ()> + Send,
{
    let dial = Arc::new(dial);
    serve_h2_with_handler(
        io,
        config,
        move |request, respond, config| {
            let authorizer = Arc::clone(&authorizer);
            let dial = Arc::clone(&dial);
            async move {
                handle_h2_connect(
                    request,
                    respond,
                    authorizer,
                    allow_private,
                    config,
                    move |destination| dial(destination),
                )
                .await
            }
        },
        shutdown,
    )
    .await
}

/// Drives a server connection and runs each admitted request in its own task.
///
/// The shutdown future starts a graceful drain capped by `drain_timeout`.
/// Clean connection EOF gives handlers the same limit to drain received data.
/// Connection failure or expiry requests handler abort. The connection is dropped
/// before final task cleanup. It continues running after individual handlers finish.
/// Dropping this future aborts its handlers without awaiting their cleanup.
/// Before authentication, a fixed `open_timeout` applies after the handshake.
/// Custom handlers lift this limit only by successfully calling [`check_h2_credential`].
pub async fn serve_h2_with_handler<I, H, Fut, S>(
    io: I,
    config: H2Config,
    handler: H,
    shutdown: S,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Fn(Request<RecvStream>, SendResponse<Bytes>, H2Config) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), EngineError>> + Send + 'static,
    S: Future<Output = ()> + Send,
{
    config.validate()?;
    let _control = config.reserve_memory(config.control_reserve_bytes)?;
    let mut connection = server_handshake(io, &config).await?;
    let handler = Arc::new(handler);
    let mut tasks = JoinSet::new();
    let mut first_error = None;
    let mut draining = false;
    let authenticated = Arc::new(AtomicBool::new(false));
    let authorization_deadline = Deadline::after(config.open_timeout)?.expires_at();
    let pre_auth = tokio::time::sleep_until(authorization_deadline);
    let drain = tokio::time::sleep(config.drain_timeout);
    tokio::pin!(pre_auth, drain, shutdown);
    let connection_result = loop {
        tokio::select! {
            _ = &mut shutdown, if !draining => {
                draining = true;
                connection.graceful_shutdown();
                drain.as_mut().reset(tokio::time::Instant::now() + config.drain_timeout);
            }
            _ = &mut pre_auth, if !authenticated.load(Ordering::Acquire) && !draining => {
                // Authentication can finish while this select is waiting.
                if !authenticated.load(Ordering::Acquire) {
                    break Err(EngineError::DeadlineExceeded);
                }
            }
            _ = &mut drain, if draining => {
                break Err(EngineError::DeadlineExceeded);
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                match completed {
                    Some(Ok(Err(error))) => { first_error.get_or_insert(error); }
                    Some(Err(_)) => { first_error.get_or_insert(EngineError::TransportUnavailable); }
                    Some(Ok(Ok(()))) | None => {}
                }
            }
            incoming = connection.accept() => {
                let (mut request, mut respond) = match incoming {
                    Some(Ok(pair)) => pair,
                    Some(Err(error)) => break Err(map_h2(error)),
                    None => {
                        while let Some(result) = tasks.try_join_next() {
                            record_drained_handler_result(&mut first_error, result);
                        }
                        // Completed wire streams can still hold data for their targets.
                        break Ok(());
                    }
                };
                if draining {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                if check_request_headers(&request, &config).is_err() {
                    // h2 bounds decoded bytes. Its public API does not bound field count.
                    respond.send_reset(h2::Reason::ENHANCE_YOUR_CALM);
                    continue;
                }
                if tasks.len() >= config.max_concurrent_streams {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                let flow = match config.reserve_flow() {
                    Ok(flow) => flow,
                    Err(_) => { respond.send_reset(h2::Reason::REFUSED_STREAM); continue; }
                };
                request.extensions_mut().insert(AuthenticationMarker {
                    authenticated: Arc::clone(&authenticated),
                    expires_at: authorization_deadline,
                });
                let handler = Arc::clone(&handler);
                let stream_config = config.clone();
                tasks.spawn(async move {
                    let _flow = flow;
                    handler(request, respond, stream_config).await
                });
            }
        }
    };
    let mut connection_result = connection_result;
    if connection_result.is_err() {
        connection.abrupt_shutdown(h2::Reason::CANCEL);
        tasks.abort_all();
    }
    drop(connection);
    let remaining = if draining {
        drain.deadline()
    } else {
        Deadline::after(config.drain_timeout)?.expires_at()
    };
    while !tasks.is_empty() {
        let result = match timeout_at(remaining, tasks.join_next()).await {
            Ok(result) => result,
            Err(_) => {
                connection_result = Err(EngineError::DeadlineExceeded);
                tasks.abort_all();
                break;
            }
        };
        if let Some(result) = result {
            record_drained_handler_result(&mut first_error, result);
        }
    }
    while tasks.join_next().await.is_some() {}
    connection_result.and(first_error.map_or(Ok(()), Err))
}

fn record_drained_handler_result(
    first_error: &mut Option<EngineError>,
    result: Result<Result<(), EngineError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Err(error)) => {
            first_error.get_or_insert(error);
        }
        Err(error) if !error.is_cancelled() => {
            first_error.get_or_insert(EngineError::TransportUnavailable);
        }
        Ok(Ok(())) | Err(_) => {}
    }
}

fn server_builder(config: &H2Config) -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(config.direction_buffer_bytes as u32)
        .initial_connection_window_size(config.initial_connection_window)
        .max_frame_size(MAX_FRAME_BYTES as u32)
        .max_header_list_size(config.max_header_bytes as u32)
        .header_table_size(config.header_table_bytes)
        .max_concurrent_streams(config.max_concurrent_streams as u32)
        .max_send_buffer_size(config.direction_buffer_bytes)
        .max_concurrent_reset_streams(config.max_concurrent_streams)
        .max_pending_accept_reset_streams(config.max_concurrent_streams)
        .max_local_error_reset_streams(Some(config.max_concurrent_streams))
        .data_frame_budget(DATA_FRAME_BUDGET)
        .enable_connect_protocol();
    builder
}

async fn server_handshake<I>(
    io: I,
    config: &H2Config,
) -> Result<h2::server::Connection<I, Bytes>, EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    Deadline::after(config.handshake_timeout)?
        .run(async {
            server_builder(config)
                .handshake::<_, Bytes>(io)
                .await
                .map_err(map_h2)
        })
        .await
}

/// Accepts one initial request, then requests graceful connection shutdown.
///
/// Uses default handshake and open timeouts. After the handler completes, driver
/// completion has no separate drain timeout. Dropping this future requests abort
/// of its background tasks without awaiting their cleanup.
/// A handler panic aborts the connection driver and waits for its cleanup.
pub async fn serve_one<I, F, Fut, T>(
    io: I,
    authorizer: StaticAuthorizer,
    allow_private: bool,
    dial: F,
) -> Result<(), EngineError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(Destination) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, EngineError>> + Send,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = H2Config::default();
    let _control = config.reserve_memory(config.control_reserve_bytes)?;
    let mut connection = server_handshake(io, &config).await?;
    let (request, respond) = Deadline::after(config.open_timeout)?
        .run(async {
            match connection.accept().await {
                Some(Ok(pair)) => Ok(pair),
                Some(Err(_)) | None => Err(EngineError::TransportUnavailable),
            }
        })
        .await?;
    connection.graceful_shutdown();

    let handler = tokio::spawn(async move {
        handle_tcp(
            request,
            respond,
            Arc::new(authorizer),
            allow_private,
            false,
            config,
            move |_, destination, _| dial(destination),
        )
        .await
    });
    let driver = tokio::spawn(async move {
        loop {
            match connection.accept().await {
                None => return Ok(()),
                Some(Err(error)) => return Err(map_h2(error)),
                Some(Ok((_, extra))) => {
                    let _ = reject(extra, StatusCode::FORBIDDEN).await;
                }
            }
        }
    });
    let _stop = AbortTasksOnDrop {
        tasks: [handler.abort_handle(), driver.abort_handle()],
    };
    let result = match handler.await {
        Ok(result) => result,
        Err(_) => {
            driver.abort();
            Err(EngineError::TransportUnavailable)
        }
    };
    let driver_result = match driver.await {
        Ok(result) => result,
        Err(_) => Err(EngineError::TransportUnavailable),
    };
    result.and(driver_result)
}

struct AbortTasksOnDrop<const N: usize> {
    tasks: [tokio::task::AbortHandle; N],
}

impl<const N: usize> Drop for AbortTasksOnDrop<N> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Routes the request and relays an authorized CONNECT to a dialed target.
///
/// The connection driver must run while this future is pending. IP egress checks
/// precede dialing; domain resolution and its egress checks belong to `dial`.
/// A root GET is served without authorization or dialing.
pub async fn handle_h2_connect<A, F, Fut, T>(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    authorizer: Arc<A>,
    allow_private: bool,
    config: H2Config,
    dial: F,
) -> Result<(), EngineError>
where
    A: Authorizer,
    F: FnOnce(Destination) -> Fut,
    Fut: Future<Output = Result<T, EngineError>>,
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    handle_h2_connect_authorized(
        request,
        respond,
        authorizer,
        allow_private,
        config,
        move |_, destination, _| dial(destination),
    )
    .await
}

/// Applies the routing and target rules of [`handle_h2_connect`].
/// The dial callback receives the authorization decision and a deadline capped
/// by `open_timeout` and the decision's `valid_for`.
/// The callback runs at most once; a peer reset interrupts a pending dial.
pub async fn handle_h2_connect_authorized<A, F, Fut, T>(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    authorizer: Arc<A>,
    allow_private: bool,
    config: H2Config,
    dial: F,
) -> Result<(), EngineError>
where
    A: Authorizer,
    F: FnOnce(AuthzDecision, Destination, Deadline) -> Fut,
    Fut: Future<Output = Result<T, EngineError>>,
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    handle_tcp(
        request,
        respond,
        authorizer,
        allow_private,
        true,
        config,
        dial,
    )
    .await
}

async fn handle_tcp<A, F, Fut, T>(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    authorizer: Arc<A>,
    allow_private: bool,
    allow_domains: bool,
    config: H2Config,
    dial: F,
) -> Result<(), EngineError>
where
    A: Authorizer,
    F: FnOnce(AuthzDecision, Destination, Deadline) -> Fut,
    Fut: Future<Output = Result<T, EngineError>>,
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    if let Err(error) = check_request_headers(&request, &config) {
        return reject(respond, status_for(error)).await;
    }
    match request_route(request.method().as_str(), request.uri().path()) {
        Route::Site => return site_page(respond).await,
        Route::Reject => return reject(respond, StatusCode::NOT_FOUND).await,
        Route::Connect => {}
    }
    if request.extensions().get::<h2::ext::Protocol>().is_some() {
        return reject(respond, StatusCode::NOT_FOUND).await;
    }
    if let Err(error) = validate_h2_versions(request.headers()) {
        return reject(respond, status_for(error)).await;
    }
    let destination = match Destination::parse(&request.uri().to_string()) {
        Ok(destination) => destination,
        Err(error) => return reject(respond, status_for(error)).await,
    };
    let decision = match check_h2_credential(&request, authorizer.as_ref()) {
        Ok(decision) => decision,
        Err(error) => return reject(respond, status_for(error)).await,
    };
    let destination = match if allow_domains && destination.as_ip().is_none() {
        Ok(destination)
    } else {
        check_ip_target(allow_private, destination)
    } {
        Ok(destination) => destination,
        Err(error) => return reject(respond, status_for(error)).await,
    };
    let opening = match config.reserve_open() {
        Ok(opening) => opening,
        Err(error) => return reject(respond, status_for(error)).await,
    };
    let read_buffer = match allocate_read_buffer(&config) {
        Ok(buffer) => buffer,
        Err(error) => return reject(respond, status_for(error)).await,
    };
    let deadline = Deadline::after(config.open_timeout)?.cap(decision.valid_for)?;
    let dialed = tokio::select! {
        dialed = deadline.run(dial(decision, destination, deadline)) => dialed,
        reset = poll_fn(|cx| respond.poll_reset(cx)) => {
            return Err(reset.map_or_else(map_h2, |_| EngineError::RemoteReset));
        }
    };
    drop(opening);
    let dialed = match dialed {
        Ok(dialed) => dialed,
        Err(error) => return reject(respond, status_for(error)).await,
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    attach_h2_versions(response.headers_mut())?;
    let send = respond
        .send_response(response, false)
        .map_err(|_| EngineError::TransportUnavailable)?;
    relay_tcp(request.into_body(), send, dialed, &config, read_buffer).await
}

fn check_ip_target(
    allow_private: bool,
    destination: Destination,
) -> Result<Destination, EngineError> {
    validate_ip_target(allow_private, &destination)?;
    Ok(destination)
}

async fn relay_tcp<T>(
    mut request_body: RecvStream,
    mut response_body: h2::SendStream<Bytes>,
    target: T,
    config: &H2Config,
    mut read_buffer: RetainedBytes,
) -> Result<(), EngineError>
where
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let mut toward_target = Bytes::new();
    let mut client_read_open = true;
    let mut target_write_open = true;
    let mut target_read_open = true;
    let mut toward_client = Bytes::new();
    let result = async {
        while client_read_open || target_write_open || target_read_open || !toward_client.is_empty() {
            tokio::select! {
                capacity = poll_fn(|cx| {
                    // Reset polling stays active while either direction is idle or blocked.
                    if let Poll::Ready(reset) = response_body.poll_reset(cx) {
                        return Poll::Ready(Err(reset.map_or_else(map_h2, |_| EngineError::RemoteReset)));
                    }
                    if toward_client.is_empty() {
                        return Poll::Pending;
                    }
                    poll_send_capacity(&mut response_body, cx)
                }) => {
                    let capacity = capacity?;
                    let n = capacity.min(toward_client.len());
                    let sent = toward_client.split_to(n);
                    response_body.send_data(sent, false).map_err(map_h2)?;
                    response_body.reserve_capacity(toward_client.len());
                }
                chunk = request_body.data(), if client_read_open && toward_target.is_empty() => {
                    match chunk {
                        Some(Ok(chunk)) => {
                            if chunk.len() > config.direction_buffer_bytes {
                                return Err(EngineError::ResourceLimitExceeded);
                            }
                            toward_target = budgeted_bytes(&chunk, config)?;
                        }
                        Some(Err(error)) => return Err(map_h2(error)),
                        None => {
                            if let Some(trailers) = request_body.trailers().await.map_err(map_h2)? {
                                check_header_limits(&trailers, &[], config)?;
                            }
                            client_read_open = false;
                        }
                    }
                }
                written = async {
                    if toward_target.is_empty() {
                        // The select guard requires request EOF before this half-close.
                        target_write.shutdown().await.map(|()| 0)
                    } else {
                        target_write.write(&toward_target).await
                    }
                }, if target_write_open && (!client_read_open || !toward_target.is_empty()) => {
                    let n = written.map_err(|_| EngineError::TargetConnectFailed)?;
                    if toward_target.is_empty() {
                        target_write_open = false;
                    } else {
                        if n == 0 {
                            return Err(EngineError::TargetConnectFailed);
                        }
                        // Credit follows target acceptance so target backpressure bounds requests.
                        request_body
                            .flow_control()
                            .release_capacity(n)
                            .map_err(|_| EngineError::TransportUnavailable)?;
                        consume_retained_bytes(&mut toward_target, n);
                    }
                }
                read = target_read.read(&mut read_buffer.bytes), if target_read_open && toward_client.is_empty() => {
                    let n = read.map_err(|_| EngineError::TargetConnectFailed)?;
                    if n == 0 {
                        target_read_open = false;
                        response_body.send_data(Bytes::new(), true).map_err(map_h2)?;
                    } else {
                        toward_client = budgeted_bytes(&read_buffer.bytes[..n], config)?;
                        response_body.reserve_capacity(n);
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        response_body.send_reset(h2::Reason::CANCEL);
        abort_tcp(target_read.unsplit(target_write));
    }
    result
}

const SITE_BODY: &[u8] = b"Service available.\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Connect,
    Site,
    Reject,
}

pub fn request_route(method: &str, path: &str) -> Route {
    match method {
        "CONNECT" => Route::Connect,
        "GET" if path == "/" => Route::Site,
        _ => Route::Reject,
    }
}

async fn site_page(mut respond: SendResponse<Bytes>) -> Result<(), EngineError> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    let mut send = respond
        .send_response(response, false)
        .map_err(|_| EngineError::TransportUnavailable)?;
    send.send_data(Bytes::from_static(SITE_BODY), true)
        .map_err(|_| EngineError::TransportUnavailable)?;
    Ok(())
}

#[derive(Clone)]
struct AuthenticationMarker {
    authenticated: Arc<AtomicBool>,
    expires_at: tokio::time::Instant,
}

/// Authorizes one credential encoded as 64 lowercase hexadecimal characters.
/// The decision must have a nonzero principal and lifetime, with quota class zero.
/// For requests from [`serve_h2_with_handler`], success before its fixed deadline
/// marks the connection authenticated. Ordinary site requests do not mark it.
pub fn check_h2_credential<B, A: Authorizer>(
    request: &Request<B>,
    authorizer: &A,
) -> Result<AuthzDecision, EngineError> {
    let mut values = request
        .headers()
        .get_all(EXPERIMENTAL_CREDENTIAL_HEADER)
        .iter();
    let Some(value) = values.next() else {
        return Err(EngineError::AuthenticationDenied);
    };
    if values.next().is_some() {
        return Err(EngineError::AuthenticationDenied);
    }
    let bytes = value.as_bytes();
    if bytes.len() != Credential::HEX_LEN || bytes.iter().any(u8::is_ascii_uppercase) {
        return Err(EngineError::AuthenticationDenied);
    }
    let mut raw = [0u8; Credential::BYTE_LEN];
    Credential::decode_hex(bytes, &mut raw).map_err(|_| EngineError::AuthenticationDenied)?;
    let credential = Credential::from_bytes(raw);
    raw.fill(0);
    let decision = authorizer.authorize(&credential)?;
    if decision.principal == 0 || decision.valid_for.is_zero() {
        return Err(EngineError::AuthenticationDenied);
    }
    if decision.quota_class != 0 {
        return Err(EngineError::AuthorizationUnavailable);
    }
    if let Some(marker) = request.extensions().get::<AuthenticationMarker>()
        && tokio::time::Instant::now() < marker.expires_at
    {
        marker.authenticated.store(true, Ordering::Release);
    }
    Ok(decision)
}

fn status_for(error: EngineError) -> StatusCode {
    match error {
        EngineError::AuthenticationDenied => StatusCode::FORBIDDEN,
        EngineError::EgressDenied
        | EngineError::TargetResolutionFailed
        | EngineError::TargetConnectFailed => StatusCode::BAD_GATEWAY,
        _ => StatusCode::NOT_FOUND,
    }
}

async fn reject(mut respond: SendResponse<Bytes>, status: StatusCode) -> Result<(), EngineError> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    respond
        .send_response(response, true)
        .map_err(|_| EngineError::TransportUnavailable)?;
    Ok(())
}

fn abort_tcp<T: Any>(stream: T) {
    let any: &dyn Any = &stream;
    if let Some(tcp) = any.downcast_ref::<tokio::net::TcpStream>() {
        let _ = tcp.set_zero_linger();
    }
}

pub(crate) fn map_h2(error: h2::Error) -> EngineError {
    eprintln!("H2 error: {error:?}");
    if error.is_reset() {
        EngineError::RemoteReset
    } else {
        EngineError::TransportUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ariad_core::{Core, CoreConfig, CoreInput, CoreOutput};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn driver_drop_distinguishes_unwinding_from_cancellation() {
        for panics in [false, true] {
            let memory = MemoryBudget::new(8).expect("memory");
            let (finished, state) = watch::channel(DriverState::Running);
            let flows = Arc::new(Mutex::new(FlowRegistry {
                closed: false,
                flows: Vec::new(),
            }));
            let driver = OwnedDriver::<tokio::io::DuplexStream> {
                connection: None,
                finished,
                result: None,
                control: Some(memory.try_acquire_scoped(&memory, 2).expect("control")),
                flows: Arc::clone(&flows),
                _metadata: Arc::new(memory.try_acquire_scoped(&memory, 1).expect("metadata")),
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _driver = driver;
                assert!(!panics, "driver panic");
            }));
            assert_eq!(outcome.is_err(), panics);
            let DriverState::Finished(result) = *state.borrow() else {
                panic!("driver completion must be published");
            };
            assert_eq!(
                result,
                Err(if panics {
                    EngineError::TransportUnavailable
                } else {
                    EngineError::Cancelled
                })
            );
            assert!(flows.lock().expect("registry").closed);
            assert_eq!(memory.used(), 0);
        }
    }

    async fn terminal_reason(shared: &H2StreamShared) -> Result<h2::Reason, h2::Error> {
        poll_fn(|cx| {
            shared
                .lock_state()
                .send
                .as_mut()
                .expect("send")
                .poll_reset(cx)
        })
        .await
    }

    fn receive_credit(shared: &H2StreamShared) -> h2::FlowControl {
        shared
            .lock_state()
            .recv
            .as_mut()
            .expect("receive stream")
            .flow_control()
            .clone()
    }

    #[test]
    fn retained_bytes_charge_follows_empty_owners_and_shared_slices() {
        let process = MemoryBudget::new(4096).expect("process budget");
        let session = MemoryBudget::new(4096).expect("session budget");
        let config = H2Config {
            process_budget: process.clone(),
            session_budget: session.clone(),
            ..H2Config::default()
        };
        let empty = budgeted_bytes(b"", &config).expect("empty owner");
        let empty_charge = retained_bytes_charge::<RetainedBytes>(0).expect("owner charge");
        assert!(empty_charge > 0);
        assert_eq!(process.used(), empty_charge);
        assert_eq!(session.used(), empty_charge);
        let empty_clone = empty.clone();
        drop(empty);
        assert_eq!(process.used(), empty_charge);
        drop(empty_clone);
        assert_eq!(process.used(), 0);
        let bytes = budgeted_bytes(b"12345678", &config).expect("payload");
        let payload_charge = retained_bytes_charge::<RetainedBytes>(8).expect("payload charge");
        let tail = bytes.slice(7..);
        drop(bytes);
        assert_eq!(tail.as_ref(), b"8");
        assert_eq!(process.used(), payload_charge);
        assert_eq!(session.used(), payload_charge);
        drop(tail);
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
        let mut consumed = budgeted_bytes(b"12345678", &config).expect("consumed payload");
        consume_retained_bytes(&mut consumed, 7);
        assert_eq!(consumed.as_ref(), b"8");
        assert_eq!(process.used(), payload_charge);
        assert_eq!(session.used(), payload_charge);
        consume_retained_bytes(&mut consumed, 1);
        assert!(consumed.is_empty());
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[test]
    fn terminal_read_queue_charges_slots_and_owners_until_they_are_released() {
        let process = MemoryBudget::new(4096).expect("process budget");
        let session = MemoryBudget::new(4096).expect("session budget");
        let config = H2Config {
            direction_buffer_bytes: 8,
            process_budget: process.clone(),
            session_budget: session.clone(),
            ..H2Config::default()
        };
        let mut queue = TerminalReadQueue::new();
        queue.push(b"123", 2, &config).expect("first chunk");
        queue.push(b"456", 2, &config).expect("second chunk");
        let owner_charge = retained_bytes_charge::<RetainedBytes>(3).expect("owner charge");
        assert_eq!(
            process.used(),
            2 * owner_charge + queue.chunks.capacity() * std::mem::size_of::<Bytes>()
        );
        assert_eq!(session.used(), process.used());
        let before_denial = process.used();
        assert_eq!(
            queue.push(b"7", 2, &config),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(process.used(), before_denial);
        let first = queue.pop().expect("first retained chunk");
        assert_eq!(first.as_ref(), b"123");
        let second = queue.pop().expect("second retained chunk");
        assert_eq!(second.as_ref(), b"456");
        assert_eq!(queue.bytes, 0);
        assert_eq!(queue.chunks.capacity(), 0);
        assert_eq!(process.used(), 2 * owner_charge);
        drop(first);
        assert_eq!(process.used(), owner_charge);
        drop(second);
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[test]
    fn route_ignores_headers_and_host() {
        assert_eq!(request_route("GET", "/"), Route::Site);
        assert_eq!(request_route("GET", "/metrics"), Route::Reject);
        assert_eq!(request_route("CONNECT", ""), Route::Connect);
        assert_eq!(request_route("CONNECT", "/"), Route::Connect);
        assert_eq!(request_route("POST", "/"), Route::Reject);
    }

    #[test]
    fn tunnel_failure_does_not_dial() {
        let mut core = Core::new(CoreConfig {
            limits: BudgetLimits::lab_small(),
            allow_private_egress: false,
        })
        .expect("core");
        for input in [
            CoreInput::BeginResolve,
            CoreInput::EndpointResolved,
            CoreInput::TransportHandshakeStarted,
            CoreInput::PeerVerified,
            CoreInput::Authorize,
        ] {
            assert!(core.handle(input).is_empty());
        }
        let failed = core.handle(CoreInput::TunnelFailed);
        assert!(
            failed
                .iter()
                .any(|output| matches!(output, CoreOutput::NoDirectConnect))
        );
        let destination = Destination::parse("1.1.1.1:9").expect("dest");
        let opened = core.handle(CoreInput::OpenStream { destination });
        assert!(
            !opened
                .iter()
                .any(|output| matches!(output, CoreOutput::DialTarget { .. }))
        );
    }

    #[test]
    fn ip_target_check_rejects_loopback_and_domain() {
        let loopback = Destination::parse("127.0.0.1:9").expect("loop");
        assert_eq!(
            check_ip_target(true, loopback),
            Err(EngineError::EgressDenied)
        );
        let domain = Destination::parse("example.com:443").expect("domain");
        assert_eq!(
            check_ip_target(false, domain),
            Err(EngineError::TargetResolutionFailed)
        );
        let public = Destination::parse("1.1.1.1:9").expect("public");
        assert_eq!(check_ip_target(false, public.clone()), Ok(public));

        for destination in [
            Destination::Ip {
                addr: "1.1.1.1".parse().expect("address"),
                port: 0,
            },
            Destination::Domain {
                name: "example.com".into(),
                port: 0,
            },
        ] {
            assert_eq!(
                check_ip_target(false, destination),
                Err(EngineError::InvalidConfig)
            );
        }
        let private = Destination::parse("10.1.2.3:9").expect("private");
        assert_eq!(
            check_ip_target(false, private.clone()),
            Err(EngineError::EgressDenied)
        );
        assert_eq!(check_ip_target(true, private.clone()), Ok(private));
        let mapped = Destination::parse("[::ffff:127.0.0.1]:9").expect("mapped loopback");
        assert_eq!(
            check_ip_target(true, mapped),
            Err(EngineError::EgressDenied)
        );
    }

    #[test]
    fn credential_headers_require_lowercase_hex() {
        let credential = Credential::from_bytes([0xab; Credential::BYTE_LEN]);
        let mut request = Request::new(());
        attach_credential(&mut request, &credential).expect("credential");
        let authorizer = StaticAuthorizer::new(credential, 7);
        assert_eq!(
            check_h2_credential(&request, &authorizer)
                .expect("lowercase credential")
                .principal,
            7
        );
        for value in [
            "AB".repeat(Credential::BYTE_LEN),
            "aB".repeat(Credential::BYTE_LEN),
            "ag".repeat(Credential::BYTE_LEN),
            "a".repeat(Credential::HEX_LEN - 1),
            "a".repeat(Credential::HEX_LEN + 1),
        ] {
            let request = Request::builder()
                .header(EXPERIMENTAL_CREDENTIAL_HEADER, value)
                .body(())
                .expect("credential header");
            assert_eq!(
                check_h2_credential(&request, &authorizer),
                Err(EngineError::AuthenticationDenied)
            );
        }
    }

    #[test]
    fn decoded_header_limits_count_pseudo_headers_and_duplicate_fields() {
        let mut headers = HeaderMap::new();
        headers.append("x", http::HeaderValue::from_static("a"));
        headers.append("x", http::HeaderValue::from_static("b"));
        let pseudo_headers = [(":status", "200")];
        assert_eq!(
            check_header_limits_with_bounds(&headers, &pseudo_headers, 3, 110),
            Ok(())
        );
        assert_eq!(
            check_header_limits_with_bounds(&headers, &pseudo_headers, 2, 110),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(
            check_header_limits_with_bounds(&headers, &pseudo_headers, 3, 109),
            Err(EngineError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn only_valid_authorization_before_expiry_marks_the_connection() {
        let credential = Credential::from_bytes([0x11; 32]);
        let authenticated = Arc::new(AtomicBool::new(false));
        let mut request = Request::new(());
        attach_credential(&mut request, &credential).expect("credential");
        request.extensions_mut().insert(AuthenticationMarker {
            authenticated: Arc::clone(&authenticated),
            expires_at: tokio::time::Instant::now() + Duration::from_secs(1),
        });
        let denied = StaticAuthorizer::new(Credential::from_bytes([0x22; 32]), 7);
        assert_eq!(
            check_h2_credential(&request, &denied),
            Err(EngineError::AuthenticationDenied)
        );
        assert!(!authenticated.load(Ordering::Acquire));
        let allowed = StaticAuthorizer::new(credential, 7);
        check_h2_credential(&request, &allowed).expect("authorized");
        assert!(authenticated.load(Ordering::Acquire));
        authenticated.store(false, Ordering::Release);
        request.extensions_mut().insert(AuthenticationMarker {
            authenticated: Arc::clone(&authenticated),
            expires_at: tokio::time::Instant::now(),
        });
        check_h2_credential(&request, &allowed).expect("valid but late");
        assert!(!authenticated.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_ready_open_response_after_expiry_is_reset_and_released() {
        struct ResponseWake(Notify);

        impl std::task::Wake for ResponseWake {
            fn wake(self: Arc<Self>) {
                self.0.notify_one();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.notify_one();
            }
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server_io) = tokio::io::duplex(8 * 1024);
            let (reply_now, waiting_reply) = tokio::sync::oneshot::channel();
            let (reset_seen, waiting_reset) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.expect("handshake");
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .expect("request present")
                    .expect("request");
                waiting_reply.await.expect("reply requested");
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("response");
                attach_h2_versions(response.headers_mut()).expect("response versions");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response");
                tokio::select! {
                    reset = poll_fn(|cx| send.poll_reset(cx)) => {
                        assert_eq!(reset.expect("peer reset"), h2::Reason::CANCEL);
                        reset_seen.send(()).expect("reset observer");
                    }
                    incoming = connection.accept() => panic!("connection ended before reset: {incoming:?}"),
                }
                match connection.accept().await {
                    None => {}
                    Some(Err(error)) => assert!(error.is_io(), "unexpected connection error: {error}"),
                    Some(Ok(_)) => panic!("unexpected request"),
                }
                drop((request, send));
            });
            let _stop = AbortTasksOnDrop {
                tasks: [server.abort_handle()],
            };
            let process_memory = MemoryBudget::new(1024 * 1024).expect("process memory");
            let session_memory = MemoryBudget::new(1024 * 1024).expect("session memory");
            let config = H2Config {
                max_concurrent_streams: 1,
                max_pending_opens: 1,
                process_budget: process_memory.clone(),
                session_budget: session_memory.clone(),
                process_flows: ResourceBudget::new(1).expect("process flows"),
                session_flows: ResourceBudget::new(1).expect("session flows"),
                process_opens: ResourceBudget::new(1).expect("process opens"),
                session_opens: ResourceBudget::new(1).expect("session opens"),
                ..H2Config::default()
            };
            let quotas = [
                config.process_flows.clone(),
                config.session_flows.clone(),
                config.process_opens.clone(),
                config.session_opens.clone(),
            ];
            let session = H2Session::handshake_with_config(client, true, config)
                .await
                .expect("session");
            let session_charge = process_memory.used();
            let destination = Destination::parse("1.1.1.1:9").expect("destination");
            let credential = Credential::from_bytes([0x11; 32]);
            let deadline = Deadline::after(Duration::from_millis(100)).expect("deadline");
            let wake = Arc::new(ResponseWake(Notify::new()));
            let waker = Waker::from(Arc::clone(&wake));
            let mut opening = Box::pin(session.open_stream_with_deadline(
                &destination,
                &credential,
                deadline,
            ));
            assert!(
                opening
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            for quota in &quotas {
                assert_eq!(quota.used(), 1);
            }
            reply_now.send(()).expect("reply requested");
            timeout_at(deadline.expires_at(), wake.0.notified())
                .await
                .expect("response wake before expiration");
            deadline.remaining().expect("response ready before expiration");
            timeout_at(deadline.expires_at(), std::future::pending::<()>())
                .await
                .expect_err("deadline elapsed");
            assert!(matches!(
                opening
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(EngineError::DeadlineExceeded))
            ));
            drop(opening);
            waiting_reset.await.expect("submitted stream reset");
            for quota in &quotas {
                assert_eq!(quota.used(), 0);
            }
            assert_eq!(session.owner.flow_slots.used(), 0);
            assert_eq!(session.owner.pending_opens.used(), 0);
            assert!(!session.has_outstanding_flows());
            assert_eq!(process_memory.used(), session_charge);
            assert_eq!(session_memory.used(), session_charge);
            session.cancel();
            assert_eq!(
                session.close(Duration::from_secs(2)).await,
                Err(EngineError::Cancelled)
            );
            drop(session);
            server.await.expect("server join");
            assert_eq!(process_memory.used(), 0);
            assert_eq!(session_memory.used(), 0);
        })
        .await
        .expect("late open response completion");
    }

    #[tokio::test]
    async fn a_ready_close_after_expiry_is_rejected_in_each_phase() {
        for hold_flow in [true, false] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let (client, server_io) = tokio::io::duplex(8 * 1024);
                let (close_peer, waiting_close) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    let mut connection = h2::server::handshake(server_io).await.expect("handshake");
                    let (request, mut respond) = connection
                        .accept()
                        .await
                        .expect("request present")
                        .expect("request");
                    let mut response = Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("response");
                    attach_h2_versions(response.headers_mut()).expect("response versions");
                    let send = respond
                        .send_response(response, true)
                        .expect("send response");
                    tokio::select! {
                        close = waiting_close => {
                            close.expect("close requested");
                            connection.graceful_shutdown();
                        }
                        incoming = connection.accept() => {
                            match incoming {
                                None => return,
                                Some(Err(error)) => {
                                    assert!(error.is_io(), "unexpected connection error: {error}");
                                    return;
                                }
                                Some(Ok(_)) => panic!("unexpected request"),
                            }
                        }
                    }
                    drop((request, send));
                    match connection.accept().await {
                        None => {}
                        Some(Err(error)) => {
                            assert!(error.is_io(), "unexpected connection error: {error}")
                        }
                        Some(Ok(_)) => panic!("unexpected request"),
                    }
                });
                let _stop = AbortTasksOnDrop {
                    tasks: [server.abort_handle()],
                };
                let process_memory = MemoryBudget::new(1024 * 1024).expect("process memory");
                let session_memory = MemoryBudget::new(1024 * 1024).expect("session memory");
                let config = H2Config {
                    max_concurrent_streams: 1,
                    max_pending_opens: 1,
                    process_budget: process_memory.clone(),
                    session_budget: session_memory.clone(),
                    process_flows: ResourceBudget::new(1).expect("process flows"),
                    session_flows: ResourceBudget::new(1).expect("session flows"),
                    process_opens: ResourceBudget::new(1).expect("process opens"),
                    session_opens: ResourceBudget::new(1).expect("session opens"),
                    ..H2Config::default()
                };
                let quotas = [
                    config.process_flows.clone(),
                    config.session_flows.clone(),
                    config.process_opens.clone(),
                    config.session_opens.clone(),
                ];
                let session = H2Session::handshake_with_config(client, true, config)
                    .await
                    .expect("session");
                let metadata_charge =
                    process_memory.used() - session.config().control_reserve_bytes;
                let destination = Destination::parse("1.1.1.1:9").expect("destination");
                let mut stream = Some(
                    session
                        .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                        .await
                        .expect("stream"),
                );
                assert_eq!(session.owner.flow_slots.used(), 1);
                if !hold_flow {
                    drop(stream.take());
                }
                let deadline = Deadline::after(Duration::from_millis(100)).expect("deadline");
                let mut closing = Box::pin(session.close_with_deadline(deadline));
                assert!(
                    closing
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert_eq!(session.owner.flow_slots.used(), usize::from(hold_flow));
                drop(stream.take());
                // The peer may finish when close releases the last client handle.
                let _ = close_peer.send(());
                session
                    .wait_closed()
                    .await
                    .expect("clean driver completion");
                deadline
                    .remaining()
                    .expect("driver completed before expiration");
                for quota in &quotas {
                    assert_eq!(quota.used(), 0);
                }
                assert!(!session.has_outstanding_flows());
                timeout_at(deadline.expires_at(), std::future::pending::<()>())
                    .await
                    .expect_err("deadline elapsed");
                assert_eq!(
                    closing
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(EngineError::DeadlineExceeded))
                );
                drop(closing);
                assert!(!session.owner.closed.load(Ordering::Acquire));
                assert!(session.owner.cancelled.load(Ordering::Acquire));
                assert_eq!(process_memory.used(), metadata_charge);
                assert_eq!(session_memory.used(), metadata_charge);
                assert_eq!(session.owner.flow_slots.used(), 0);
                assert_eq!(session.owner.pending_opens.used(), 0);
                assert_eq!(
                    session.close(Duration::from_secs(2)).await,
                    Err(EngineError::Cancelled)
                );
                drop(session);
                server.await.expect("server join");
                assert_eq!(process_memory.used(), 0);
                assert_eq!(session_memory.used(), 0);
            })
            .await
            .expect("late close completion");
        }
    }

    #[tokio::test]
    async fn a_ready_dial_result_after_expiry_is_rejected_and_released() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server_io) = tokio::io::duplex(8 * 1024);
            let accept = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.expect("handshake");
                let (request, respond) = connection
                    .accept()
                    .await
                    .expect("request present")
                    .expect("request");
                (connection, request, respond)
            });
            let _stop_accept = AbortTasksOnDrop {
                tasks: [accept.abort_handle()],
            };
            let session = Arc::new(H2Session::handshake(client, true).await.expect("session"));
            let opening_session = Arc::clone(&session);
            let opening = tokio::spawn(async move {
                opening_session
                    .open_stream(
                        &Destination::parse("1.1.1.1:9").expect("destination"),
                        &Credential::from_bytes([0x11; 32]),
                    )
                    .await
            });
            let _stop_opening = AbortTasksOnDrop {
                tasks: [opening.abort_handle()],
            };
            let (mut connection, request, respond) = accept.await.expect("accept join");
            let driver = tokio::spawn(async move {
                match connection.accept().await {
                    None => {}
                    Some(Err(error)) => {
                        assert!(error.is_io(), "unexpected connection error: {error}")
                    }
                    Some(Ok(_)) => panic!("unexpected request"),
                }
            });
            let _stop_driver = AbortTasksOnDrop {
                tasks: [driver.abort_handle()],
            };
            let process_memory = MemoryBudget::new(1024 * 1024).expect("process memory");
            let session_memory = MemoryBudget::new(1024 * 1024).expect("session memory");
            let process_opens = ResourceBudget::new(1).expect("process opens");
            let session_opens = ResourceBudget::new(1).expect("session opens");
            let config = H2Config {
                process_budget: process_memory.clone(),
                session_budget: session_memory.clone(),
                process_opens: process_opens.clone(),
                session_opens: session_opens.clone(),
                open_timeout: Duration::from_millis(100),
                ..H2Config::default()
            };
            let (complete_dial, waiting_dial) = tokio::sync::oneshot::channel();
            let (deadline_seen, seen_deadline) = tokio::sync::oneshot::channel();
            let (target, mut target_peer) = tokio::io::duplex(16);
            let mut handler = Box::pin(handle_h2_connect_authorized(
                request,
                respond,
                Arc::new(StaticAuthorizer::new(Credential::from_bytes([0x11; 32]), 7)),
                false,
                config,
                move |_, _, deadline| async move {
                    deadline_seen
                        .send(deadline)
                        .expect("dial deadline observer");
                    waiting_dial
                        .await
                        .map_err(|_| EngineError::TargetConnectFailed)
                },
            ));
            assert!(
                handler
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(process_opens.used(), 1);
            assert_eq!(session_opens.used(), 1);
            assert!(process_memory.used() > 0);
            assert_eq!(session_memory.used(), process_memory.used());
            let deadline = seen_deadline.await.expect("dial deadline");
            timeout_at(deadline.expires_at(), std::future::pending::<()>())
                .await
                .expect_err("deadline elapsed");
            assert_eq!(deadline.remaining(), Err(EngineError::DeadlineExceeded));
            complete_dial.send(target).expect("ready target");
            let completion = handler
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            let opened = opening.await.expect("open join").expect("rejected stream");
            assert_eq!(opened.status(), StatusCode::NOT_FOUND);
            assert!(matches!(completion, Poll::Ready(Ok(()))));
            drop(handler);
            let mut sentinel = [0x7e];
            assert_eq!(
                target_peer
                    .read(&mut sentinel)
                    .await
                    .expect("target closed"),
                0
            );
            assert_eq!(sentinel, [0x7e]);
            assert_eq!(process_opens.used(), 0);
            assert_eq!(session_opens.used(), 0);
            assert_eq!(process_memory.used(), 0);
            assert_eq!(session_memory.used(), 0);
            drop(opened);
            session.cancel();
            assert_eq!(
                session.close(Duration::from_secs(2)).await,
                Err(EngineError::Cancelled)
            );
            drop(session);
            driver.await.expect("driver join");
        })
        .await
        .expect("late dial rejection completion");
    }

    fn reply_after_request_eof() -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, server_io) = tokio::io::duplex(8 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.expect("handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("request present")
                .expect("request");
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("response");
            let mut send = respond
                .send_response(response, false)
                .expect("send response");
            let exchange = async move {
                let mut body = request.into_body();
                let mut received = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("request data");
                    assert!(received.len() + chunk.len() <= 4);
                    received.extend_from_slice(&chunk);
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("receive credit");
                }
                assert_eq!(received, b"ping");
                send.send_data(Bytes::from_static(b"pong"), true)
                    .expect("reply");
            };
            tokio::select! {
                () = exchange => {}
                incoming = connection.accept() => panic!("connection ended before request EOF: {incoming:?}"),
            }
            match connection.accept().await {
                None => {}
                Some(Err(error)) => assert!(error.is_io(), "unexpected connection error: {error}"),
                Some(Ok(_)) => panic!("unexpected request"),
            }
        });
        (client, server)
    }

    #[tokio::test]
    async fn split_writer_drop_preserves_reply_and_weak_controls_keep_metadata_charged() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server) = reply_after_request_eof();
            let _stop = AbortTasksOnDrop {
                tasks: [server.abort_handle()],
            };
            let memory = MemoryBudget::new(1024 * 1024).expect("memory");
            let config = H2Config {
                process_budget: memory.clone(),
                session_budget: MemoryBudget::new(1024 * 1024).expect("session memory"),
                ..H2Config::default()
            };
            let flows = config.session_flows.clone();
            let session = H2Session::handshake_with_config(client, true, config)
                .await
                .expect("session");
            let destination = Destination::parse("1.1.1.1:9").expect("destination");
            let stream = session
                .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                .await
                .expect("stream");
            let control = stream.control();
            let (mut reader, mut writer) = stream.into_split();
            assert_eq!(flows.used(), 1);
            assert_eq!(writer.write(b"ping").await.expect("write"), 4);
            drop(writer);
            let mut reply = [0u8; 4];
            assert_eq!(
                reader.read(&mut reply).await.expect("reply"),
                ReadOutcome::Data(4)
            );
            assert_eq!(reply, *b"pong");
            assert_eq!(
                reader.read(&mut reply).await.expect("EOF"),
                ReadOutcome::Eof
            );
            assert_eq!(flows.used(), 0);
            drop(reader);
            tokio::time::timeout(
                Duration::from_secs(2),
                session.close(Duration::from_secs(2)),
            )
            .await
            .expect("close completion")
            .expect("close");
            drop(session);
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server completion")
                .expect("server join");
            assert_eq!(control.cancel(), Err(EngineError::Cancelled));
            let metadata_charge = memory.used();
            assert!(metadata_charge > 0);
            let retained_control = control.clone();
            drop(control);
            assert_eq!(memory.used(), metadata_charge);
            drop(retained_control);
            assert_eq!(memory.used(), 0);
        })
        .await
        .expect("split ownership completion");
    }

    #[tokio::test]
    async fn dropping_capacity_reservation_returns_assigned_credit_without_reset() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server) = reply_after_request_eof();
            let _stop = AbortTasksOnDrop {
                tasks: [server.abort_handle()],
            };
            let destination = Destination::parse("1.1.1.1:9").expect("destination");
            let stream = open_h2(
                client,
                &destination,
                &Credential::from_bytes([0x11; 32]),
                true,
            )
            .await
            .expect("stream");
            let (mut reader, mut writer) = stream.into_split();
            writer
                .shared
                .lock_state()
                .send
                .as_mut()
                .expect("send")
                .reserve_capacity(4);
            let capacity = CapacityReservation {
                shared: &writer.shared,
            };
            let assigned = tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| {
                    writer
                        .shared
                        .lock_state()
                        .poll_capacity(cx, &writer.shared.owner)
                }),
            )
            .await
            .expect("capacity completion")
            .expect("capacity");
            assert!(assigned >= 4);
            drop(capacity);
            assert_eq!(
                writer
                    .shared
                    .lock_state()
                    .send
                    .as_ref()
                    .expect("send")
                    .capacity(),
                0
            );
            assert_eq!(writer.write(b"ping").await.expect("reused writer"), 4);
            writer.end_write().await.expect("request EOF");
            let mut reply = [0u8; 4];
            assert_eq!(
                reader.read(&mut reply).await.expect("reply"),
                ReadOutcome::Data(4)
            );
            assert_eq!(reply, *b"pong");
            assert_eq!(
                reader.read(&mut reply).await.expect("EOF"),
                ReadOutcome::Eof
            );
            drop((reader, writer));
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server completion")
                .expect("server join");
        })
        .await
        .expect("capacity rollback completion");
    }

    #[tokio::test]
    async fn dropping_reader_returns_only_the_unread_tail_while_writer_survives() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server_io) = tokio::io::duplex(8 * 1024);
            let (request_eof, eof_received) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.expect("handshake");
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .expect("request present")
                    .expect("request");
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("response");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response");
                send.send_data(Bytes::from_static(b"12345678"), false)
                    .expect("initial reply");
                let exchange = async move {
                    let mut body = request.into_body();
                    let mut received = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.expect("request data");
                        assert!(received.len() + chunk.len() <= 4);
                        received.extend_from_slice(&chunk);
                        body.flow_control()
                            .release_capacity(chunk.len())
                            .expect("request credit");
                    }
                    assert_eq!(received, b"ping");
                    send.send_data(Bytes::new(), true).expect("reply EOF");
                    request_eof.send(()).expect("request EOF observer");
                };
                tokio::select! {
                    () = exchange => {}
                    incoming = connection.accept() => panic!("connection ended before request EOF: {incoming:?}"),
                }
                match connection.accept().await {
                    None => {}
                    Some(Err(error)) => assert!(error.is_io(), "unexpected connection error: {error}"),
                    Some(Ok(_)) => panic!("unexpected request"),
                }
            });
            let _stop = AbortTasksOnDrop {
                tasks: [server.abort_handle()],
            };
            let destination = Destination::parse("1.1.1.1:9").expect("destination");
            let stream = open_h2(
                client,
                &destination,
                &Credential::from_bytes([0x11; 32]),
                true,
            )
            .await
            .expect("stream");
            let (mut reader, mut writer) = stream.into_split();
            let mut prefix = [0u8; 1];
            assert_eq!(reader.read(&mut prefix).await.expect("prefix"), ReadOutcome::Data(1));
            assert_eq!(prefix, *b"1");
            let credit = receive_credit(&reader.shared);
            assert_eq!(credit.used_capacity(), 7);
            drop(reader);
            assert_eq!(credit.used_capacity(), 0);
            assert_eq!(writer.write(b"ping").await.expect("writer survives"), 4);
            writer.end_write().await.expect("request EOF");
            eof_received.await.expect("peer observed request EOF");
            drop((credit, writer));
            server.await.expect("server join");
        })
        .await
        .expect("reader drop completion");
    }

    #[derive(Clone, Copy)]
    enum PeerClose {
        Reset,
        GoAway,
        TransportLoss,
    }

    fn close_peer_after_reply(
        close: PeerClose,
        empty_frames: usize,
        extra_data_frames: usize,
    ) -> (
        tokio::io::DuplexStream,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client, server_io) = tokio::io::duplex(8 * 1024);
        let (close_peer, close_requested) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(server_io);
            let mut connection = h2::server::handshake(tokio::io::join(&mut read, &mut write))
                .await
                .expect("handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("request present")
                .expect("request");
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("response");
            let mut send = respond
                .send_response(response, false)
                .expect("send response");
            send.send_data(Bytes::from_static(b"1234"), false)
                .expect("first reply chunk");
            send.send_data(Bytes::from_static(b"5678"), false)
                .expect("second reply chunk");
            for _ in 0..extra_data_frames {
                send.send_data(Bytes::from_static(b"x"), false)
                    .expect("queued DATA");
            }
            for _ in 0..empty_frames {
                send.send_data(Bytes::new(), false).expect("empty DATA");
            }
            tokio::select! {
                closed = close_requested => closed.expect("close requested"),
                incoming = connection.accept() => panic!("connection ended before peer close: {incoming:?}"),
            }
            match close {
                PeerClose::Reset => {
                    send.send_reset(h2::Reason::CANCEL);
                    match connection.accept().await {
                        None => {}
                        Some(Err(error)) => {
                            assert!(error.is_io(), "unexpected connection error: {error}")
                        }
                        Some(Ok(_)) => panic!("unexpected request"),
                    }
                }
                PeerClose::GoAway => {
                    drop((send, request, connection));
                    // Last stream ID zero applies the GOAWAY error to this stream.
                    let goaway = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
                    write.write_all(&goaway).await.expect("GOAWAY frame");
                    write.shutdown().await.expect("GOAWAY flushed");
                    // Keep reads open until the client receives GOAWAY and closes its transport.
                    let mut buffer = [0; 1024];
                    while read.read(&mut buffer).await.expect("peer close") != 0 {}
                    return;
                }
                PeerClose::TransportLoss => {}
            }
            drop((send, request, connection));
        });
        (client, close_peer, server)
    }

    #[tokio::test]
    async fn io_wait_observes_pending_poll_changes_and_notifies_on_ready() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, close_peer, server) =
                close_peer_after_reply(PeerClose::TransportLoss, 0, 0);
            let _stop = AbortTasksOnDrop {
                tasks: [server.abort_handle()],
            };
            let session = H2Session::handshake(client, true).await.expect("session");
            let destination = Destination::parse("1.1.1.1:9").expect("destination");
            let stream = session
                .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                .await
                .expect("stream");
            let shared = &stream.shared;
            let mut polls = 0;
            shared
                .wait_for_io(|_| {
                    polls += 1;
                    if polls == 1 {
                        shared.changed.notify_waiters();
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            assert_eq!(polls, 2);
            let ready = shared.changed.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            shared.wait_for_io(|_| Poll::Ready(())).await;
            ready.await;
            close_peer.send(()).expect("close peer");
            server.await.expect("server join");
            session.cancel();
            assert_eq!(
                session.close(Duration::from_secs(2)).await,
                Err(EngineError::Cancelled)
            );
        })
        .await
        .expect("I/O notification completion");
    }

    #[tokio::test]
    async fn ready_reset_discards_tail_and_queued_data_but_goaway_drains_both() {
        for reset in [true, false] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let close = if reset {
                    PeerClose::Reset
                } else {
                    PeerClose::GoAway
                };
                let (client, close_peer, server) = close_peer_after_reply(close, 0, 0);
                let _stop = AbortTasksOnDrop {
                    tasks: [server.abort_handle()],
                };
                let session = H2Session::handshake(client, true).await.expect("session");
                let destination = Destination::parse("1.1.1.1:9").expect("destination");
                let mut stream = session
                    .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                    .await
                    .expect("stream");
                let mut prefix = [0u8; 1];
                assert_eq!(
                    stream.read(&mut prefix).await.expect("prefix"),
                    ReadOutcome::Data(1)
                );
                assert_eq!(prefix, *b"1");
                close_peer.send(()).expect("close peer");
                let reason = terminal_reason(&stream.shared)
                    .await
                    .expect("ready terminal reason");
                assert_eq!(
                    reason,
                    if reset {
                        h2::Reason::CANCEL
                    } else {
                        h2::Reason::INTERNAL_ERROR
                    }
                );
                let credit = receive_credit(&stream.shared);
                assert_eq!(credit.used_capacity(), 7);
                let mut sentinel = [0x7e; 4];
                if reset {
                    assert_eq!(
                        stream.read(&mut sentinel).await.expect("reset"),
                        ReadOutcome::Reset
                    );
                    assert_eq!(sentinel, [0x7e; 4]);
                } else {
                    assert_eq!(
                        session.wait_closed().await,
                        Err(EngineError::TransportUnavailable)
                    );
                    assert_eq!(
                        stream.read(&mut sentinel).await.expect("tail"),
                        ReadOutcome::Data(3)
                    );
                    assert_eq!(sentinel, *b"234~");
                    assert_eq!(credit.used_capacity(), 4);
                    assert_eq!(
                        stream.read(&mut sentinel).await.expect("queued DATA"),
                        ReadOutcome::Data(4)
                    );
                    assert_eq!(sentinel, *b"5678");
                    assert_eq!(credit.used_capacity(), 0);
                    sentinel.fill(0x7e);
                    assert_eq!(
                        stream.read(&mut sentinel).await,
                        Err(EngineError::TransportUnavailable)
                    );
                    assert_eq!(sentinel, [0x7e; 4]);
                }
                drop((credit, stream, session));
                server.await.expect("server join");
            })
            .await
            .expect("terminal read completion");
        }
    }

    #[tokio::test]
    async fn split_writer_failure_preserves_connection_data_and_discards_reset_data() {
        #[derive(Clone, Copy)]
        enum WriteOperation {
            Data,
            End,
            Drop,
        }
        for close in [
            PeerClose::Reset,
            PeerClose::GoAway,
            PeerClose::TransportLoss,
        ] {
            for read_first in [false, true] {
                for operation in [
                    WriteOperation::Data,
                    WriteOperation::End,
                    WriteOperation::Drop,
                ] {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        let (client, close_peer, server) = close_peer_after_reply(close, 0, 0);
                        let _stop = AbortTasksOnDrop {
                            tasks: [server.abort_handle()],
                        };
                        let process = MemoryBudget::new(1024 * 1024).expect("process memory");
                        let session_memory =
                            MemoryBudget::new(1024 * 1024).expect("session memory");
                        let config = H2Config {
                            process_budget: process.clone(),
                            session_budget: session_memory.clone(),
                            ..H2Config::default()
                        };
                        let flows = config.session_flows.clone();
                        let opens = config.session_opens.clone();
                        let session = H2Session::handshake_with_config(client, true, config)
                            .await
                            .expect("session");
                        let destination = Destination::parse("1.1.1.1:9").expect("destination");
                        let stream = session
                            .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                            .await
                            .expect("stream");
                        let (mut reader, writer) = stream.into_split();
                        let mut writer = Some(writer);
                        let mut prefix = [0u8; 1];
                        assert_eq!(
                            reader.read(&mut prefix).await.expect("prefix"),
                            ReadOutcome::Data(1)
                        );
                        assert_eq!(prefix, *b"1");
                        close_peer.send(()).expect("close peer");
                        let reset = matches!(close, PeerClose::Reset);
                        if reset {
                            let reason =
                                terminal_reason(&reader.shared).await.expect("reset ready");
                            assert_eq!(reason, h2::Reason::CANCEL);
                        } else {
                            let completion = session.wait_closed().await;
                            if matches!(close, PeerClose::TransportLoss) {
                                assert_eq!(completion, Ok(()));
                                assert_eq!(
                                    session.driver_error(),
                                    Some(EngineError::TransportUnavailable)
                                );
                            } else {
                                assert_eq!(completion, Err(EngineError::TransportUnavailable));
                            }
                            assert_eq!(flows.used(), 0);
                        }
                        let credit = receive_credit(&reader.shared);
                        assert_eq!(credit.used_capacity(), 7);
                        let mut sentinel = [0x7e; 4];
                        if read_first {
                            if reset {
                                assert_eq!(
                                    reader.read(&mut sentinel).await.expect("reset"),
                                    ReadOutcome::Reset
                                );
                                assert_eq!(sentinel, [0x7e; 4]);
                            } else {
                                assert_eq!(
                                    reader.read(&mut sentinel).await.expect("tail"),
                                    ReadOutcome::Data(3)
                                );
                                assert_eq!(sentinel, *b"234~");
                                assert_eq!(credit.used_capacity(), 4);
                            }
                        }
                        let expected = if reset && read_first {
                            EngineError::ProtocolViolation
                        } else if reset {
                            EngineError::RemoteReset
                        } else {
                            EngineError::TransportUnavailable
                        };
                        match operation {
                            WriteOperation::Data => {
                                assert_eq!(
                                    writer.as_mut().expect("writer").write(b"late").await,
                                    Err(expected)
                                );
                            }
                            WriteOperation::End => {
                                assert_eq!(
                                    writer.as_mut().expect("writer").end_write().await,
                                    Err(expected)
                                );
                            }
                            WriteOperation::Drop => drop(writer.take()),
                        }
                        if reset {
                            sentinel.fill(0x7e);
                            assert_eq!(
                                reader.read(&mut sentinel).await.expect("reset"),
                                ReadOutcome::Reset
                            );
                            assert_eq!(sentinel, [0x7e; 4]);
                        } else {
                            if !read_first {
                                assert_eq!(
                                    reader.read(&mut sentinel).await.expect("tail"),
                                    ReadOutcome::Data(3)
                                );
                                assert_eq!(sentinel, *b"234~");
                                assert_eq!(credit.used_capacity(), 4);
                            }
                            assert_eq!(
                                reader.read(&mut sentinel).await.expect("queued DATA"),
                                ReadOutcome::Data(4)
                            );
                            assert_eq!(sentinel, *b"5678");
                            assert_eq!(credit.used_capacity(), 0);
                            sentinel.fill(0x7e);
                            assert_eq!(
                                reader.read(&mut sentinel).await,
                                Err(EngineError::TransportUnavailable)
                            );
                            assert_eq!(sentinel, [0x7e; 4]);
                        }
                        assert_eq!(flows.used(), 0);
                        assert_eq!(opens.used(), 0);
                        drop((credit, reader, writer));
                        session.cancel();
                        assert_eq!(
                            session.close(Duration::from_secs(2)).await,
                            Err(EngineError::Cancelled)
                        );
                        drop(session);
                        server.await.expect("server join");
                        assert_eq!(process.used(), 0);
                        assert_eq!(session_memory.used(), 0);
                    })
                    .await
                    .expect("split writer failure completion");
                }
            }
        }
    }

    #[tokio::test]
    async fn writer_drop_leaves_an_incomplete_terminal_probe_for_the_reader() {
        for close in [PeerClose::Reset, PeerClose::GoAway] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let (client, close_peer, server) = close_peer_after_reply(close, 0, 64);
                let _stop = AbortTasksOnDrop {
                    tasks: [server.abort_handle()],
                };
                let session = H2Session::handshake(client, true).await.expect("session");
                let destination = Destination::parse("1.1.1.1:9").expect("destination");
                let stream = session
                    .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                    .await
                    .expect("stream");
                let (mut reader, writer) = stream.into_split();
                let mut prefix = [0u8; 1];
                assert_eq!(
                    reader.read(&mut prefix).await.expect("prefix"),
                    ReadOutcome::Data(1)
                );
                close_peer.send(()).expect("close peer");
                terminal_reason(&reader.shared)
                    .await
                    .expect("terminal reason");
                let credit = receive_credit(&reader.shared);
                assert_eq!(credit.used_capacity(), 71);
                drop(writer);
                {
                    let state = reader.shared.lock_state();
                    assert_eq!(state.terminal_probe_events, TERMINAL_PROBE_EVENTS_PER_POLL);
                    assert_eq!(
                        state.terminal_read_queue.chunks.len(),
                        TERMINAL_PROBE_EVENTS_PER_POLL
                    );
                    assert_eq!(state.pending_read.as_ref(), b"234");
                }
                let mut sentinel = [0x7e; 4];
                if matches!(close, PeerClose::Reset) {
                    assert_eq!(
                        reader.read(&mut sentinel).await.expect("reset"),
                        ReadOutcome::Reset
                    );
                    assert_eq!(sentinel, [0x7e; 4]);
                } else {
                    let mut received = Vec::new();
                    loop {
                        match reader.read(&mut sentinel).await {
                            Ok(ReadOutcome::Data(n)) => received.extend_from_slice(&sentinel[..n]),
                            Err(EngineError::TransportUnavailable) => break,
                            result => panic!("unexpected read result: {result:?}"),
                        }
                    }
                    assert_eq!(&received[..7], b"2345678");
                    assert_eq!(&received[7..], &[b'x'; 64]);
                    assert_eq!(credit.used_capacity(), 0);
                }
                drop((credit, reader));
                session.cancel();
                assert_eq!(
                    session.close(Duration::from_secs(2)).await,
                    Err(EngineError::Cancelled)
                );
                server.await.expect("server join");
            })
            .await
            .expect("writer drop probe completion");
        }
    }

    #[tokio::test]
    async fn reader_drop_returns_queued_probe_credit_after_a_write_future_is_dropped() {
        for close in [PeerClose::Reset, PeerClose::GoAway] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let (client, close_peer, server) = close_peer_after_reply(close, 0, 64);
                let _stop = AbortTasksOnDrop {
                    tasks: [server.abort_handle()],
                };
                let session = H2Session::handshake(client, true).await.expect("session");
                let destination = Destination::parse("1.1.1.1:9").expect("destination");
                let stream = session
                    .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                    .await
                    .expect("stream");
                let (mut reader, mut writer) = stream.into_split();
                let mut prefix = [0u8; 1];
                assert_eq!(
                    reader.read(&mut prefix).await.expect("prefix"),
                    ReadOutcome::Data(1)
                );
                close_peer.send(()).expect("close peer");
                terminal_reason(&reader.shared)
                    .await
                    .expect("terminal reason");
                let credit = receive_credit(&reader.shared);
                assert_eq!(credit.used_capacity(), 71);
                let mut writing = Box::pin(writer.write(b"late"));
                assert!(
                    writing
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                drop(writing);
                assert_eq!(
                    reader.shared.lock_state().terminal_read_queue.chunks.len(),
                    TERMINAL_PROBE_EVENTS_PER_POLL
                );
                assert_eq!(credit.used_capacity(), 71);
                drop(reader);
                assert_eq!(credit.used_capacity(), 0);
                assert!(
                    writer
                        .shared
                        .lock_state()
                        .terminal_read_queue
                        .chunks
                        .is_empty()
                );
                assert_eq!(
                    writer
                        .shared
                        .lock_state()
                        .terminal_read_queue
                        .chunks
                        .capacity(),
                    0
                );
                drop((credit, writer));
                session.cancel();
                assert_eq!(
                    session.close(Duration::from_secs(2)).await,
                    Err(EngineError::Cancelled)
                );
                server.await.expect("server join");
            })
            .await
            .expect("reader drop probe credit completion");
        }
    }

    #[tokio::test]
    async fn terminal_read_probe_enforces_memory_limits_and_ignores_empty_data() {
        for deny_memory in [true, false] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let empty_frames = if deny_memory { 0 } else { 9 };
                let (client, close_peer, server) =
                    close_peer_after_reply(PeerClose::GoAway, empty_frames, 0);
                let _stop = AbortTasksOnDrop {
                    tasks: [server.abort_handle()],
                };
                let process = MemoryBudget::new(1024 * 1024).expect("process budget");
                let session_memory = MemoryBudget::new(1024 * 1024).expect("session budget");
                let config = H2Config {
                    direction_buffer_bytes: 8,
                    process_budget: process.clone(),
                    session_budget: session_memory.clone(),
                    ..H2Config::default()
                };
                let session = H2Session::handshake_with_config(client, true, config)
                    .await
                    .expect("session");
                let destination = Destination::parse("1.1.1.1:9").expect("destination");
                let mut stream = session
                    .open_stream(&destination, &Credential::from_bytes([0x11; 32]))
                    .await
                    .expect("stream");
                let mut prefix = [0u8; 1];
                assert_eq!(
                    stream.read(&mut prefix).await.expect("prefix"),
                    ReadOutcome::Data(1)
                );
                assert_eq!(prefix, *b"1");
                close_peer.send(()).expect("close peer");
                assert_eq!(
                    session.wait_closed().await,
                    Err(EngineError::TransportUnavailable)
                );
                let ready = stream
                    .shared
                    .lock_state()
                    .send
                    .as_mut()
                    .expect("send")
                    .poll_reset(&mut Context::from_waker(Waker::noop()));
                let reason = match ready {
                    Poll::Ready(Ok(reason)) => reason,
                    other => panic!("expected ready GOAWAY: {other:?}"),
                };
                assert_eq!(reason, h2::Reason::INTERNAL_ERROR);
                assert_eq!(
                    stream
                        .shared
                        .lock_state()
                        .recv
                        .as_mut()
                        .expect("receive stream")
                        .flow_control()
                        .used_capacity(),
                    7
                );
                let pressure = if deny_memory {
                    Some(
                        process
                            .try_acquire_scoped(&session_memory, process.limit() - process.used())
                            .expect("fill remaining memory"),
                    )
                } else {
                    None
                };
                let mut sentinel = [0x7e; 4];
                if deny_memory {
                    assert_eq!(
                        stream.read(&mut sentinel).await,
                        Err(EngineError::ResourceLimitExceeded)
                    );
                    assert_eq!(sentinel, [0x7e; 4]);
                } else {
                    assert_eq!(
                        stream.read(&mut sentinel).await.expect("tail"),
                        ReadOutcome::Data(3)
                    );
                    assert_eq!(sentinel, *b"234~");
                    assert_eq!(
                        stream.read(&mut sentinel).await.expect("queued DATA"),
                        ReadOutcome::Data(4)
                    );
                    assert_eq!(sentinel, *b"5678");
                    sentinel.fill(0x7e);
                    assert_eq!(
                        stream.read(&mut sentinel).await,
                        Err(EngineError::TransportUnavailable)
                    );
                    assert_eq!(sentinel, [0x7e; 4]);
                }
                assert!(stream.shared.lock_state().pending_read.is_empty());
                assert!(
                    stream
                        .shared
                        .lock_state()
                        .terminal_read_queue
                        .chunks
                        .is_empty()
                );
                assert_eq!(
                    stream
                        .shared
                        .lock_state()
                        .terminal_read_queue
                        .chunks
                        .capacity(),
                    0
                );
                drop((pressure, stream, session));
                server.await.expect("server join");
                assert_eq!(process.used(), 0);
                assert_eq!(session_memory.used(), 0);
            })
            .await
            .expect("bounded terminal probe completion");
        }
    }

    #[tokio::test]
    async fn remote_reset_discards_reply_before_reads_or_late_writes() {
        const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

        for (read_first, end_write) in [(true, false), (false, false), (false, true)] {
            let (client, server_io) = tokio::io::duplex(8 * 1024);
            let (reset_peer, reset_requested) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.expect("handshake");
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .expect("request present")
                    .expect("request");
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("response");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response");
                send.send_data(Bytes::from_static(b"pong"), true)
                    .expect("reply");
                tokio::select! {
                    _ = async {
                        reset_requested.await.expect("reset requested");
                        send.send_reset(h2::Reason::CANCEL);
                        std::future::pending::<()>().await;
                    } => unreachable!("pending reset task"),
                    _ = connection.accept() => {}
                }
                drop(request);
            });
            let destination = Destination::parse("1.1.1.1:9").expect("dest");
            let mut opened = tokio::time::timeout(
                IO_TIMEOUT,
                open_h2(
                    client,
                    &destination,
                    &Credential::from_bytes([0x11; 32]),
                    true,
                ),
            )
            .await
            .expect("open completion")
            .expect("open");
            let mut prefix = [0u8; 1];
            assert_eq!(
                tokio::time::timeout(IO_TIMEOUT, opened.read(&mut prefix))
                    .await
                    .expect("reply progress")
                    .expect("read"),
                ReadOutcome::Data(1)
            );
            assert_eq!(&prefix, b"p");
            if end_write {
                let mut tail = [0u8; 3];
                assert_eq!(
                    opened.read(&mut tail).await.expect("tail"),
                    ReadOutcome::Data(3)
                );
                assert_eq!(&tail, b"ong");
                assert_eq!(
                    opened.read(&mut prefix).await.expect("eof"),
                    ReadOutcome::Eof
                );
            }
            reset_peer.send(()).expect("reset peer");
            let reset = tokio::time::timeout(IO_TIMEOUT, terminal_reason(&opened.shared))
                .await
                .expect("reset completion")
                .expect("reset");
            assert_eq!(reset, h2::Reason::CANCEL);
            if !read_first {
                let result = if end_write {
                    opened.end_write().await
                } else {
                    opened.write(b"late").await.map(|_| ())
                };
                assert_eq!(result, Err(EngineError::RemoteReset));
            }
            prefix[0] = 0x7e;
            assert_eq!(
                opened.read(&mut prefix).await.expect("read"),
                ReadOutcome::Reset
            );
            assert_eq!(prefix, [0x7e]);
            assert_eq!(
                opened.write(b"later").await,
                Err(EngineError::ProtocolViolation)
            );
            drop(opened);
            tokio::time::timeout(IO_TIMEOUT, server)
                .await
                .expect("server completion")
                .expect("server join");
        }
    }

    #[tokio::test]
    async fn zero_linger_close_is_not_a_clean_fin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let local = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let (mut peer, _) = listener.accept().await.expect("accept");
        abort_tcp(local);
        let mut buf = [0u8; 8];
        peer.read(&mut buf).await.expect_err("rst");
    }
}
