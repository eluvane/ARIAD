#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use ariad_core::MemoryBudget;
use ariad_core::{
    BindingId, BudgetLimits, Credential, DatagramOutcome, DeliveryMode, Destination, EngineError,
    NetworkEpoch, ResourceBudget, ResourceReservation, ScopedMemoryReservation,
    ScopedResourceReservation, SessionPhase,
};
use tokio::sync::{Notify, watch};

use crate::Deadline;
use crate::api::EngineConfig;
use crate::datagram::{
    DatagramAssociation, DatagramControl, DatagramOptions, DatagramPayload, DatagramRecvHalf,
    DatagramSendHalf,
};
use crate::dir::ReadOutcome;
use crate::h2_tunnel::H2Config;
use crate::h2_tunnel::{H2Connect, H2ReadHalf, H2Session, H2StreamControl, H2WriteHalf};
#[cfg(feature = "h3")]
use crate::h3_tunnel::{
    H3Connect, H3DatagramAssociation, H3DatagramControl, H3DatagramRecvHalf, H3DatagramSendHalf,
    H3ReadHalf, H3Session, H3StreamControl, H3WriteHalf,
};
use crate::response::classify_connect_status;

/// A snapshot of binding support and completed datagram negotiation.
/// Session readiness and target acceptance remain separate outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    /// The transport binding selected for this session.
    pub binding: BindingId,
    /// Whether the binding supports TCP CONNECT streams.
    pub tcp_streams: bool,
    /// Whether the peer currently enables extended CONNECT.
    pub extended_connect: bool,
    /// Delivery mode of the last successful association open, or `Unsupported`
    /// before an association has been opened.
    pub datagram_delivery: DeliveryMode,
    /// False for the currently supported transport connectors.
    pub ech: bool,
}

/// Restrictions checked before opening a TCP CONNECT stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamOptions {
    /// Requires this session binding. `None` accepts the selected binding.
    pub require_binding: Option<BindingId>,
}

/// Delivery requirements checked before opening a datagram association.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramRequirements {
    /// Rejects reliable encapsulation. Native datagram delivery requires H3.
    pub require_unreliable: bool,
}

/// How a session close treats existing flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseMode {
    /// Allows existing flows to finish before forcing cancellation.
    Graceful,
    /// Requests cancellation before waiting for transport cleanup.
    Immediate,
}

/// Whether session cleanup required cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Existing flows and transport cleanup completed without forced cancellation.
    Graceful,
    /// Cancellation was requested or the drain deadline expired.
    Forced,
}

#[derive(Clone, Copy)]
struct SessionState {
    phase: SessionPhase,
    close_result: Option<Result<CloseOutcome, EngineError>>,
}

impl SessionState {
    fn check_io(self) -> Result<(), EngineError> {
        if self.close_result == Some(Ok(CloseOutcome::Forced)) {
            return Err(EngineError::Cancelled);
        }
        // Transport closure preserves buffered I/O and its terminal outcomes.
        match self.phase {
            SessionPhase::Ready
            | SessionPhase::Draining
            | SessionPhase::Closed
            | SessionPhase::Failed => Ok(()),
            _ => Err(EngineError::Cancelled),
        }
    }
}

#[derive(Clone)]
enum SessionBinding {
    H2(H2Session),
    #[cfg(feature = "h3")]
    H3(H3Session),
}

impl SessionBinding {
    fn binding(&self) -> BindingId {
        match self {
            Self::H2(_) => BindingId::H2,
            #[cfg(feature = "h3")]
            Self::H3(_) => BindingId::H3,
        }
    }

    fn cancel(&self) {
        match self {
            Self::H2(session) => session.cancel(),
            #[cfg(feature = "h3")]
            Self::H3(session) => session.cancel(),
        }
    }

    fn driver_error(&self) -> Option<EngineError> {
        match self {
            Self::H2(session) => session.driver_error(),
            #[cfg(feature = "h3")]
            Self::H3(session) => session.driver_error(),
        }
    }

    async fn close(&self, deadline: Deadline) -> Result<(), EngineError> {
        match self {
            Self::H2(session) => session.close_with_deadline(deadline).await,
            #[cfg(feature = "h3")]
            Self::H3(session) => session.shutdown(deadline).await,
        }
    }

    async fn wait_closed(&self) -> Result<(), EngineError> {
        match self {
            Self::H2(session) => session.wait_closed().await,
            #[cfg(feature = "h3")]
            Self::H3(session) => session.wait_closed().await,
        }
    }
}

pub(crate) struct SessionInner {
    binding: SessionBinding,
    credential: Credential,
    endpoint_id: u64,
    network_epoch: NetworkEpoch,
    proxy: String,
    limits: BudgetLimits,
    state: watch::Sender<SessionState>,
    close_started: AtomicBool,
    udp_negotiated: AtomicBool,
    udp_native: AtomicBool,
    next_generation: AtomicU64,
    slot: Mutex<Option<ResourceReservation>>,
    completion: Mutex<Option<tokio::task::JoinHandle<()>>>,
    completion_done: watch::Sender<bool>,
}

impl SessionInner {
    fn check_open(&self) -> Result<(), EngineError> {
        if let Some(error) = self.binding.driver_error() {
            return Err(error);
        }
        match self.state.borrow().phase {
            SessionPhase::Ready => Ok(()),
            SessionPhase::Cancelled => Err(EngineError::Cancelled),
            SessionPhase::Failed => Err(EngineError::TransportUnavailable),
            _ => Err(EngineError::ProtocolViolation),
        }
    }

    async fn run_operation<T>(
        &self,
        operation: SessionOperation,
        io: impl Future<Output = Result<T, EngineError>>,
    ) -> Result<T, EngineError> {
        let mut cancellation = self.state.subscribe();
        tokio::select! {
            biased;
            error = wait_session_interrupt(&mut cancellation, operation) => Err(error),
            result = io => result,
        }
    }

    pub(crate) fn drain(&self) {
        self.state.send_modify(|state| {
            if state.phase == SessionPhase::Ready {
                state.phase = SessionPhase::Draining;
            }
        });
    }

    fn cancel(&self) {
        self.binding.cancel();
        self.state.send_modify(|state| {
            if state.close_result.is_none() {
                state.phase = SessionPhase::Cancelled;
            }
        });
    }

    fn finish_close(&self, result: Result<CloseOutcome, EngineError>) {
        self.release_slot();
        self.state.send_modify(|state| {
            state.phase = if result.is_ok() {
                SessionPhase::Closed
            } else {
                SessionPhase::Failed
            };
            state.close_result = Some(result);
        });
    }

    fn release_slot(&self) {
        drop(
            self.slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take(),
        );
    }

    pub(crate) async fn join_completion(&self) -> Result<(), EngineError> {
        // Only one caller owns the join handle. Others must wait for its completion signal.
        let task = self
            .completion
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(task) = task {
            if task.await.is_err() {
                self.release_slot();
                let _ = self.completion_done.send_replace(true);
                return Err(EngineError::TransportUnavailable);
            }
        } else {
            let mut done = self.completion_done.subscribe();
            loop {
                if *done.borrow() {
                    break;
                }
                done.changed()
                    .await
                    .map_err(|_| EngineError::TransportUnavailable)?;
            }
        }
        Ok(())
    }

    fn generation(&self) -> Result<u64, EngineError> {
        self.next_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| EngineError::ResourceLimitExceeded)
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        self.binding.cancel();
        if let Some(task) = self
            .completion
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

/// A verified transport shared by clones, streams, and datagram associations.
///
/// Streams and associations retain the transport after a session handle is
/// dropped. Dropping the last owner requests cancellation. Retained handles and
/// buffers keep their memory charges after network admission is released.
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: Arc<SessionInner>,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("phase", &self.phase())
            .field("capabilities", &self.capabilities())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn ensure_ready(&self) -> Result<(), EngineError> {
        self.inner.check_open()
    }

    pub(crate) fn from_h2(
        session: H2Session,
        credential: Credential,
        endpoint_id: u64,
        network_epoch: NetworkEpoch,
        proxy: String,
        limits: BudgetLimits,
        slot: ResourceReservation,
    ) -> Self {
        Self::from_binding(
            SessionBinding::H2(session),
            credential,
            endpoint_id,
            network_epoch,
            proxy,
            limits,
            slot,
        )
    }

    #[cfg(feature = "h3")]
    pub(crate) fn from_h3(
        session: H3Session,
        credential: Credential,
        endpoint_id: u64,
        network_epoch: NetworkEpoch,
        proxy: String,
        limits: BudgetLimits,
        slot: ResourceReservation,
    ) -> Self {
        Self::from_binding(
            SessionBinding::H3(session),
            credential,
            endpoint_id,
            network_epoch,
            proxy,
            limits,
            slot,
        )
    }

    fn from_binding(
        binding: SessionBinding,
        credential: Credential,
        endpoint_id: u64,
        network_epoch: NetworkEpoch,
        proxy: String,
        limits: BudgetLimits,
        slot: ResourceReservation,
    ) -> Self {
        let (state, _) = watch::channel(SessionState {
            phase: SessionPhase::Ready,
            close_result: None,
        });
        let (completion_done, _) = watch::channel(false);
        let session = Self {
            inner: Arc::new(SessionInner {
                binding,
                credential,
                endpoint_id,
                network_epoch,
                proxy,
                limits,
                state,
                close_started: AtomicBool::new(false),
                udp_negotiated: AtomicBool::new(false),
                udp_native: AtomicBool::new(false),
                next_generation: AtomicU64::new(1),
                slot: Mutex::new(Some(slot)),
                completion: Mutex::new(None),
                completion_done,
            }),
        };
        // A weak reference prevents a cycle through the completion task.
        let weak = Arc::downgrade(&session.inner);
        let binding = session.inner.binding.clone();
        let completion_done = session.inner.completion_done.clone();
        let completion = tokio::spawn(async move {
            let result = binding.wait_closed().await;
            if let Some(inner) = weak.upgrade() {
                inner.release_slot();
                inner.state.send_modify(|state| {
                    if matches!(state.phase, SessionPhase::Ready | SessionPhase::Draining)
                        && !inner.close_started.load(Ordering::Acquire)
                    {
                        state.phase = match result {
                            Ok(()) => SessionPhase::Closed,
                            Err(EngineError::Cancelled) => SessionPhase::Cancelled,
                            Err(_) => SessionPhase::Failed,
                        };
                    }
                });
            }
            // Close waiters use the signal below to observe release of this task's transport owner.
            drop(binding);
            let _ = completion_done.send_replace(true);
        });
        *session
            .inner
            .completion
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(completion);
        session
    }

    /// Returns the current lifecycle snapshot; it can change before a later call.
    pub fn phase(&self) -> SessionPhase {
        if self.inner.binding.driver_error().is_some()
            && matches!(
                self.inner.state.borrow().phase,
                SessionPhase::Ready | SessionPhase::Draining
            )
        {
            SessionPhase::Failed
        } else {
            self.inner.state.borrow().phase
        }
    }

    /// Reports binding support and the last successful datagram negotiation.
    pub fn capabilities(&self) -> NegotiatedCapabilities {
        let extended_connect = match &self.inner.binding {
            SessionBinding::H2(session) => session.extended_connect_enabled(),
            #[cfg(feature = "h3")]
            SessionBinding::H3(session) => session.extended_connect_enabled(),
        };
        NegotiatedCapabilities {
            binding: self.inner.binding.binding(),
            tcp_streams: true,
            extended_connect,
            datagram_delivery: if self.inner.udp_negotiated.load(Ordering::Acquire) {
                if self.inner.udp_native.load(Ordering::Acquire) {
                    DeliveryMode::UnreliableNative
                } else {
                    DeliveryMode::ReliableEncapsulation
                }
            } else {
                DeliveryMode::Unsupported
            },
            ech: false,
        }
    }

    /// Returns the ID of the selected endpoint descriptor.
    pub fn endpoint_id(&self) -> u64 {
        self.inner.endpoint_id
    }

    /// Returns the epoch captured when the transport was selected.
    /// Later engine epoch changes do not change this value.
    pub fn network_epoch(&self) -> NetworkEpoch {
        self.inner.network_epoch
    }

    /// Opens a TCP tunnel after the peer accepts CONNECT on a ready session.
    ///
    /// A required binding mismatch fails before sending the request. Timeout or
    /// dropping a pending open releases its flow and open reservations. The peer
    /// may already have started a target dial; these effects are not rolled back.
    pub async fn open_stream(
        &self,
        destination: &Destination,
        options: StreamOptions,
        deadline: Deadline,
    ) -> Result<Stream, EngineError> {
        deadline.remaining()?;
        self.inner.check_open()?;
        if options
            .require_binding
            .is_some_and(|required| required != self.inner.binding.binding())
        {
            return Err(EngineError::UnsupportedCapability);
        }
        let binding = match &self.inner.binding {
            SessionBinding::H2(session) => {
                let opened = self
                    .inner
                    .run_operation(
                        SessionOperation::Open,
                        session.open_stream_with_deadline(
                            destination,
                            &self.inner.credential,
                            deadline,
                        ),
                    )
                    .await?;
                classify_connect_status(opened.status())?;
                StreamBinding::H2(opened)
            }
            #[cfg(feature = "h3")]
            SessionBinding::H3(session) => {
                let opened = self
                    .inner
                    .run_operation(
                        SessionOperation::Open,
                        session.open_tcp(destination, &self.inner.credential, deadline),
                    )
                    .await?;
                classify_connect_status(opened.status())?;
                StreamBinding::H3(opened)
            }
        };
        self.inner.check_open()?;
        Stream::new(binding, Arc::clone(&self.inner))
    }

    /// Opens and negotiates a CONNECT-UDP association on a ready session.
    ///
    /// An unmet delivery requirement fails before sending the request. Timeout or
    /// dropping a pending open releases its reservations, but a peer target dial
    /// may already have started. Successful negotiation updates `capabilities`.
    pub async fn open_datagram_association(
        &self,
        destination: &Destination,
        requirements: DatagramRequirements,
        deadline: Deadline,
    ) -> Result<Association, EngineError> {
        deadline.remaining()?;
        self.inner.check_open()?;
        let generation = self.inner.generation()?;
        let association = match &self.inner.binding {
            SessionBinding::H2(session) => {
                if requirements.require_unreliable {
                    return Err(EngineError::UnsupportedCapability);
                }
                let mut options =
                    DatagramOptions::from_h2_config(session.config(), generation, false);
                options.limits = self.inner.limits;
                AssociationBinding::H2(
                    self.inner
                        .run_operation(
                            SessionOperation::Open,
                            DatagramAssociation::open_h2(
                                session,
                                &self.inner.proxy,
                                destination,
                                &self.inner.credential,
                                options,
                                deadline,
                            ),
                        )
                        .await?,
                )
            }
            #[cfg(feature = "h3")]
            SessionBinding::H3(session) => {
                if requirements.require_unreliable && !session.native_datagram_enabled() {
                    return Err(EngineError::UnsupportedCapability);
                }
                AssociationBinding::H3(
                    self.inner
                        .run_operation(
                            SessionOperation::Open,
                            session.open_datagram(
                                &self.inner.proxy,
                                destination,
                                &self.inner.credential,
                                generation,
                                deadline,
                            ),
                        )
                        .await?,
                )
            }
        };
        self.inner.check_open()?;
        self.inner.udp_native.store(
            association.delivery_mode() == DeliveryMode::UnreliableNative,
            Ordering::Release,
        );
        self.inner.udp_negotiated.store(true, Ordering::Release);
        Ok(Association {
            binding: association,
            session: Arc::clone(&self.inner),
        })
    }

    /// Requests cancellation of the transport and its flows without waiting.
    /// Repeated calls retain a completed close result, if one exists.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Stops new opens and waits for transport cleanup.
    ///
    /// The active closer selects the mode and effective drain deadline. Concurrent
    /// callers wait for its stored result under their own deadlines; later calls
    /// return that result. A drain timeout forces cancellation, then waits for
    /// cleanup, which can outlive the deadline. Other transport failures are errors.
    /// Dropping the active close future requests cancellation and permits a later
    /// close call to finish cleanup. Retained buffers keep their memory charges.
    pub async fn close(
        &self,
        mode: CloseMode,
        deadline: Deadline,
    ) -> Result<CloseOutcome, EngineError> {
        let mut changed = self.inner.state.subscribe();
        loop {
            if let Some(result) = changed.borrow().close_result {
                return result;
            }
            if self
                .inner
                .close_started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
            deadline
                .run(async { changed.changed().await.map_err(|_| EngineError::Cancelled) })
                .await?;
        }
        let mut guard = CloseOperation {
            inner: Arc::clone(&self.inner),
            complete: false,
        };
        let forced = mode == CloseMode::Immediate || self.phase() == SessionPhase::Cancelled;
        if forced {
            self.inner.cancel();
        } else {
            self.inner.drain();
        }
        let mut result = match self.inner.binding.close(deadline).await {
            Ok(()) => Ok(if forced {
                CloseOutcome::Forced
            } else {
                CloseOutcome::Graceful
            }),
            Err(EngineError::Cancelled) => Ok(CloseOutcome::Forced),
            Err(EngineError::DeadlineExceeded) => {
                self.inner.cancel();
                Ok(CloseOutcome::Forced)
            }
            Err(error) => Err(error),
        };
        if let Err(error) = self.inner.join_completion().await
            && result.is_ok()
        {
            result = Err(error);
        }
        self.inner.finish_close(result);
        guard.complete = true;
        result
    }
}

struct CloseOperation {
    inner: Arc<SessionInner>,
    complete: bool,
}

impl Drop for CloseOperation {
    fn drop(&mut self) {
        if !self.complete {
            // Clear ownership before cancel publishes a state change, so waiting closers can retry.
            self.inner.close_started.store(false, Ordering::Release);
            self.inner.cancel();
        }
    }
}

enum StreamBinding {
    H2(H2Connect),
    #[cfg(feature = "h3")]
    H3(H3Connect),
}

impl StreamBinding {
    fn control(&self) -> StreamBindingControl {
        match self {
            Self::H2(stream) => StreamBindingControl::H2(stream.control()),
            #[cfg(feature = "h3")]
            Self::H3(stream) => StreamBindingControl::H3(stream.control()),
        }
    }

    fn reserve_metadata(&self, bytes: usize) -> Result<ScopedMemoryReservation, EngineError> {
        match self {
            Self::H2(stream) => stream.reserve_metadata(bytes),
            #[cfg(feature = "h3")]
            Self::H3(stream) => stream.reserve_metadata(bytes),
        }
    }

    fn cancel(&mut self) {
        match self {
            Self::H2(stream) => {
                let _ = stream.cancel();
            }
            #[cfg(feature = "h3")]
            Self::H3(stream) => {
                let _ = stream.cancel();
            }
        }
    }
}

enum StreamBindingControl {
    H2(H2StreamControl),
    #[cfg(feature = "h3")]
    H3(H3StreamControl),
}

impl StreamBindingControl {
    fn cancel(&self) {
        match self {
            Self::H2(control) => {
                let _ = control.cancel();
            }
            #[cfg(feature = "h3")]
            Self::H3(control) => {
                let _ = control.cancel();
            }
        }
    }

    fn reset(&self) -> Result<(), EngineError> {
        match self {
            Self::H2(control) => control.reset(),
            #[cfg(feature = "h3")]
            Self::H3(control) => control.reset(),
        }
    }
}

// Conservative allowance for the watch channel and Arc allocation headers.
const STREAM_CONTROL_METADATA_OVERHEAD: usize = 1024;

struct StreamState {
    binding: StreamBindingControl,
    session: Arc<SessionInner>,
    terminal: watch::Sender<Option<EngineError>>,
    memory: Arc<ScopedMemoryReservation>,
}

impl StreamState {
    fn control(self: &Arc<Self>) -> StreamControl {
        StreamControl {
            state: Arc::downgrade(self),
            _memory: Arc::clone(&self.memory),
        }
    }

    fn check_io(&self) -> Result<(), EngineError> {
        if let Some(error) = *self.terminal.borrow() {
            return Err(error);
        }
        let state = *self.session.state.borrow();
        state.check_io()
    }

    fn record_terminal(&self, error: EngineError) {
        self.terminal.send_if_modified(|terminal| {
            if terminal.is_some() {
                false
            } else {
                *terminal = Some(error);
                true
            }
        });
    }

    fn record_read_result(
        &self,
        result: Result<ReadOutcome, EngineError>,
    ) -> Result<ReadOutcome, EngineError> {
        // A write transport error can leave readable data. Reads resolve the terminal cause.
        match result {
            Ok(ReadOutcome::Reset) | Err(EngineError::RemoteReset) => {
                self.record_terminal(EngineError::RemoteReset);
            }
            Ok(ReadOutcome::Truncated) | Err(EngineError::TruncatedStream) => {
                self.record_terminal(EngineError::TruncatedStream);
            }
            Err(EngineError::TransportUnavailable) => {
                self.record_terminal(EngineError::TransportUnavailable);
            }
            _ => {}
        }
        result
    }

    fn cancel_io(&self, error: EngineError) {
        // Publish the reason before native cancellation wakes the other half.
        self.record_terminal(error);
        self.binding.cancel();
    }

    async fn run_io<T>(
        self: &Arc<Self>,
        deadline: Deadline,
        io: impl Future<Output = Result<T, EngineError>>,
    ) -> Result<T, EngineError> {
        self.check_io()?;
        deadline.remaining()?;
        let mut session_cancellation = self.session.state.subscribe();
        let mut stream_cancellation = self.terminal.subscribe();
        let mut operation = StreamOperation {
            control: self.control(),
            complete: false,
        };
        let result = tokio::select! {
            biased;
            error = wait_stream_interrupt(&mut stream_cancellation) => Err(error),
            error = wait_session_interrupt(&mut session_cancellation, SessionOperation::Io) => Err(error),
            result = io => result,
        };
        operation.complete = true;
        match result {
            Err(error @ (EngineError::DeadlineExceeded | EngineError::Cancelled)) => {
                self.cancel_io(error);
            }
            Err(EngineError::RemoteReset) => self.record_terminal(EngineError::RemoteReset),
            _ => {}
        }
        result
    }

    async fn run_read_io(
        self: &Arc<Self>,
        deadline: Deadline,
        io: impl Future<Output = Result<ReadOutcome, EngineError>>,
    ) -> Result<ReadOutcome, EngineError> {
        match self.record_read_result(self.run_io(deadline, io).await) {
            Err(EngineError::Cancelled) => Ok(ReadOutcome::Cancelled),
            Err(EngineError::RemoteReset) => Ok(ReadOutcome::Reset),
            Err(EngineError::TruncatedStream) => Ok(ReadOutcome::Truncated),
            result => result,
        }
    }
}

/// Cancels or resets a stream while either I/O half is borrowed.
///
/// Clones do not retain the session or flow admission. The shared metadata charge
/// remains until the last I/O owner and control clone drop.
#[derive(Clone)]
pub struct StreamControl {
    state: Weak<StreamState>,
    _memory: Arc<ScopedMemoryReservation>,
}

impl StreamControl {
    /// Cancels both directions and wakes pending I/O. Has no effect after all I/O owners drop.
    /// Retained receive allocations can remain charged until the reader observes cancellation.
    pub fn cancel(&self) {
        if let Some(state) = self.state.upgrade() {
            state.terminal.send_replace(Some(EngineError::Cancelled));
            state.binding.cancel();
        }
    }

    /// Resets both directions. Reads report `Reset`; writes return `RemoteReset`.
    /// Returns `Cancelled` after all I/O owners drop.
    pub fn reset(&self) -> Result<(), EngineError> {
        let state = self.state.upgrade().ok_or(EngineError::Cancelled)?;
        state.check_io()?;
        state.binding.reset()?;
        state.terminal.send_replace(Some(EngineError::RemoteReset));
        Ok(())
    }
}

struct StreamDropGuard {
    control: StreamControl,
    armed: bool,
}

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if self.armed {
            self.control.cancel();
        }
    }
}

/// One accepted TCP tunnel that retains its session.
///
/// A deadline exhausted before I/O starts leaves the stream unchanged. Timeout,
/// cancellation, or dropping an I/O future after it starts cancels the stream.
/// Bytes accepted by earlier polls cannot be recalled. Dropping this handle also
/// requests cancellation of its binding stream. Use [`Self::into_split`] for
/// concurrent reads and writes; operation cancellation still affects both halves.
/// Dropping another pending operation preserves an existing terminal error.
/// Calling `cancel` explicitly records `Cancelled`.
pub struct Stream {
    // Cancel before the binding drops. Splitting disarms this guard.
    drop_guard: StreamDropGuard,
    binding: StreamBinding,
    state: Arc<StreamState>,
}

impl fmt::Debug for Stream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Stream")
            .field("terminal", &*self.state.terminal.borrow())
            .finish_non_exhaustive()
    }
}

impl Stream {
    fn new(binding: StreamBinding, session: Arc<SessionInner>) -> Result<Self, EngineError> {
        let memory = Arc::new(binding.reserve_metadata(
            std::mem::size_of::<StreamState>() + STREAM_CONTROL_METADATA_OVERHEAD,
        )?);
        let (terminal, _) = watch::channel(None);
        let state = Arc::new(StreamState {
            binding: binding.control(),
            session,
            terminal,
            memory,
        });
        Ok(Self {
            drop_guard: StreamDropGuard {
                control: state.control(),
                armed: true,
            },
            binding,
            state,
        })
    }

    /// Returns a control handle that can interrupt I/O without borrowing the stream.
    pub fn control(&self) -> StreamControl {
        self.state.control()
    }

    /// Transfers the stream into independently usable read and write owners.
    ///
    /// Each half retains the session. Call [`StreamWriteHalf::end_write`] before
    /// dropping the writer to send FIN on either binding and leave the reader usable.
    /// Dropping the last unfinished I/O owner requests a binding reset.
    pub fn into_split(self) -> (StreamReadHalf, StreamWriteHalf) {
        let Self {
            mut drop_guard,
            binding,
            state,
        } = self;
        drop_guard.armed = false;
        let (read, write) = match binding {
            StreamBinding::H2(stream) => {
                let (read, write) = stream.into_split();
                (StreamReadBinding::H2(read), StreamWriteBinding::H2(write))
            }
            #[cfg(feature = "h3")]
            StreamBinding::H3(stream) => {
                let (read, write) = stream.into_split();
                (StreamReadBinding::H3(read), StreamWriteBinding::H3(write))
            }
        };
        (
            StreamReadHalf {
                binding: read,
                state: Arc::clone(&state),
            },
            StreamWriteHalf {
                binding: write,
                state,
            },
        )
    }

    /// Accepts a prefix of nonempty `bytes` into the transport.
    ///
    /// The count can be smaller than the input length and denotes local acceptance.
    /// Peer delivery can remain unknown after a timeout or other failure.
    pub async fn write(&mut self, bytes: &[u8], deadline: Deadline) -> Result<usize, EngineError> {
        self.state
            .run_io(deadline, async {
                match &mut self.binding {
                    StreamBinding::H2(stream) => deadline.run(stream.write(bytes)).await,
                    #[cfg(feature = "h3")]
                    StreamBinding::H3(stream) => stream.write(bytes, deadline).await,
                }
            })
            .await
    }

    /// Accepts all `bytes` under one absolute deadline.
    ///
    /// Success reports local acceptance. Peer delivery can remain unknown. A failure
    /// can follow an accepted prefix; do not replay the full input after failure.
    /// Timeout or dropping a started helper cancels the stream. Call [`Self::end_write`]
    /// separately to send FIN. Empty input checks stream state and the deadline.
    pub async fn write_all(
        &mut self,
        mut bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), EngineError> {
        let state = Arc::clone(&self.state);
        // Native writes use one operation guard so timeout keeps its terminal cause.
        state
            .run_io(
                deadline,
                deadline.run(async {
                    while !bytes.is_empty() {
                        self.state.check_io()?;
                        deadline.remaining()?;
                        let written = match &mut self.binding {
                            StreamBinding::H2(stream) => stream.write(bytes).await?,
                            #[cfg(feature = "h3")]
                            StreamBinding::H3(stream) => stream.write(bytes, deadline).await?,
                        };
                        if written == 0 {
                            return Err(EngineError::TransferStalled);
                        }
                        bytes = bytes.get(written..).ok_or(EngineError::ProtocolViolation)?;
                    }
                    Ok(())
                }),
            )
            .await
    }

    /// Waits for data or a terminal read outcome.
    ///
    /// `Data(count)` identifies the received prefix of `out`. Buffered data and
    /// EOF or truncation can remain observable after transport closure. A timeout can
    /// follow a poll that already changed `out`; only `Data` reports received bytes.
    pub async fn read(
        &mut self,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<ReadOutcome, EngineError> {
        self.state
            .run_read_io(deadline, async {
                match &mut self.binding {
                    StreamBinding::H2(stream) => deadline.run(stream.read(out)).await,
                    #[cfg(feature = "h3")]
                    StreamBinding::H3(stream) => stream.read(out, deadline).await,
                }
            })
            .await
    }

    /// Fills `out` under one absolute deadline.
    ///
    /// EOF before `out` is full returns `TruncatedStream`. Reset and cancellation
    /// return `RemoteReset` and `Cancelled`. Failure can leave a changed prefix in
    /// `out`; its length is not reported. Timeout or dropping a started helper cancels
    /// the stream. Empty output checks stream state and the deadline.
    pub async fn read_exact(
        &mut self,
        mut out: &mut [u8],
        deadline: Deadline,
    ) -> Result<(), EngineError> {
        let state = Arc::clone(&self.state);
        state
            .run_io(
                deadline,
                deadline.run(async move {
                    while !out.is_empty() {
                        self.state.check_io()?;
                        deadline.remaining()?;
                        let result = match &mut self.binding {
                            StreamBinding::H2(stream) => stream.read(out).await,
                            #[cfg(feature = "h3")]
                            StreamBinding::H3(stream) => stream.read(out, deadline).await,
                        };
                        let outcome = self.state.record_read_result(result)?;
                        let received = exact_read_progress(outcome)?;
                        out = out
                            .get_mut(received..)
                            .ok_or(EngineError::ProtocolViolation)?;
                    }
                    Ok(())
                }),
            )
            .await
    }

    /// Ends the write direction after previously accepted bytes.
    /// The read direction remains available.
    pub async fn end_write(&mut self, deadline: Deadline) -> Result<(), EngineError> {
        self.state
            .run_io(deadline, async {
                match &mut self.binding {
                    StreamBinding::H2(stream) => deadline.run(stream.end_write()).await,
                    #[cfg(feature = "h3")]
                    StreamBinding::H3(stream) => stream.end_write(deadline).await,
                }
            })
            .await
    }

    /// Discards buffered reads and requests a stream reset.
    /// On success, later reads report `Reset` and writes return `RemoteReset`.
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.state.check_io()?;
        match &mut self.binding {
            StreamBinding::H2(stream) => stream.reset()?,
            #[cfg(feature = "h3")]
            StreamBinding::H3(stream) => stream.reset()?,
        }
        self.state
            .terminal
            .send_replace(Some(EngineError::RemoteReset));
        Ok(())
    }

    /// Discards buffered reads and requests cancellation without waiting.
    /// Later reads report `Cancelled`; other I/O returns that error.
    pub fn cancel(&mut self) {
        self.binding.cancel();
        self.state
            .terminal
            .send_replace(Some(EngineError::Cancelled));
    }
}

enum StreamReadBinding {
    H2(H2ReadHalf),
    #[cfg(feature = "h3")]
    H3(H3ReadHalf),
}

/// The read direction returned by [`Stream::into_split`].
///
/// Reads can run while the writer waits. Deadlines and destructive operation
/// cancellation follow [`Stream`]. Dropping this half abandons unread data;
/// the write owner retains its direction and the session.
pub struct StreamReadHalf {
    binding: StreamReadBinding,
    state: Arc<StreamState>,
}

impl StreamReadHalf {
    /// Returns a control handle for both directions without borrowing either half.
    pub fn control(&self) -> StreamControl {
        self.state.control()
    }

    /// Reads with the outcomes and cancellation contract of [`Stream::read`].
    pub async fn read(
        &mut self,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<ReadOutcome, EngineError> {
        self.state
            .run_read_io(deadline, async {
                match &mut self.binding {
                    StreamReadBinding::H2(stream) => deadline.run(stream.read(out)).await,
                    #[cfg(feature = "h3")]
                    StreamReadBinding::H3(stream) => stream.read(out, deadline).await,
                }
            })
            .await
    }

    /// Fills `out` with the progress, deadline, and cancellation contract of [`Stream::read_exact`].
    pub async fn read_exact(
        &mut self,
        mut out: &mut [u8],
        deadline: Deadline,
    ) -> Result<(), EngineError> {
        let state = Arc::clone(&self.state);
        state
            .run_io(
                deadline,
                deadline.run(async move {
                    while !out.is_empty() {
                        self.state.check_io()?;
                        deadline.remaining()?;
                        let result = match &mut self.binding {
                            StreamReadBinding::H2(stream) => stream.read(out).await,
                            #[cfg(feature = "h3")]
                            StreamReadBinding::H3(stream) => stream.read(out, deadline).await,
                        };
                        let outcome = self.state.record_read_result(result)?;
                        let received = exact_read_progress(outcome)?;
                        out = out
                            .get_mut(received..)
                            .ok_or(EngineError::ProtocolViolation)?;
                    }
                    Ok(())
                }),
            )
            .await
    }

    /// Resets both directions as in [`Stream::reset`].
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.state.check_io()?;
        match &mut self.binding {
            StreamReadBinding::H2(stream) => stream.reset()?,
            #[cfg(feature = "h3")]
            StreamReadBinding::H3(stream) => stream.reset()?,
        }
        self.state
            .terminal
            .send_replace(Some(EngineError::RemoteReset));
        Ok(())
    }

    /// Cancels both directions as in [`Stream::cancel`].
    pub fn cancel(&mut self) {
        match &mut self.binding {
            StreamReadBinding::H2(stream) => {
                let _ = stream.cancel();
            }
            #[cfg(feature = "h3")]
            StreamReadBinding::H3(stream) => {
                let _ = stream.cancel();
            }
        }
        self.state
            .terminal
            .send_replace(Some(EngineError::Cancelled));
    }
}

enum StreamWriteBinding {
    H2(H2WriteHalf),
    #[cfg(feature = "h3")]
    H3(H3WriteHalf),
}

/// The write direction returned by [`Stream::into_split`].
///
/// Writes can run while the reader waits. Deadlines and destructive operation
/// cancellation follow [`Stream`]. Call [`Self::end_write`] before dropping this
/// half to send FIN on either binding; the reader remains usable after success.
pub struct StreamWriteHalf {
    binding: StreamWriteBinding,
    state: Arc<StreamState>,
}

impl StreamWriteHalf {
    /// Returns a control handle for both directions without borrowing either half.
    pub fn control(&self) -> StreamControl {
        self.state.control()
    }

    /// Accepts a prefix with the delivery and cancellation contract of [`Stream::write`].
    pub async fn write(&mut self, bytes: &[u8], deadline: Deadline) -> Result<usize, EngineError> {
        self.state
            .run_io(deadline, async {
                match &mut self.binding {
                    StreamWriteBinding::H2(stream) => deadline.run(stream.write(bytes)).await,
                    #[cfg(feature = "h3")]
                    StreamWriteBinding::H3(stream) => stream.write(bytes, deadline).await,
                }
            })
            .await
    }

    /// Accepts all `bytes` with the delivery and cancellation contract of [`Stream::write_all`].
    pub async fn write_all(
        &mut self,
        mut bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), EngineError> {
        let state = Arc::clone(&self.state);
        state
            .run_io(
                deadline,
                deadline.run(async {
                    while !bytes.is_empty() {
                        self.state.check_io()?;
                        deadline.remaining()?;
                        let written = match &mut self.binding {
                            StreamWriteBinding::H2(stream) => stream.write(bytes).await?,
                            #[cfg(feature = "h3")]
                            StreamWriteBinding::H3(stream) => stream.write(bytes, deadline).await?,
                        };
                        if written == 0 {
                            return Err(EngineError::TransferStalled);
                        }
                        bytes = bytes.get(written..).ok_or(EngineError::ProtocolViolation)?;
                    }
                    Ok(())
                }),
            )
            .await
    }

    /// Sends FIN after accepted bytes, leaving the read direction available.
    /// Interruption after I/O starts cancels both halves.
    pub async fn end_write(&mut self, deadline: Deadline) -> Result<(), EngineError> {
        self.state
            .run_io(deadline, async {
                match &mut self.binding {
                    StreamWriteBinding::H2(stream) => deadline.run(stream.end_write()).await,
                    #[cfg(feature = "h3")]
                    StreamWriteBinding::H3(stream) => stream.end_write(deadline).await,
                }
            })
            .await
    }

    /// Resets both directions as in [`Stream::reset`].
    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.control().reset()
    }

    /// Cancels both directions as in [`Stream::cancel`].
    pub fn cancel(&mut self) {
        self.control().cancel();
    }
}

fn exact_read_progress(outcome: ReadOutcome) -> Result<usize, EngineError> {
    match outcome {
        ReadOutcome::Data(0) | ReadOutcome::Waiting => Err(EngineError::TransferStalled),
        ReadOutcome::Data(count) => Ok(count),
        ReadOutcome::Eof | ReadOutcome::Truncated => Err(EngineError::TruncatedStream),
        ReadOutcome::Reset => Err(EngineError::RemoteReset),
        ReadOutcome::Cancelled => Err(EngineError::Cancelled),
    }
}

async fn wait_stream_interrupt(receiver: &mut watch::Receiver<Option<EngineError>>) -> EngineError {
    loop {
        if let Some(error) = *receiver.borrow() {
            return error;
        }
        if receiver.changed().await.is_err() {
            return EngineError::Cancelled;
        }
    }
}

struct StreamOperation {
    control: StreamControl,
    complete: bool,
}

impl Drop for StreamOperation {
    fn drop(&mut self) {
        if !self.complete
            && let Some(state) = self.control.state.upgrade()
        {
            state.cancel_io(EngineError::Cancelled);
        }
    }
}

#[cfg_attr(
    feature = "h3",
    expect(
        clippy::large_enum_variant,
        reason = "Keep H2 handles inline to avoid an unbudgeted heap allocation."
    )
)]
enum AssociationBinding {
    H2(DatagramAssociation),
    #[cfg(feature = "h3")]
    H3(H3DatagramAssociation),
}

impl AssociationBinding {
    fn delivery_mode(&self) -> DeliveryMode {
        match self {
            Self::H2(association) => association.delivery_mode(),
            #[cfg(feature = "h3")]
            Self::H3(association) => association.delivery_mode(),
        }
    }
    fn max_payload(&self) -> usize {
        match self {
            Self::H2(association) => association.max_payload(),
            #[cfg(feature = "h3")]
            Self::H3(association) => association.max_payload(),
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::H2(association) => association.generation(),
            #[cfg(feature = "h3")]
            Self::H3(association) => association.generation(),
        }
    }
    fn cancel(&mut self) -> Result<(), EngineError> {
        match self {
            Self::H2(association) => association.cancel(),
            #[cfg(feature = "h3")]
            Self::H3(association) => association.cancel(),
        }
    }
    fn close(&mut self) -> Result<(), EngineError> {
        match self {
            Self::H2(association) => association.close(),
            #[cfg(feature = "h3")]
            Self::H3(association) => association.close(),
        }
    }
    async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        match self {
            Self::H2(association) => association.send(payload, deadline).await,
            #[cfg(feature = "h3")]
            Self::H3(association) => association.send(payload, deadline).await,
        }
    }
    async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        match self {
            Self::H2(association) => association.recv(deadline).await,
            #[cfg(feature = "h3")]
            Self::H3(association) => association.recv(deadline).await,
        }
    }
}

/// One negotiated CONNECT-UDP route that retains its session.
///
/// Messages use reliable capsules on H2 or native datagrams on H3. Received
/// payloads own their bytes and keep memory charged until all owners drop them.
pub struct Association {
    binding: AssociationBinding,
    session: Arc<SessionInner>,
}

impl fmt::Debug for Association {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Association")
            .field("delivery_mode", &self.delivery_mode())
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl Association {
    /// Returns a control handle that can close both directions during pending I/O.
    pub fn control(&self) -> AssociationControl {
        let binding = match &self.binding {
            AssociationBinding::H2(association) => {
                AssociationBindingControl::H2(association.control())
            }
            #[cfg(feature = "h3")]
            AssociationBinding::H3(association) => {
                AssociationBindingControl::H3(association.control())
            }
        };
        AssociationControl { binding }
    }

    /// Transfers the association into independent send and receive owners.
    /// Each half retains the session. Closing or cancelling either affects both.
    /// The transport-specific interruption contracts of `send` and `recv` still apply.
    pub fn into_split(self) -> (AssociationSendHalf, AssociationRecvHalf) {
        let (send, recv) = match self.binding {
            AssociationBinding::H2(association) => {
                let (send, recv) = association.into_split();
                (
                    AssociationSendBinding::H2(send),
                    AssociationRecvBinding::H2(recv),
                )
            }
            #[cfg(feature = "h3")]
            AssociationBinding::H3(association) => {
                let (send, recv) = association.into_split();
                (
                    AssociationSendBinding::H3(send),
                    AssociationRecvBinding::H3(recv),
                )
            }
        };
        (
            AssociationSendHalf {
                binding: send,
                session: Arc::clone(&self.session),
            },
            AssociationRecvHalf {
                binding: recv,
                session: self.session,
            },
        )
    }

    /// Reports the delivery mode negotiated for this association.
    pub fn delivery_mode(&self) -> DeliveryMode {
        self.binding.delivery_mode()
    }
    /// Returns the current maximum payload length in bytes.
    pub fn max_payload(&self) -> usize {
        self.binding.max_payload()
    }
    /// Returns this association's generation within its session.
    pub fn generation(&self) -> u64 {
        self.binding.generation()
    }

    /// Submits one complete message no larger than `max_payload`.
    ///
    /// `Queued` denotes local acceptance; `Dropped` denotes bounded admission or
    /// queue rejection. Interrupting a reliable capsule send cancels the association.
    /// A native datagram already queued can still be sent after this future is dropped.
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        let result = self
            .session
            .run_operation(SessionOperation::Io, self.binding.send(payload, deadline))
            .await;
        if matches!(result, Err(EngineError::Cancelled)) {
            let _ = self.binding.cancel();
        }
        result
    }

    /// Returns one complete payload whose memory charge follows its owned bytes.
    ///
    /// Interrupting a reliable capsule receive cancels the association. A native
    /// receive timeout can leave it usable. Interrupted receives can consume a message.
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        let result = self
            .session
            .run_operation(SessionOperation::Io, self.binding.recv(deadline))
            .await;
        if matches!(result, Err(EngineError::Cancelled)) {
            let _ = self.binding.cancel();
        }
        result
    }

    /// Discards queued receives and requests stream closure without waiting.
    /// Local closure is idempotent, including after a transport error.
    pub fn close(&mut self) -> Result<(), EngineError> {
        self.binding.close()
    }
    /// Discards queued receives and requests cancellation without waiting.
    /// Repeated calls succeed after local closure.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.binding.cancel()
    }
}

#[derive(Clone)]
enum AssociationBindingControl {
    H2(DatagramControl),
    #[cfg(feature = "h3")]
    H3(H3DatagramControl),
}

/// Closes an association while either I/O half is borrowed.
///
/// Clones retain control metadata, but do not retain native flow admission.
/// Receive allocations can remain charged until the receiver observes closure or drops.
#[derive(Clone)]
pub struct AssociationControl {
    binding: AssociationBindingControl,
}

impl AssociationControl {
    /// Requests closure of both halves without waiting for peer acknowledgment.
    /// Can return `Cancelled` after all I/O owners drop.
    pub fn close(&self) -> Result<(), EngineError> {
        match &self.binding {
            AssociationBindingControl::H2(control) => control.close(),
            #[cfg(feature = "h3")]
            AssociationBindingControl::H3(control) => control.close(),
        }
    }

    /// Requests cancellation of both halves and wakes pending I/O.
    /// Can return `Cancelled` after all I/O owners drop.
    pub fn cancel(&self) -> Result<(), EngineError> {
        match &self.binding {
            AssociationBindingControl::H2(control) => control.cancel(),
            #[cfg(feature = "h3")]
            AssociationBindingControl::H3(control) => control.cancel(),
        }
    }
}

enum AssociationSendBinding {
    H2(DatagramSendHalf),
    #[cfg(feature = "h3")]
    H3(H3DatagramSendHalf),
}

/// The send direction returned by [`Association::into_split`].
/// A pending receive does not block this half. Send interruption follows [`Association::send`].
pub struct AssociationSendHalf {
    binding: AssociationSendBinding,
    session: Arc<SessionInner>,
}

impl AssociationSendHalf {
    /// Reports the delivery mode negotiated for this association.
    pub fn delivery_mode(&self) -> DeliveryMode {
        match &self.binding {
            AssociationSendBinding::H2(association) => association.delivery_mode(),
            #[cfg(feature = "h3")]
            AssociationSendBinding::H3(association) => association.delivery_mode(),
        }
    }

    /// Returns the current maximum payload length in bytes.
    pub fn max_payload(&self) -> usize {
        match &self.binding {
            AssociationSendBinding::H2(association) => association.max_payload(),
            #[cfg(feature = "h3")]
            AssociationSendBinding::H3(association) => association.max_payload(),
        }
    }

    /// Returns this association's generation within its session.
    pub fn generation(&self) -> u64 {
        match &self.binding {
            AssociationSendBinding::H2(association) => association.generation(),
            #[cfg(feature = "h3")]
            AssociationSendBinding::H3(association) => association.generation(),
        }
    }

    /// Returns a control handle for both directions without borrowing either half.
    pub fn control(&self) -> AssociationControl {
        let binding = match &self.binding {
            AssociationSendBinding::H2(association) => {
                AssociationBindingControl::H2(association.control())
            }
            #[cfg(feature = "h3")]
            AssociationSendBinding::H3(association) => {
                AssociationBindingControl::H3(association.control())
            }
        };
        AssociationControl { binding }
    }

    /// Submits one complete message with the contract of [`Association::send`].
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        let result = self
            .session
            .run_operation(SessionOperation::Io, async {
                match &mut self.binding {
                    AssociationSendBinding::H2(association) => {
                        association.send(payload, deadline).await
                    }
                    #[cfg(feature = "h3")]
                    AssociationSendBinding::H3(association) => {
                        association.send(payload, deadline).await
                    }
                }
            })
            .await;
        if matches!(result, Err(EngineError::Cancelled)) {
            let _ = self.control().cancel();
        }
        result
    }

    /// Closes both directions as in [`AssociationControl::close`].
    pub fn close(&mut self) -> Result<(), EngineError> {
        self.control().close()
    }

    /// Cancels both directions as in [`AssociationControl::cancel`].
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.control().cancel()
    }
}

#[cfg_attr(
    feature = "h3",
    expect(
        clippy::large_enum_variant,
        reason = "Keep H2 handles inline to avoid an unbudgeted heap allocation."
    )
)]
enum AssociationRecvBinding {
    H2(DatagramRecvHalf),
    #[cfg(feature = "h3")]
    H3(H3DatagramRecvHalf),
}

/// The receive direction returned by [`Association::into_split`].
/// A pending send does not block this half. Receive interruption follows [`Association::recv`].
pub struct AssociationRecvHalf {
    binding: AssociationRecvBinding,
    session: Arc<SessionInner>,
}

impl AssociationRecvHalf {
    /// Reports the delivery mode negotiated for this association.
    pub fn delivery_mode(&self) -> DeliveryMode {
        match &self.binding {
            AssociationRecvBinding::H2(association) => association.delivery_mode(),
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => association.delivery_mode(),
        }
    }

    /// Returns the current maximum payload length in bytes.
    pub fn max_payload(&self) -> usize {
        match &self.binding {
            AssociationRecvBinding::H2(association) => association.max_payload(),
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => association.max_payload(),
        }
    }

    /// Returns this association's generation within its session.
    pub fn generation(&self) -> u64 {
        match &self.binding {
            AssociationRecvBinding::H2(association) => association.generation(),
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => association.generation(),
        }
    }

    /// Returns a control handle for both directions without borrowing either half.
    pub fn control(&self) -> AssociationControl {
        let binding = match &self.binding {
            AssociationRecvBinding::H2(association) => {
                AssociationBindingControl::H2(association.control())
            }
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => {
                AssociationBindingControl::H3(association.control())
            }
        };
        AssociationControl { binding }
    }

    /// Returns one complete owned payload with the contract of [`Association::recv`].
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        let result = self
            .session
            .run_operation(SessionOperation::Io, async {
                match &mut self.binding {
                    AssociationRecvBinding::H2(association) => association.recv(deadline).await,
                    #[cfg(feature = "h3")]
                    AssociationRecvBinding::H3(association) => association.recv(deadline).await,
                }
            })
            .await;
        if matches!(result, Err(EngineError::Cancelled)) {
            let _ = self.control().cancel();
        }
        result
    }

    /// Closes both directions and releases this half's receive buffers.
    pub fn close(&mut self) -> Result<(), EngineError> {
        match &mut self.binding {
            AssociationRecvBinding::H2(association) => association.close(),
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => association.close(),
        }
    }

    /// Cancels both directions and releases this half's receive buffers.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        match &mut self.binding {
            AssociationRecvBinding::H2(association) => association.cancel(),
            #[cfg(feature = "h3")]
            AssociationRecvBinding::H3(association) => association.cancel(),
        }
    }
}

#[derive(Clone, Copy)]
enum SessionOperation {
    Open,
    Io,
}

async fn wait_session_interrupt(
    receiver: &mut watch::Receiver<SessionState>,
    operation: SessionOperation,
) -> EngineError {
    loop {
        let state = *receiver.borrow();
        match operation {
            SessionOperation::Open => match state.phase {
                SessionPhase::Ready => {}
                SessionPhase::Failed => return EngineError::TransportUnavailable,
                _ => return EngineError::Cancelled,
            },
            SessionOperation::Io => {
                if let Err(error) = state.check_io() {
                    return error;
                }
            }
        }
        if receiver.changed().await.is_err() {
            return EngineError::Cancelled;
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimeState {
    epoch: NetworkEpoch,
    stopping: bool,
}

impl RuntimeState {
    fn is_cancelled(self, epoch: NetworkEpoch) -> bool {
        self.stopping || self.epoch != epoch
    }
}

/// A resource pool for transport application memory and object quotas.
///
/// Each engine creates its own pool by default. Supplying the same pool to several
/// engines shares their memory, flow, open, session, and handshake caps. Memory
/// accounting covers charged application allocations and retained owners; it does
/// not measure process RSS or cap all allocations in transport dependencies.
/// Usage counters are sampled independently and can change between calls.
#[derive(Debug)]
pub struct EngineResources {
    application_memory: MemoryBudget,
    flow_slots: ResourceBudget,
    open_slots: ResourceBudget,
    session_slots: ResourceBudget,
    handshake_slots: ResourceBudget,
}

impl EngineResources {
    /// Creates fixed caps from validated limits.
    ///
    /// Flow and open totals are `active_sessions` times their per-session limits.
    /// These totals stay fixed when attached engines use different per-session
    /// limits. Returns `InvalidConfig` for invalid limits or overflowing totals.
    pub fn new(limits: BudgetLimits) -> Result<Self, EngineError> {
        limits.validate()?;
        let flows = limits
            .active_sessions
            .checked_mul(limits.active_flows_per_session)
            .ok_or(EngineError::InvalidConfig)?;
        let opens = limits
            .active_sessions
            .checked_mul(limits.pending_egress_opens)
            .ok_or(EngineError::InvalidConfig)?;
        Ok(Self {
            application_memory: MemoryBudget::new(limits.global_application_budget)?,
            flow_slots: ResourceBudget::new(flows)?,
            open_slots: ResourceBudget::new(opens)?,
            session_slots: ResourceBudget::new(limits.active_sessions)?,
            handshake_slots: ResourceBudget::new(limits.pending_handshakes)?,
        })
    }

    /// Returns the current charge for retained application allocations, in bytes.
    pub fn application_memory_used(&self) -> usize {
        self.application_memory.used()
    }

    /// Returns the number of currently reserved flow slots.
    pub fn active_flows(&self) -> usize {
        self.flow_slots.used()
    }

    /// Returns the number of currently reserved egress open slots.
    pub fn pending_opens(&self) -> usize {
        self.open_slots.used()
    }

    /// Returns the number of currently reserved session slots, including pending connects.
    pub fn active_sessions(&self) -> usize {
        self.session_slots.used()
    }

    /// Returns the number of currently reserved handshake slots.
    pub fn pending_handshakes(&self) -> usize {
        self.handshake_slots.used()
    }

    fn check_limits(&self, limits: BudgetLimits) -> Result<(), EngineError> {
        if limits.global_application_budget != self.application_memory.limit()
            || limits.active_sessions != self.session_slots.limit()
            || limits.pending_handshakes != self.handshake_slots.limit()
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }
}

pub(crate) struct EngineRuntime {
    limits: BudgetLimits,
    resources: Arc<EngineResources>,
    state: watch::Sender<RuntimeState>,
    sessions: Mutex<Vec<Weak<SessionInner>>>,
    pending_connections: ResourceBudget,
    pending_changed: Notify,
    retired: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    spawner: Mutex<Option<tokio::runtime::Handle>>,
}

impl EngineRuntime {
    pub(crate) fn new(config: EngineConfig) -> Result<Arc<Self>, EngineError> {
        let resources = Arc::new(EngineResources::new(config.limits)?);
        Self::new_with_resources(config, resources)
    }

    pub(crate) fn new_with_resources(
        config: EngineConfig,
        resources: Arc<EngineResources>,
    ) -> Result<Arc<Self>, EngineError> {
        let limits = config.limits;
        limits.validate()?;
        resources.check_limits(limits)?;
        let (state, _) = watch::channel(RuntimeState {
            epoch: NetworkEpoch::start(),
            stopping: false,
        });
        Ok(Arc::new(Self {
            limits,
            state,
            sessions: Mutex::new(Vec::new()),
            pending_connections: ResourceBudget::new(limits.pending_handshakes)?,
            pending_changed: Notify::new(),
            resources,
            retired: Mutex::new(Vec::new()),
            spawner: Mutex::new(None),
        }))
    }

    pub(crate) fn resources(&self) -> Arc<EngineResources> {
        Arc::clone(&self.resources)
    }

    pub(crate) fn epoch(&self) -> NetworkEpoch {
        self.state.borrow().epoch
    }

    pub(crate) fn begin_connect(self: &Arc<Self>) -> Result<ConnectionPermit, EngineError> {
        let state = *self.state.borrow();
        if state.stopping {
            return Err(EngineError::Cancelled);
        }
        let slot = self.resources.session_slots.try_acquire()?;
        let handshake = self
            .resources
            .handshake_slots
            .try_acquire_scoped(&self.pending_connections)?;
        let permit = ConnectionPermit {
            runtime: Arc::clone(self),
            slot: Some(slot),
            handshake: Some(handshake),
            epoch: state.epoch,
        };
        // Quota reservation does not lock runtime state.
        // Stop or epoch change can occur between reads.
        let latest = *self.state.borrow();
        if latest.is_cancelled(state.epoch) {
            return Err(EngineError::Cancelled);
        }
        Ok(permit)
    }

    pub(crate) fn h2_config(&self) -> Result<H2Config, EngineError> {
        let limits = self.limits;
        let max_pending_opens = limits
            .pending_egress_opens
            .min(limits.active_flows_per_session);
        let config = H2Config {
            direction_buffer_bytes: limits.stream_queue_per_direction,
            max_header_bytes: limits.decoded_header_bytes,
            max_header_count: limits.decoded_header_fields,
            max_concurrent_streams: limits.active_flows_per_session,
            max_pending_opens,
            control_reserve_bytes: limits.control_reserve,
            header_table_bytes: limits.decoded_header_bytes.min(4096) as u32,
            initial_connection_window: limits
                .session_application_budget
                .saturating_sub(limits.control_reserve)
                .min(1024 * 1024) as u32,
            process_budget: self.resources.application_memory.clone(),
            session_budget: MemoryBudget::new(limits.session_application_budget)?,
            process_flows: self.resources.flow_slots.clone(),
            session_flows: ResourceBudget::new(limits.active_flows_per_session)?,
            process_opens: self.resources.open_slots.clone(),
            session_opens: ResourceBudget::new(max_pending_opens)?,
            ..H2Config::default()
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn register(&self, session: &Session) -> Result<(), EngineError> {
        let spawner =
            tokio::runtime::Handle::try_current().map_err(|_| EngineError::InvalidConfig)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| EngineError::TransportUnavailable)?;
        let state = *self.state.borrow();
        if state.is_cancelled(session.network_epoch()) {
            return Err(EngineError::Cancelled);
        }
        sessions.retain(|weak| {
            weak.upgrade().is_some_and(|session| {
                session
                    .slot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .is_some()
            })
        });
        sessions
            .try_reserve(1)
            .map_err(|_| EngineError::ResourceLimitExceeded)?;
        *self
            .spawner
            .lock()
            .map_err(|_| EngineError::TransportUnavailable)? = Some(spawner);
        sessions.push(Arc::downgrade(&session.inner));
        Ok(())
    }

    pub(crate) fn on_network_change(&self, epoch: NetworkEpoch) -> Result<(), EngineError> {
        let mut result = Ok(());
        let mut changed = false;
        self.state.send_modify(|state| {
            if state.stopping {
                result = Err(EngineError::Cancelled);
            } else if epoch.get() < state.epoch.get() {
                result = Err(EngineError::InvalidConfig);
            } else {
                changed = epoch != state.epoch;
                state.epoch = epoch;
            }
        });
        result?;
        if changed {
            let mut retired = self
                .retired
                .lock()
                .map_err(|_| EngineError::TransportUnavailable)?;
            let spawner = self
                .spawner
                .lock()
                .map_err(|_| EngineError::TransportUnavailable)?
                .clone();
            retired.retain(|task| !task.is_finished());
            for session in self.sessions() {
                if session.network_epoch().get() < self.epoch().get()
                    && session.phase() == SessionPhase::Ready
                {
                    let deadline = Deadline::after(ariad_core::lab_cap(
                        ariad_core::DeadlineKind::GracefulDrain,
                    ))?;
                    let spawner = spawner.as_ref().ok_or(EngineError::InvalidConfig)?;
                    retired
                        .try_reserve(1)
                        .map_err(|_| EngineError::ResourceLimitExceeded)?;
                    session.inner.drain();
                    retired.push(spawner.spawn(async move {
                        if session.close(CloseMode::Graceful, deadline).await.is_err() {
                            session.cancel();
                        }
                    }));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn stop(&self) -> Vec<Session> {
        self.state.send_modify(|state| state.stopping = true);
        self.sessions()
    }

    fn sessions(&self) -> Vec<Session> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        sessions
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|inner| inner.state.borrow().close_result.is_none())
            .map(|inner| Session { inner })
            .collect()
    }

    pub(crate) async fn join_retired(&self) {
        let tasks = std::mem::take(
            &mut *self
                .retired
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    pub(crate) fn pending_connects(&self) -> usize {
        self.pending_connections.used()
    }

    pub(crate) async fn wait_pending(&self, deadline: Deadline) -> Result<(), EngineError> {
        deadline
            .run(async {
                loop {
                    let changed = self.pending_changed.notified();
                    tokio::pin!(changed);
                    // Register before reading the count so a concurrent permit drop is not missed.
                    changed.as_mut().enable();
                    if self.pending_connects() == 0 {
                        return Ok(());
                    }
                    changed.await;
                }
            })
            .await
    }

    pub(crate) async fn wait_cancelled(&self, epoch: NetworkEpoch) {
        let mut receiver = self.state.subscribe();
        loop {
            let state = *receiver.borrow();
            if state.is_cancelled(epoch) {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for EngineRuntime {
    fn drop(&mut self) {
        for task in self
            .retired
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

pub(crate) struct ConnectionPermit {
    runtime: Arc<EngineRuntime>,
    slot: Option<ResourceReservation>,
    handshake: Option<ScopedResourceReservation>,
    pub(crate) epoch: NetworkEpoch,
}

impl ConnectionPermit {
    pub(crate) fn take_slot(&mut self) -> Result<ResourceReservation, EngineError> {
        self.slot.take().ok_or(EngineError::ProtocolViolation)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        // Waiters recheck pending_connects on wake; release the reservation before notifying them.
        drop(self.handshake.take());
        self.runtime.pending_changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::h2_tunnel::serve_h2_with_handler;

    fn one_session_runtime() -> Arc<EngineRuntime> {
        let mut limits = BudgetLimits::lab_small();
        limits.active_sessions = 1;
        limits.active_flows_per_session = 1;
        EngineRuntime::new(EngineConfig { limits }).expect("runtime")
    }

    fn deadline() -> Deadline {
        Deadline::after(Duration::from_secs(2)).expect("deadline")
    }

    fn shared_resources() -> (BudgetLimits, Arc<EngineResources>) {
        let mut limits = BudgetLimits::lab_small();
        limits.active_sessions = 2;
        limits.active_flows_per_session = 1;
        limits.pending_egress_opens = 1;
        limits.pending_handshakes = 1;
        limits.global_application_budget = limits.session_application_budget;
        let resources = Arc::new(EngineResources::new(limits).expect("shared pool"));
        (limits, resources)
    }

    fn runtime_with_resources(
        limits: BudgetLimits,
        resources: &Arc<EngineResources>,
    ) -> Arc<EngineRuntime> {
        EngineRuntime::new_with_resources(EngineConfig { limits }, Arc::clone(resources))
            .expect("shared runtime")
    }

    #[test]
    fn runtime_retains_the_original_resource_pool() {
        let (limits, resources) = shared_resources();
        let runtime = runtime_with_resources(limits, &resources);
        assert!(Arc::ptr_eq(&resources, &runtime.resources()));
        let pending = runtime.begin_connect().expect("pending connect");
        assert_eq!(runtime.resources().active_sessions(), 1);
        assert_eq!(runtime.resources().pending_handshakes(), 1);
        drop(pending);
        assert_eq!(resources.active_sessions(), 0);
        assert_eq!(resources.pending_handshakes(), 0);
        let private_runtime = one_session_runtime();
        assert!(Arc::ptr_eq(
            &private_runtime.resources(),
            &private_runtime.resources()
        ));
        assert!(!Arc::ptr_eq(&resources, &private_runtime.resources()));
    }

    #[test]
    fn shared_session_and_handshake_caps_apply_across_runtimes_and_roll_back_denials() {
        let (limits, resources) = shared_resources();
        let first = runtime_with_resources(limits, &resources);
        let second = runtime_with_resources(limits, &resources);
        let mut first_pending = first.begin_connect().expect("first handshake");
        assert!(matches!(
            second.begin_connect(),
            Err(EngineError::ResourceLimitExceeded)
        ));
        assert_eq!(resources.session_slots.used(), 1);
        assert_eq!(resources.handshake_slots.used(), 1);
        assert_eq!(first.pending_connects(), 1);
        assert_eq!(second.pending_connects(), 0);
        let first_session = first_pending.take_slot().expect("first live session");
        drop(first_pending);
        let mut second_pending = second.begin_connect().expect("second handshake");
        let second_session = second_pending.take_slot().expect("second live session");
        drop(second_pending);
        assert_eq!(resources.session_slots.used(), 2);
        assert_eq!(resources.handshake_slots.used(), 0);
        assert!(matches!(
            first.begin_connect(),
            Err(EngineError::ResourceLimitExceeded)
        ));
        assert_eq!(first.pending_connects(), 0);
        drop(first_session);
        drop(second_session);
        assert_eq!(resources.session_slots.used(), 0);
        let replacement = first.begin_connect().expect("released process slot");
        drop(replacement);
        assert_eq!(resources.handshake_slots.used(), 0);
        assert_eq!(resources.session_slots.used(), 0);
    }

    #[test]
    fn shared_memory_cap_counts_other_runtimes_and_releases_both_scopes() {
        let (limits, resources) = shared_resources();
        let first = runtime_with_resources(limits, &resources);
        let mut other_limits = limits;
        other_limits.session_application_budget /= 2;
        other_limits.active_flows_per_session = 2;
        other_limits.pending_egress_opens = 2;
        let second = runtime_with_resources(other_limits, &resources);
        let first_config = first.h2_config().expect("first config");
        let second_config = second.h2_config().expect("second config");
        assert_eq!(
            second_config.session_budget.limit(),
            other_limits.session_application_budget
        );
        assert_eq!(second_config.session_flows.limit(), 2);
        assert_eq!(second_config.process_flows.limit(), 2);
        assert_eq!(second_config.process_opens.limit(), 2);
        let retained = first_config
            .process_budget
            .try_acquire_scoped(
                &first_config.session_budget,
                limits.global_application_budget - 8,
            )
            .expect("first allocation");
        assert!(matches!(
            second_config
                .process_budget
                .try_acquire_scoped(&second_config.session_budget, 16,),
            Err(EngineError::ResourceLimitExceeded)
        ));
        assert_eq!(second_config.session_budget.used(), 0);
        assert_eq!(
            resources.application_memory.used(),
            limits.global_application_budget - 8
        );
        drop(retained);
        assert_eq!(resources.application_memory.used(), 0);
        assert_eq!(first_config.session_budget.used(), 0);
        let session_full = second_config
            .session_budget
            .try_acquire(other_limits.session_application_budget)
            .expect("second session full");
        assert!(matches!(
            second_config
                .process_budget
                .try_acquire_scoped(&second_config.session_budget, 16,),
            Err(EngineError::ResourceLimitExceeded)
        ));
        assert_eq!(resources.application_memory.used(), 0);
        assert_eq!(
            second_config.session_budget.used(),
            other_limits.session_application_budget
        );
        drop(session_full);
        let replacement = second_config
            .process_budget
            .try_acquire_scoped(&second_config.session_budget, 16)
            .expect("released shared memory");
        assert_eq!(resources.application_memory.used(), 16);
        drop(replacement);
        assert_eq!(resources.application_memory.used(), 0);
        assert_eq!(second_config.session_budget.used(), 0);
    }

    #[test]
    fn shared_pool_rejects_process_limit_mismatch_without_charging_quotas() {
        let (limits, resources) = shared_resources();
        for mismatch in [
            BudgetLimits {
                global_application_budget: limits.global_application_budget + 1,
                ..limits
            },
            BudgetLimits {
                active_sessions: limits.active_sessions + 1,
                ..limits
            },
            BudgetLimits {
                pending_handshakes: limits.pending_handshakes + 1,
                ..limits
            },
        ] {
            assert!(matches!(
                EngineRuntime::new_with_resources(
                    EngineConfig { limits: mismatch },
                    Arc::clone(&resources),
                ),
                Err(EngineError::InvalidConfig)
            ));
        }
        assert_eq!(resources.session_slots.used(), 0);
        assert_eq!(resources.handshake_slots.used(), 0);
        assert_eq!(resources.application_memory.used(), 0);
    }

    #[tokio::test]
    async fn one_runtime_shutdown_does_not_wait_for_another_runtime_handshake() {
        let (limits, resources) = shared_resources();
        let first = runtime_with_resources(limits, &resources);
        let second = runtime_with_resources(limits, &resources);
        let pending = second.begin_connect().expect("second pending");
        assert_eq!(resources.handshake_slots.used(), 1);
        assert!(first.stop().is_empty());
        assert_eq!(first.wait_pending(deadline()).await, Ok(()));
        assert_eq!(second.pending_connects(), 1);
        drop(pending);
        let replacement = second
            .begin_connect()
            .expect("second engine still admits work");
        drop(replacement);
    }

    async fn attach(
        runtime: &Arc<EngineRuntime>,
    ) -> (Session, tokio::task::JoinHandle<Result<(), EngineError>>) {
        let (client, peer) = tokio::io::duplex(32 * 1024);
        let server = tokio::spawn(async move {
            serve_h2_with_handler(
                peer,
                H2Config::default(),
                |request, mut respond, _| async move {
                    let mut response = http::Response::new(());
                    crate::connect::attach_h2_versions(response.headers_mut())?;
                    let mut sending = respond
                        .send_response(response, false)
                        .map_err(|_| EngineError::TransportUnavailable)?;
                    let mut incoming = request.into_body();
                    while let Some(chunk) = incoming.data().await {
                        let chunk = chunk.map_err(|_| EngineError::RemoteReset)?;
                        incoming
                            .flow_control()
                            .release_capacity(chunk.len())
                            .map_err(|_| EngineError::ProtocolViolation)?;
                        sending
                            .send_data(chunk, false)
                            .map_err(|_| EngineError::RemoteReset)?;
                    }
                    sending
                        .send_data(bytes::Bytes::new(), true)
                        .map_err(|_| EngineError::TransportUnavailable)?;
                    Ok(())
                },
                std::future::pending(),
            )
            .await
        });
        let mut permit = runtime.begin_connect().expect("admit");
        let h2 = H2Session::handshake_with_deadline(
            client,
            true,
            runtime.h2_config().expect("config"),
            deadline(),
        )
        .await
        .expect("handshake");
        let session = Session::from_h2(
            h2,
            Credential::from_bytes([0x11; 32]),
            1,
            permit.epoch,
            "example.test:443".to_owned(),
            runtime.limits,
            permit.take_slot().expect("session slot"),
        );
        runtime.register(&session).expect("register");
        drop(permit);
        (session, server)
    }

    async fn attach_interrupted_peer(
        runtime: &Arc<EngineRuntime>,
        reset: bool,
    ) -> (
        Session,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), EngineError>>,
    ) {
        let (client, peer) = tokio::io::duplex(8 * 1024);
        let (reset_peer, reset_requested) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(0)
                .handshake::<_, bytes::Bytes>(peer)
                .await
                .expect("handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("request present")
                .expect("request");
            let mut response = http::Response::new(());
            crate::connect::attach_h2_versions(response.headers_mut())?;
            let mut sending = respond
                .send_response(response, false)
                .expect("send response");
            tokio::select! {
                requested = reset_requested => requested.expect("reset requested"),
                incoming = connection.accept() => {
                    panic!("connection ended before peer reset: {incoming:?}");
                }
            }
            if !reset {
                drop(connection);
                return Ok(());
            }
            sending.send_reset(h2::Reason::CANCEL);
            match connection.accept().await {
                None => {}
                Some(Err(error)) => {
                    assert!(error.is_io(), "unexpected connection error: {error}");
                }
                Some(Ok(_)) => panic!("unexpected request"),
            }
            drop(request);
            Ok(())
        });
        let mut permit = runtime.begin_connect().expect("admit");
        let h2 = H2Session::handshake_with_deadline(
            client,
            true,
            runtime.h2_config().expect("config"),
            deadline(),
        )
        .await
        .expect("handshake");
        let session = Session::from_h2(
            h2,
            Credential::from_bytes([0x11; 32]),
            1,
            permit.epoch,
            "example.test:443".to_owned(),
            runtime.limits,
            permit.take_slot().expect("session slot"),
        );
        runtime.register(&session).expect("register");
        drop(permit);
        (session, reset_peer, server)
    }

    async fn open(session: &Session) -> Stream {
        session
            .open_stream(
                &Destination::parse("1.1.1.1:9").expect("target"),
                StreamOptions::default(),
                deadline(),
            )
            .await
            .expect("open")
    }

    async fn exchange(stream: &mut Stream) {
        let mut payload = b"payload".as_slice();
        while !payload.is_empty() {
            let written = stream.write(payload, deadline()).await.expect("write");
            assert!(written > 0);
            payload = &payload[written..];
        }
        stream.end_write(deadline()).await.expect("half close");
        let mut received = [0u8; 7];
        let mut offset = 0;
        while offset < received.len() {
            let ReadOutcome::Data(count) = stream
                .read(&mut received[offset..], deadline())
                .await
                .expect("read")
            else {
                panic!("data before EOF");
            };
            assert!(count > 0);
            offset += count;
        }
        assert_eq!(&received, b"payload");
        assert_eq!(
            stream.read(&mut [0u8; 1], deadline()).await.expect("EOF"),
            ReadOutcome::Eof
        );
    }

    async fn join_server(
        server: tokio::task::JoinHandle<Result<(), EngineError>>,
        allowed_errors: &[EngineError],
    ) {
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server stopped")
            .expect("server task did not panic");
        match result {
            Ok(()) => {}
            Err(error) => assert!(
                allowed_errors.contains(&error),
                "unexpected server result: {error:?}"
            ),
        }
    }

    #[tokio::test]
    async fn complete_stream_helpers_preserve_preflight_and_short_read_prefix() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let runtime = one_session_runtime();
            let (session, server) = attach(&runtime).await;
            let mut stream = open(&session).await;
            let io_deadline = deadline();
            stream
                .write_all(&[], io_deadline)
                .await
                .expect("empty write");
            stream
                .read_exact(&mut [], io_deadline)
                .await
                .expect("empty read");
            let expired = Deadline::at(tokio::time::Instant::now());
            let mut received = [0xa5; 8];
            assert_eq!(
                stream.write_all(b"ignored", expired).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(
                stream.read_exact(&mut received, expired).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(received, [0xa5; 8]);
            assert_eq!(runtime.resources.active_flows(), 1);
            stream
                .write_all(b"payload", io_deadline)
                .await
                .expect("write payload");
            stream.end_write(io_deadline).await.expect("FIN");
            assert_eq!(
                stream.read_exact(&mut received, io_deadline).await,
                Err(EngineError::TruncatedStream)
            );
            assert_eq!(&received[..7], b"payload");
            assert_eq!(received[7], 0xa5);
            assert_eq!(
                stream.read(&mut received, io_deadline).await.expect("EOF"),
                ReadOutcome::Eof
            );
            assert_eq!(runtime.resources.active_flows(), 0);
            drop(stream);
            assert_eq!(
                session
                    .close(CloseMode::Graceful, deadline())
                    .await
                    .expect("close"),
                CloseOutcome::Graceful
            );
            assert_eq!(runtime.resources.active_sessions(), 0);
            join_server(server, &[]).await;
        })
        .await
        .expect("stream helper watchdog");
    }

    #[tokio::test]
    async fn split_complete_helpers_transfer_multiple_fragments_before_fin() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let runtime = one_session_runtime();
            let (session, server) = attach(&runtime).await;
            let (mut reader, mut writer) = open(&session).await.into_split();
            let payload = vec![0x7b; 32 * 1024 + 17];
            let mut received = vec![0xa5; payload.len()];
            let io_deadline = deadline();
            let send = async {
                writer.write_all(&payload, io_deadline).await?;
                writer.end_write(io_deadline).await
            };
            let receive = async {
                reader.read_exact(&mut received, io_deadline).await?;
                assert_eq!(
                    reader.read(&mut [0u8; 1], io_deadline).await?,
                    ReadOutcome::Eof
                );
                Ok::<(), EngineError>(())
            };
            tokio::try_join!(send, receive).expect("complete exchange");
            assert_eq!(received, payload);
            assert_eq!(runtime.resources.active_flows(), 0);
            drop(writer);
            drop(reader);
            assert_eq!(
                session
                    .close(CloseMode::Graceful, deadline())
                    .await
                    .expect("close"),
                CloseOutcome::Graceful
            );
            assert_eq!(runtime.resources.active_sessions(), 0);
            join_server(server, &[]).await;
        })
        .await
        .expect("split helper watchdog");
    }

    #[tokio::test]
    async fn read_exact_timeout_keeps_received_prefix_and_deadline_cause() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let runtime = one_session_runtime();
            let (session, server) = attach(&runtime).await;
            let (mut reader, mut writer) = open(&session).await.into_split();
            writer
                .write_all(b"payload", deadline())
                .await
                .expect("write prefix");
            let mut received = [0xa5; 8];
            let io_deadline = Deadline::after(Duration::from_millis(250)).expect("read deadline");
            assert_eq!(
                reader.read_exact(&mut received, io_deadline).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(&received[..7], b"payload");
            assert_eq!(received[7], 0xa5);
            assert_eq!(
                writer.write_all(b"not accepted", deadline()).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(
                reader.read_exact(&mut received, deadline()).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(runtime.resources.active_flows(), 0);
            drop(writer);
            drop(reader);
            assert_eq!(
                session
                    .close(CloseMode::Graceful, deadline())
                    .await
                    .expect("close"),
                CloseOutcome::Graceful
            );
            assert_eq!(runtime.resources.active_sessions(), 0);
            join_server(server, &[EngineError::RemoteReset]).await;
        })
        .await
        .expect("read deadline watchdog");
    }

    #[tokio::test]
    async fn dropping_read_exact_preserves_the_first_terminal_cause() {
        use std::future::poll_fn;
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(5), async {
            for reset in [false, true] {
                let runtime = one_session_runtime();
                let (session, server) = attach(&runtime).await;
                let (mut reader, mut writer) = open(&session).await.into_split();
                let control = writer.control();
                let mut received = [0xa5; 1];
                let mut reading = Box::pin(reader.read_exact(&mut received, deadline()));
                assert!(
                    poll_fn(|context| Poll::Ready(reading.as_mut().poll(context)))
                        .await
                        .is_pending()
                );
                let expected = if reset {
                    control.reset().expect("reset pending exact read");
                    EngineError::RemoteReset
                } else {
                    EngineError::Cancelled
                };
                drop(reading);
                assert_eq!(
                    writer.write_all(b"not accepted", deadline()).await,
                    Err(expected)
                );
                assert_eq!(
                    reader.read_exact(&mut received, deadline()).await,
                    Err(expected)
                );
                assert_eq!(received, [0xa5; 1]);
                assert_eq!(runtime.resources.active_flows(), 0);
                drop(writer);
                drop(reader);
                assert_eq!(
                    session
                        .close(CloseMode::Graceful, deadline())
                        .await
                        .expect("close"),
                    CloseOutcome::Graceful
                );
                assert_eq!(runtime.resources.active_sessions(), 0);
                join_server(server, &[EngineError::RemoteReset]).await;
            }
        })
        .await
        .expect("read cancellation watchdog");
    }

    #[tokio::test]
    async fn transport_read_failure_survives_dropping_an_unrepolled_writer() {
        use std::future::poll_fn;
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(5), async {
            for exact in [false, true] {
                let runtime = one_session_runtime();
                let (session, close_peer, server) = attach_interrupted_peer(&runtime, false).await;
                let (mut reader, mut writer) = open(&session).await.into_split();
                let mut writing = Box::pin(writer.write_all(b"waiting for credit", deadline()));
                assert!(
                    poll_fn(|context| Poll::Ready(writing.as_mut().poll(context)))
                        .await
                        .is_pending()
                );
                close_peer.send(()).expect("close peer transport");
                let mut received = [0xa5; 1];
                if exact {
                    assert_eq!(
                        reader.read_exact(&mut received, deadline()).await,
                        Err(EngineError::TransportUnavailable)
                    );
                } else {
                    assert_eq!(
                        reader.read(&mut received, deadline()).await,
                        Err(EngineError::TransportUnavailable)
                    );
                }
                drop(writing);
                assert_eq!(
                    writer.write(b"late", deadline()).await,
                    Err(EngineError::TransportUnavailable)
                );
                assert_eq!(
                    reader.read(&mut received, deadline()).await,
                    Err(EngineError::TransportUnavailable)
                );
                assert_eq!(
                    reader.read_exact(&mut received, deadline()).await,
                    Err(EngineError::TransportUnavailable)
                );
                assert_eq!(received, [0xa5; 1]);
                reader.control().cancel();
                assert_eq!(
                    writer.write(b"late", deadline()).await,
                    Err(EngineError::Cancelled)
                );
                assert_eq!(
                    reader.read(&mut received, deadline()).await,
                    Ok(ReadOutcome::Cancelled)
                );
                assert_eq!(runtime.resources.active_flows(), 0);
                drop(writer);
                drop(reader);
                session.cancel();
                assert_eq!(
                    session.close(CloseMode::Immediate, deadline()).await,
                    Ok(CloseOutcome::Forced)
                );
                assert_eq!(runtime.resources.active_sessions(), 0);
                join_server(server, &[]).await;
            }
        })
        .await
        .expect("transport read failure watchdog");
    }

    #[tokio::test]
    async fn peer_reset_read_survives_dropping_an_unrepolled_writer() {
        use std::future::poll_fn;
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(5), async {
            for (exact, native_first) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let runtime = one_session_runtime();
                let (session, reset_peer, server) = attach_interrupted_peer(&runtime, true).await;
                let (mut reader, mut writer) = open(&session).await.into_split();
                let control = reader.control();
                let mut writing = Box::pin(writer.write_all(b"waiting for credit", deadline()));
                assert!(
                    poll_fn(|context| Poll::Ready(writing.as_mut().poll(context)))
                        .await
                        .is_pending()
                );
                reset_peer.send(()).expect("reset peer");
                let mut received = [0xa5; 1];
                if native_first {
                    let result = match &mut reader.binding {
                        StreamReadBinding::H2(stream) => stream.read(&mut received).await,
                        #[cfg(feature = "h3")]
                        StreamReadBinding::H3(_) => unreachable!("H2 fixture"),
                    };
                    assert!(matches!(
                        result,
                        Err(EngineError::RemoteReset) | Ok(ReadOutcome::Reset)
                    ));
                    assert_eq!(*reader.state.terminal.borrow(), None);
                }
                if exact {
                    assert_eq!(
                        reader.read_exact(&mut received, deadline()).await,
                        Err(EngineError::RemoteReset)
                    );
                } else {
                    assert_eq!(
                        reader.read(&mut received, deadline()).await,
                        Ok(ReadOutcome::Reset)
                    );
                }
                drop(writing);
                assert_eq!(
                    writer.write(b"late", deadline()).await,
                    Err(EngineError::RemoteReset)
                );
                assert_eq!(
                    reader.read(&mut received, deadline()).await,
                    Ok(ReadOutcome::Reset)
                );
                assert_eq!(received, [0xa5; 1]);
                assert_eq!(runtime.resources.active_flows(), 0);
                control.cancel();
                assert_eq!(
                    writer.write_all(b"late", deadline()).await,
                    Err(EngineError::Cancelled)
                );
                assert_eq!(
                    reader.read(&mut received, deadline()).await,
                    Ok(ReadOutcome::Cancelled)
                );
                drop(writer);
                drop(reader);
                assert_eq!(
                    session.close(CloseMode::Graceful, deadline()).await,
                    Ok(CloseOutcome::Graceful)
                );
                assert_eq!(runtime.resources.active_sessions(), 0);
                join_server(server, &[]).await;
            }
        })
        .await
        .expect("peer reset read watchdog");
    }

    #[tokio::test]
    async fn peer_reset_write_survives_dropping_an_unrepolled_reader() {
        use std::future::poll_fn;
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(5), async {
            for exact in [false, true] {
                let runtime = one_session_runtime();
                let (session, reset_peer, server) = attach_interrupted_peer(&runtime, true).await;
                let (mut reader, mut writer) = open(&session).await.into_split();
                let mut received = [0xa5; 1];
                let mut reading = Box::pin(async {
                    if exact {
                        reader.read_exact(&mut received, deadline()).await
                    } else {
                        reader.read(&mut received, deadline()).await.map(|_| ())
                    }
                });
                assert!(
                    poll_fn(|context| Poll::Ready(reading.as_mut().poll(context)))
                        .await
                        .is_pending()
                );
                reset_peer.send(()).expect("reset peer");
                assert_eq!(
                    writer.write(b"late", deadline()).await,
                    Err(EngineError::RemoteReset)
                );
                drop(reading);
                assert_eq!(
                    reader.read(&mut received, deadline()).await,
                    Ok(ReadOutcome::Reset)
                );
                assert_eq!(
                    reader.read_exact(&mut received, deadline()).await,
                    Err(EngineError::RemoteReset)
                );
                assert_eq!(
                    writer.write_all(b"late", deadline()).await,
                    Err(EngineError::RemoteReset)
                );
                assert_eq!(received, [0xa5; 1]);
                assert_eq!(runtime.resources.active_flows(), 0);
                drop(writer);
                drop(reader);
                assert_eq!(
                    session.close(CloseMode::Graceful, deadline()).await,
                    Ok(CloseOutcome::Graceful)
                );
                assert_eq!(runtime.resources.active_sessions(), 0);
                join_server(server, &[]).await;
            }
        })
        .await
        .expect("peer reset write watchdog");
    }

    #[tokio::test]
    async fn stream_read_reset_survives_dropping_an_unrepolled_operation() {
        use std::future::poll_fn;
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(5), async {
            let runtime = one_session_runtime();
            let (session, reset_peer, server) = attach_interrupted_peer(&runtime, true).await;
            let mut stream = open(&session).await;
            let state = Arc::clone(&stream.state);
            // An unsplit handle cannot borrow a second public I/O operation at the same time.
            let mut pending = Box::pin(state.run_io(
                deadline(),
                std::future::pending::<Result<(), EngineError>>(),
            ));
            assert!(
                poll_fn(|context| Poll::Ready(pending.as_mut().poll(context)))
                    .await
                    .is_pending()
            );
            reset_peer.send(()).expect("reset peer");
            let mut received = [0xa5; 1];
            let result = match &mut stream.binding {
                StreamBinding::H2(stream) => stream.read(&mut received).await,
                #[cfg(feature = "h3")]
                StreamBinding::H3(_) => unreachable!("H2 fixture"),
            };
            assert!(matches!(
                result,
                Err(EngineError::RemoteReset) | Ok(ReadOutcome::Reset)
            ));
            assert_eq!(*state.terminal.borrow(), None);
            assert_eq!(
                stream.read(&mut received, deadline()).await,
                Ok(ReadOutcome::Reset)
            );
            drop(pending);
            assert_eq!(
                stream.read(&mut received, deadline()).await,
                Ok(ReadOutcome::Reset)
            );
            assert_eq!(
                stream.write(b"late", deadline()).await,
                Err(EngineError::RemoteReset)
            );
            assert_eq!(received, [0xa5; 1]);
            assert_eq!(runtime.resources.active_flows(), 0);
            drop(stream);
            assert_eq!(
                session.close(CloseMode::Graceful, deadline()).await,
                Ok(CloseOutcome::Graceful)
            );
            assert_eq!(runtime.resources.active_sessions(), 0);
            join_server(server, &[]).await;
        })
        .await
        .expect("stream reset watchdog");
    }

    #[tokio::test]
    async fn dropping_a_stream_keeps_the_verified_session_available() {
        let runtime = one_session_runtime();
        let (session, server) = attach(&runtime).await;
        drop(open(&session).await);
        assert_eq!(runtime.resources.active_flows(), 0);
        let mut retained = open(&session).await;
        drop(session);
        exchange(&mut retained).await;
        assert_eq!(runtime.resources.active_flows(), 0);
        let active = runtime.stop().pop().expect("session owned by stream");
        assert_eq!(
            active
                .close(CloseMode::Graceful, deadline())
                .await
                .expect("close"),
            CloseOutcome::Graceful
        );
        assert_eq!(runtime.resources.active_sessions(), 0);
        join_server(server, &[EngineError::RemoteReset]).await;
    }

    #[tokio::test]
    async fn cancel_releases_network_slots_while_old_handles_are_retained() {
        let runtime = one_session_runtime();
        let (old, old_server) = attach(&runtime).await;
        let mut old_stream = open(&old).await;
        old.cancel();
        old.inner
            .join_completion()
            .await
            .expect("completion cleanup");
        assert_eq!(runtime.resources.active_sessions(), 0);
        assert_eq!(runtime.resources.active_flows(), 0);
        assert_eq!(
            old_stream
                .read(&mut [0u8; 1], deadline())
                .await
                .expect("cancelled"),
            ReadOutcome::Cancelled
        );
        let (fresh, fresh_server) = attach(&runtime).await;
        let mut fresh_stream = open(&fresh).await;
        exchange(&mut fresh_stream).await;
        assert_eq!(
            fresh
                .close(CloseMode::Graceful, deadline())
                .await
                .expect("fresh close"),
            CloseOutcome::Graceful
        );
        assert_eq!(
            old.close(CloseMode::Immediate, deadline())
                .await
                .expect("old close"),
            CloseOutcome::Forced
        );
        join_server(
            old_server,
            &[EngineError::RemoteReset, EngineError::TransportUnavailable],
        )
        .await;
        join_server(fresh_server, &[]).await;
    }

    #[tokio::test]
    async fn network_change_rejects_new_opens_and_drains_an_existing_stream() {
        let runtime = one_session_runtime();
        let (old, server) = attach(&runtime).await;
        let mut existing = open(&old).await;
        let next = runtime.epoch().advance().expect("next epoch");
        runtime.on_network_change(next).expect("network change");
        assert_eq!(old.phase(), SessionPhase::Draining);
        assert!(
            old.open_stream(
                &Destination::parse("1.1.1.1:9").expect("target"),
                StreamOptions::default(),
                deadline(),
            )
            .await
            .is_err()
        );
        exchange(&mut existing).await;
        assert_eq!(
            old.close(CloseMode::Graceful, deadline())
                .await
                .expect("close"),
            CloseOutcome::Graceful
        );
        runtime.join_retired().await;
        assert_eq!(runtime.resources.active_sessions(), 0);
        assert!(runtime.on_network_change(NetworkEpoch::start()).is_err());
        join_server(server, &[]).await;
    }

    #[tokio::test]
    async fn expired_open_and_native_udp_requirement_send_no_request() {
        let runtime = one_session_runtime();
        let (session, server) = attach(&runtime).await;
        let destination = Destination::parse("1.1.1.1:9").expect("target");
        assert_eq!(
            session
                .open_stream(
                    &destination,
                    StreamOptions::default(),
                    Deadline::at(tokio::time::Instant::now()),
                )
                .await
                .unwrap_err(),
            EngineError::DeadlineExceeded
        );
        assert_eq!(
            session
                .open_datagram_association(
                    &destination,
                    DatagramRequirements {
                        require_unreliable: true
                    },
                    deadline(),
                )
                .await
                .unwrap_err(),
            EngineError::UnsupportedCapability
        );
        assert_eq!(
            session.capabilities().datagram_delivery,
            DeliveryMode::Unsupported
        );
        assert_eq!(runtime.resources.active_flows(), 0);
        assert_eq!(
            session
                .close(CloseMode::Graceful, deadline())
                .await
                .expect("close"),
            CloseOutcome::Graceful
        );
        join_server(server, &[]).await;
    }

    #[tokio::test]
    async fn dropping_a_pending_close_cancels_the_session_and_releases_its_slots() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let runtime = one_session_runtime();
        let (session, server) = attach(&runtime).await;
        let mut stream = open(&session).await;
        let mut closing = Box::pin(session.close(CloseMode::Graceful, deadline()));
        let progress = poll_fn(|context| Poll::Ready(closing.as_mut().poll(context))).await;
        assert!(progress.is_pending());
        drop(closing);
        session
            .inner
            .join_completion()
            .await
            .expect("cancelled close cleanup");
        assert_eq!(session.phase(), SessionPhase::Cancelled);
        assert_eq!(runtime.resources.active_sessions(), 0);
        assert_eq!(runtime.resources.active_flows(), 0);
        let mut out = [0xa5; 1];
        assert_eq!(
            stream
                .read(&mut out, deadline())
                .await
                .expect("read cancelled"),
            ReadOutcome::Cancelled
        );
        assert_eq!(out, [0xa5]);
        assert_eq!(
            session
                .close(CloseMode::Immediate, deadline())
                .await
                .expect("retry cleanup"),
            CloseOutcome::Forced
        );
        join_server(
            server,
            &[EngineError::RemoteReset, EngineError::TransportUnavailable],
        )
        .await;
    }

    #[tokio::test]
    async fn split_stream_writes_during_pending_read_and_retains_reader_after_fin() {
        use std::future::poll_fn;
        use std::task::Poll;

        let runtime = one_session_runtime();
        let (session, server) = attach(&runtime).await;
        let (mut reader, mut writer) = open(&session).await.into_split();
        drop(session);
        let mut out = [0u8; 7];
        let expired = Deadline::at(tokio::time::Instant::now());
        assert_eq!(
            writer.write(b"ignored", expired).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(
            writer.end_write(expired).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(
            reader.read(&mut out, expired).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(out, [0u8; 7]);
        let mut reading = Box::pin(reader.read(&mut out, deadline()));
        assert!(
            poll_fn(|context| Poll::Ready(reading.as_mut().poll(context)))
                .await
                .is_pending()
        );
        let mut payload = b"payload".as_slice();
        while !payload.is_empty() {
            let written = writer
                .write(payload, deadline())
                .await
                .expect("write during read");
            assert!(written > 0);
            payload = &payload[written..];
        }
        writer.end_write(deadline()).await.expect("FIN");
        drop(writer);
        let ReadOutcome::Data(mut offset) = reading.await.expect("pending read completed") else {
            panic!("data before EOF");
        };
        assert!(offset > 0);
        while offset < out.len() {
            let ReadOutcome::Data(count) = reader
                .read(&mut out[offset..], deadline())
                .await
                .expect("remaining data")
            else {
                panic!("data before EOF");
            };
            assert!(count > 0);
            offset += count;
        }
        assert_eq!(&out, b"payload");
        assert_eq!(
            reader.read(&mut [0u8; 1], deadline()).await.expect("EOF"),
            ReadOutcome::Eof
        );
        assert_eq!(runtime.resources.active_flows(), 0);
        let active = runtime.stop().pop().expect("reader retains session");
        assert_eq!(
            active
                .close(CloseMode::Graceful, deadline())
                .await
                .expect("close"),
            CloseOutcome::Graceful
        );
        assert_eq!(runtime.resources.active_sessions(), 0);
        drop(reader);
        join_server(server, &[]).await;
    }

    #[tokio::test]
    async fn dropping_pending_split_read_cancels_writer_and_releases_flow() {
        use std::future::poll_fn;
        use std::task::Poll;

        let runtime = one_session_runtime();
        let (session, server) = attach(&runtime).await;
        let (mut reader, mut writer) = open(&session).await.into_split();
        let mut out = [0xa5; 1];
        let mut reading = Box::pin(reader.read(&mut out, deadline()));
        assert!(
            poll_fn(|context| Poll::Ready(reading.as_mut().poll(context)))
                .await
                .is_pending()
        );
        drop(reading);
        assert_eq!(
            writer.write(b"payload", deadline()).await,
            Err(EngineError::Cancelled)
        );
        assert_eq!(
            reader
                .read(&mut out, deadline())
                .await
                .expect("cancelled read"),
            ReadOutcome::Cancelled
        );
        assert_eq!(out, [0xa5]);
        assert_eq!(runtime.resources.active_flows(), 0);
        drop(writer);
        drop(reader);
        assert_eq!(
            session
                .close(CloseMode::Graceful, deadline())
                .await
                .expect("close"),
            CloseOutcome::Graceful
        );
        assert_eq!(runtime.resources.active_sessions(), 0);
        join_server(server, &[EngineError::RemoteReset]).await;
    }

    #[tokio::test]
    async fn split_control_interrupts_pending_read_without_retaining_network_slots() {
        use std::future::poll_fn;
        use std::task::Poll;

        for reset in [false, true] {
            let runtime = one_session_runtime();
            let (session, server) = attach(&runtime).await;
            let (mut reader, mut writer) = open(&session).await.into_split();
            let control = writer.control();
            let mut out = [0xa5; 1];
            let mut reading = Box::pin(reader.read(&mut out, deadline()));
            assert!(
                poll_fn(|context| Poll::Ready(reading.as_mut().poll(context)))
                    .await
                    .is_pending()
            );
            let (read_terminal, write_terminal) = if reset {
                control.reset().expect("reset while read is borrowed");
                (ReadOutcome::Reset, EngineError::RemoteReset)
            } else {
                control.cancel();
                (ReadOutcome::Cancelled, EngineError::Cancelled)
            };
            assert_eq!(reading.await.expect("interrupted read"), read_terminal);
            assert_eq!(out, [0xa5]);
            assert_eq!(
                writer.write(b"payload", deadline()).await,
                Err(write_terminal)
            );
            assert_eq!(runtime.resources.active_flows(), 0);
            drop(reader);
            drop(writer);
            assert_eq!(control.reset(), Err(EngineError::Cancelled));
            assert_eq!(
                session
                    .close(CloseMode::Graceful, deadline())
                    .await
                    .expect("close"),
                CloseOutcome::Graceful
            );
            assert_eq!(runtime.resources.active_sessions(), 0);
            drop(session);
            join_server(server, &[EngineError::RemoteReset]).await;
            assert!(runtime.resources.application_memory_used() > 0);
            drop(control);
            assert_eq!(runtime.resources.application_memory_used(), 0);
        }
    }

    #[tokio::test]
    #[should_panic(expected = "unexpected server result: ProtocolViolation")]
    async fn server_join_rejects_protocol_violation_during_forced_cleanup() {
        let server = tokio::spawn(async { Err(EngineError::ProtocolViolation) });
        join_server(
            server,
            &[EngineError::RemoteReset, EngineError::TransportUnavailable],
        )
        .await;
    }

    #[tokio::test]
    async fn pending_connect_cleanup_wakes_shutdown_without_starting_a_new_deadline() {
        let runtime = one_session_runtime();
        let permit = runtime.begin_connect().expect("admit");
        assert_eq!(runtime.pending_connects(), 1);
        let shutdown_deadline = deadline();
        let release = async {
            tokio::task::yield_now().await;
            drop(permit);
        };
        let wait = runtime.wait_pending(shutdown_deadline);
        let ((), result) = tokio::join!(release, wait);
        assert_eq!(result, Ok(()));
        assert_eq!(runtime.pending_connects(), 0);
        let _ = runtime.stop();
        assert!(matches!(
            runtime.begin_connect(),
            Err(EngineError::Cancelled)
        ));
    }
}
