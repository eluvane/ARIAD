#![forbid(unsafe_code)]

use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ariad_core::{
    AuthzDecision, BudgetLimits, CapsuleDecoder, Credential, DATAGRAM_CAPSULE, DatagramOutcome,
    DeliveryMode, Destination, EngineError, MemoryBudget, ScopedMemoryReservation, VarInt,
    datagram_max_payload, encode_datagram_capsule, split_http_datagram, wire_overhead,
};
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderValue, Request, Response, StatusCode};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::Deadline;
use crate::connect::attach_h2_versions;
use crate::dir::ReadOutcome;
use crate::h2_tunnel::{
    H2Config, H2Connect, H2ReadHalf, H2Session, H2StreamControl, H2WriteHalf, check_h2_credential,
    check_header_limits_with_bounds, map_h2, poll_send_capacity,
};
use crate::host::Authorizer;
use crate::masque::{
    CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED, CONNECT_UDP_CONTEXT_ID, MAX_DATAGRAM_PAYLOAD,
    capsule_protocol_enabled, connect_udp_template, negotiated_datagram_payload,
    target_of_connect_udp, validate_capsule_response,
};
use crate::response::classify_connect_status;

const OPEN_METADATA_RESERVE_BYTES: usize = 4 * 1024;

/// Payload bytes of one received datagram, including an empty message.
///
/// Clones and nonempty `Bytes` slices retain the memory reservation for the full
/// backing allocation until the last owner is dropped. Empty slices do not retain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramPayload {
    bytes: Bytes,
}

impl DatagramPayload {
    pub(crate) fn from_bytes(bytes: Bytes) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers the shared storage and its memory reservation to `Bytes`.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

impl AsRef<[u8]> for DatagramPayload {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::ops::Deref for DatagramPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

/// Limits and memory quotas for HTTP/2 datagram capsule flows.
#[derive(Debug, Clone)]
pub struct DatagramOptions {
    /// H2 payload allowance accounts for capsule overhead before queue and path limits.
    pub limits: BudgetLimits,
    /// Session generation reported by the association.
    pub generation: u64,
    /// Reject reliable H2 capsule mode when true.
    pub require_unreliable: bool,
    /// Shared quota for retained buffer allocations; its scope follows the supplied pool.
    pub process_memory: MemoryBudget,
    /// Session quota paired with `process_memory`.
    pub session_memory: MemoryBudget,
    /// Inactivity timeout; zero is invalid.
    pub idle_timeout: Duration,
    /// Optional payload ceiling in bytes, excluding encapsulation headers.
    /// `None` adds no ceiling; zero is unsupported. Peer negotiation may reduce it.
    pub path_payload_limit: Option<usize>,
}

impl DatagramOptions {
    /// Uses lab limits, the lab UDP idle timeout, and the config's shared quotas.
    /// Capability and limit checks run when the flow is opened or relayed.
    pub fn from_h2_config(config: &H2Config, generation: u64, require_unreliable: bool) -> Self {
        Self {
            limits: BudgetLimits::lab_small(),
            generation,
            require_unreliable,
            process_memory: config.process_budget.clone(),
            session_memory: config.session_budget.clone(),
            idle_timeout: ariad_core::lab_cap(ariad_core::DeadlineKind::IdleUdp),
            path_payload_limit: None,
        }
    }

    fn max_payload(&self) -> Result<usize, EngineError> {
        self.limits.validate()?;
        if self.require_unreliable {
            return Err(EngineError::UnsupportedCapability);
        }
        if self.idle_timeout.is_zero() {
            return Err(EngineError::InvalidConfig);
        }
        if self.path_payload_limit == Some(0) {
            return Err(EngineError::UnsupportedCapability);
        }
        Ok(datagram_max_payload(
            false,
            CONNECT_UDP_CONTEXT_ID,
            self.limits.udp_payload_absolute_max,
        )?
        .min(self.limits.udp_queue_bytes)
        .min(self.path_payload_limit.unwrap_or(usize::MAX)))
    }

    fn reserve(&self, bytes: usize) -> Result<ScopedMemoryReservation, EngineError> {
        self.process_memory
            .try_acquire_scoped(&self.session_memory, bytes)
    }
}

struct DatagramDecoder {
    decoder: CapsuleDecoder,
    max_payload: usize,
    reservation: Option<ScopedMemoryReservation>,
}

struct CapsuleDatagram {
    capsule_value: Vec<u8>,
    payload_offset: usize,
    _reservation: ScopedMemoryReservation,
}

impl CapsuleDatagram {
    fn payload(&self) -> &[u8] {
        &self.capsule_value[self.payload_offset..]
    }

    fn into_payload(self) -> DatagramPayload {
        DatagramPayload::from_bytes(Bytes::from_owner(self))
    }
}

impl AsRef<[u8]> for CapsuleDatagram {
    fn as_ref(&self) -> &[u8] {
        self.payload()
    }
}

impl DatagramDecoder {
    fn new(max_payload: usize) -> Result<Self, EngineError> {
        Ok(Self {
            // QUIC permits nonminimal context IDs up to eight bytes.
            decoder: CapsuleDecoder::new(
                max_payload
                    .checked_add(VarInt::MAX_ENCODED_LEN)
                    .ok_or(EngineError::InvalidConfig)?,
            )?,
            max_payload,
            reservation: None,
        })
    }

    fn feed(
        &mut self,
        bytes: &[u8],
        options: &DatagramOptions,
    ) -> Result<(usize, Option<CapsuleDatagram>), EngineError> {
        let reservation = &mut self.reservation;
        let (consumed, capsule) = self.decoder.feed(bytes, |value_len| {
            if reservation.is_some() {
                return Err(EngineError::ProtocolViolation);
            }
            *reservation =
                Some(options.reserve(crate::retained_bytes_charge::<CapsuleDatagram>(value_len)?)?);
            Ok(())
        })?;
        let Some(capsule) = capsule else {
            return Ok((consumed, None));
        };
        if capsule.kind != DATAGRAM_CAPSULE {
            return Ok((consumed, None));
        }
        let (context_id, payload) = split_http_datagram(&capsule.value)?;
        let payload_offset = capsule.value.len() - payload.len();
        let payload_len = payload.len();
        let reservation = self
            .reservation
            .take()
            .ok_or(EngineError::ProtocolViolation)?;
        if crate::retained_bytes_charge::<CapsuleDatagram>(capsule.value.capacity())?
            > reservation.bytes()
        {
            drop(capsule);
            drop(reservation);
            return Err(EngineError::ResourceLimitExceeded);
        }
        if payload_len > self.max_payload {
            drop(capsule);
            drop(reservation);
            return Err(EngineError::MessageTooLarge);
        }
        let datagram = CapsuleDatagram {
            capsule_value: capsule.value,
            payload_offset,
            _reservation: reservation,
        };
        if context_id != CONNECT_UDP_CONTEXT_ID {
            return Ok((consumed, None));
        }
        Ok((consumed, Some(datagram)))
    }

    fn finish(&self) -> Result<(), EngineError> {
        self.decoder.finish()
    }
}

/// One CONNECT-UDP flow using reliable HTTP/2 capsule encapsulation.
///
/// Send and receive deadlines are capped by the inactivity timeout. Queued sends
/// and successful receives restart that timeout. Closing or dropping the association
/// resets its H2 flow; delivered payloads retain their own memory reservations.
/// Use [`Self::into_split`] to send while a receive is pending.
pub struct DatagramAssociation {
    // Reset the combined handle before either H2 half is dropped.
    drop_guard: DatagramAssociationCloseGuard,
    sender: DatagramSendHalf,
    receiver: DatagramRecvHalf,
}

/// An independent capsule sender with shared cancellation and inactivity state.
///
/// Dropping it attempts request END_STREAM and leaves receive available if that
/// succeeds. Dropping a pending send cancels both directions.
pub struct DatagramSendHalf {
    transport: H2WriteHalf,
    control: DatagramControl,
    max_payload: usize,
    generation: u64,
}

/// An independent capsule receiver that owns its decoder and charged read buffers.
///
/// Dropping it releases unread receive buffers. Delivered payloads keep their own
/// reservations. Dropping a pending receive cancels both directions.
pub struct DatagramRecvHalf {
    // The active receive future owns this state until completion or cancellation.
    read: Option<DatagramReadState>,
    transport: H2ReadHalf,
    control: DatagramControl,
    max_payload: usize,
    generation: u64,
}

/// A shared close and cancellation handle for both datagram directions.
///
/// Pending operations wake on closure. Idle receive buffers remain charged until
/// their owner observes closure or drops. This handle retains metadata charge,
/// but it does not keep the H2 flow alive after both IO halves drop.
#[derive(Clone)]
pub struct DatagramControl {
    shared: Arc<DatagramShared>,
}

struct DatagramShared {
    transport: H2StreamControl,
    options: DatagramOptions,
    state: Mutex<DatagramState>,
    changed: Notify,
    _reservation: ScopedMemoryReservation,
}

impl DatagramShared {
    fn lock_state(&self) -> MutexGuard<'_, DatagramState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

struct DatagramState {
    last_activity: Instant,
    terminal: Option<EngineError>,
    closed: bool,
}

impl DatagramState {
    fn check_open(&self) -> Result<(), EngineError> {
        if let Some(error) = self.terminal {
            Err(error)
        } else if self.closed {
            Err(EngineError::ProtocolViolation)
        } else {
            Ok(())
        }
    }

    fn close_once(&mut self, terminal: Option<EngineError>) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        self.terminal = terminal;
        true
    }
}

struct DatagramReadState {
    decoder: DatagramDecoder,
    read_buffer: Vec<u8>,
    read_offset: usize,
    read_len: usize,
    _read_reservation: ScopedMemoryReservation,
}

impl DatagramControl {
    /// Closes both directions and requests H2 reset without waiting for the peer.
    /// Closing an open flow makes later operations return `ProtocolViolation`.
    /// Calls after closure succeed without changing its terminal state.
    pub fn close(&self) -> Result<(), EngineError> {
        self.terminate(None)
    }

    /// Closes both directions with `Cancelled` as the terminal error.
    /// Calls after closure succeed without changing the stored terminal state.
    pub fn cancel(&self) -> Result<(), EngineError> {
        self.terminate(Some(EngineError::Cancelled))
    }

    fn terminate(&self, terminal: Option<EngineError>) -> Result<(), EngineError> {
        {
            let mut state = self.shared.lock_state();
            if !state.close_once(terminal) {
                return Ok(());
            }
        }
        let result = if terminal.is_some() {
            self.shared.transport.cancel()
        } else {
            self.shared.transport.reset()
        };
        self.shared.changed.notify_waiters();
        result
    }

    fn fail(&self, error: EngineError) {
        let _ = self.terminate(Some(error));
    }

    fn check_open(&self) -> Result<(), EngineError> {
        self.shared.lock_state().check_open()
    }

    fn is_closed(&self) -> bool {
        self.shared.lock_state().closed
    }

    fn record_activity(&self) -> Result<(), EngineError> {
        {
            let mut state = self.shared.lock_state();
            state.check_open()?;
            state.last_activity = Instant::now();
        }
        self.shared.changed.notify_waiters();
        Ok(())
    }

    fn operation_deadline(&self, deadline: Deadline) -> Result<Deadline, EngineError> {
        let error = {
            let mut state = self.shared.lock_state();
            state.check_open()?;
            let idle_expires_at = state
                .last_activity
                .checked_add(self.shared.options.idle_timeout)
                .ok_or(EngineError::InvalidConfig)?;
            let deadline = Deadline::at(deadline.expires_at().min(idle_expires_at));
            match deadline.remaining() {
                Ok(_) => return Ok(deadline),
                Err(error) => {
                    state.close_once(Some(error));
                    error
                }
            }
        };
        let _ = self.shared.transport.cancel();
        self.shared.changed.notify_waiters();
        Err(error)
    }

    async fn run<T, F>(&self, deadline: Deadline, operation: F) -> Result<T, EngineError>
    where
        F: Future<Output = Result<T, EngineError>>,
    {
        tokio::pin!(operation);
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            // Register before checking state so closure and idle updates cannot be lost.
            changed.as_mut().enable();
            let current_deadline = self.operation_deadline(deadline)?;
            tokio::select! {
                biased;
                result = &mut operation => {
                    self.check_open()?;
                    let value = result?;
                    self.operation_deadline(deadline)?;
                    return Ok(value);
                }
                _ = &mut changed => {}
                _ = tokio::time::sleep_until(current_deadline.expires_at()) => {}
            }
        }
    }
}

impl Drop for DatagramShared {
    fn drop(&mut self) {
        let _ = self.transport.reset();
    }
}

impl DatagramAssociation {
    /// Opens a capsule flow by the deadline and checks the peer's UDP negotiation.
    /// Unreliable delivery is unsupported by this binding.
    pub async fn open_h2(
        session: &H2Session,
        proxy: &str,
        target: &Destination,
        credential: &Credential,
        options: DatagramOptions,
        deadline: Deadline,
    ) -> Result<Self, EngineError> {
        let _ = options.max_payload()?;
        deadline.remaining()?;
        if !session.extended_connect_enabled() {
            return Err(EngineError::UnsupportedCapability);
        }
        let _request_reservation = options.reserve(OPEN_METADATA_RESERVE_BYTES)?;
        let request = connect_udp_template(proxy, target)?;
        let transport = session
            .open_request_with_deadline(request, credential, deadline)
            .await?;
        Self::from_h2(transport, options)
    }

    fn from_h2(
        mut transport: H2Connect,
        mut options: DatagramOptions,
    ) -> Result<Self, EngineError> {
        let result = match transport.status() {
            StatusCode::SERVICE_UNAVAILABLE => Err(EngineError::ResourceLimitExceeded),
            StatusCode::GATEWAY_TIMEOUT => Err(EngineError::DeadlineExceeded),
            status => classify_connect_status(status),
        };
        if let Err(error) = result {
            let _ = transport.reset();
            return Err(error);
        }
        if !capsule_protocol_enabled(transport.response_headers()) {
            let _ = transport.reset();
            return Err(EngineError::UnsupportedCapability);
        }
        if let Err(error) =
            validate_capsule_response(transport.status(), transport.response_headers())
        {
            let _ = transport.reset();
            return Err(error);
        }
        if let Some(remote_limit) = negotiated_datagram_payload(transport.response_headers())? {
            options.path_payload_limit = Some(
                options
                    .path_payload_limit
                    .unwrap_or(usize::MAX)
                    .min(remote_limit),
            );
        }
        let max_payload = options.max_payload()?;
        let read_buffer_len = options.limits.stream_queue_per_direction.min(8 * 1024);
        let BudgetedBuffer {
            bytes: read_buffer,
            _reservation: read_reservation,
        } = BudgetedBuffer::new(&options, read_buffer_len)?;
        let decoder = DatagramDecoder::new(max_payload)?;
        // Include the strong and weak counters of the shared Arc allocation.
        let shared_charge = std::mem::size_of::<DatagramShared>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .ok_or(EngineError::ResourceLimitExceeded)?;
        let shared_reservation = options.reserve(shared_charge)?;
        let generation = options.generation;
        let control = DatagramControl {
            shared: Arc::new(DatagramShared {
                transport: transport.control(),
                options,
                state: Mutex::new(DatagramState {
                    last_activity: Instant::now(),
                    terminal: None,
                    closed: false,
                }),
                changed: Notify::new(),
                _reservation: shared_reservation,
            }),
        };
        let (read_transport, write_transport) = transport.into_split();
        Ok(Self {
            drop_guard: DatagramAssociationCloseGuard {
                control: control.clone(),
                reset_on_drop: true,
            },
            sender: DatagramSendHalf {
                transport: write_transport,
                control: control.clone(),
                max_payload,
                generation,
            },
            receiver: DatagramRecvHalf {
                read: Some(DatagramReadState {
                    decoder,
                    read_buffer,
                    read_offset: 0,
                    read_len: 0,
                    _read_reservation: read_reservation,
                }),
                transport: read_transport,
                control,
                max_payload,
                generation,
            },
        })
    }

    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::ReliableEncapsulation
    }

    /// Maximum payload bytes accepted by `send`, excluding capsule framing.
    /// The H2 capsule allowance is capped by queue, local, and peer path limits.
    pub const fn max_payload(&self) -> usize {
        self.sender.max_payload
    }

    /// The session generation supplied when this association was opened.
    pub const fn generation(&self) -> u64 {
        self.sender.generation
    }

    /// Consumes the association into independent send and receive owners.
    /// Both share inactivity, terminal errors, and close or cancellation control.
    pub fn into_split(mut self) -> (DatagramSendHalf, DatagramRecvHalf) {
        self.drop_guard.reset_on_drop = false;
        (self.sender, self.receiver)
    }

    /// Returns a control that can close or cancel independently pending IO.
    pub fn control(&self) -> DatagramControl {
        self.sender.control()
    }

    /// Submits one complete datagram, including an empty payload.
    ///
    /// `Queued` means all capsule bytes were accepted locally by H2. Remote UDP
    /// delivery remains unconfirmed. Oversize returns `MessageTooLarge`; a failed
    /// memory reservation returns `Dropped` before submission.
    ///
    /// Once submission starts, cancellation or an error closes the association.
    /// Accepted stream bytes cannot be recalled.
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        let operation = DatagramAssociationOperation { association: self };
        operation.association.sender.send(payload, deadline).await
    }

    /// Returns the next complete datagram for context ID zero, including empty payloads.
    /// Unknown kinds and nonzero contexts within their size limits are skipped.
    /// A read or decode failure, or dropping a pending receive, closes the association.
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        let operation = DatagramAssociationOperation { association: self };
        operation.association.receiver.recv(deadline).await
    }

    /// Requests an H2 reset, closes the association, and releases its receive buffers.
    /// Repeated calls succeed. This does not wait for peer acknowledgment.
    pub fn close(&mut self) -> Result<(), EngineError> {
        self.receiver.close()
    }

    /// Closes an open association with `Cancelled` as its terminal error.
    /// Calls on an already closed association succeed without changing its state.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.receiver.cancel()
    }
}

impl DatagramSendHalf {
    /// Reports reliable H2 capsule delivery.
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::ReliableEncapsulation
    }

    /// Returns the negotiated payload ceiling in bytes, excluding capsule framing.
    pub const fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Returns the generation supplied when the association was opened.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns shared close and cancellation control for both directions.
    pub fn control(&self) -> DatagramControl {
        self.control.clone()
    }

    /// Sends with the submission and cancellation contract of [`DatagramAssociation::send`].
    /// The receive half can run concurrently.
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        self.control.check_open()?;
        if payload.len() > self.max_payload {
            return Err(EngineError::MessageTooLarge);
        }
        self.control.operation_deadline(deadline)?;
        let capsule_len = capsule_wire_len(payload.len())?;
        let reservation = match self.control.shared.options.reserve(capsule_len) {
            Ok(reservation) => reservation,
            Err(EngineError::ResourceLimitExceeded) => return Ok(DatagramOutcome::Dropped),
            Err(error) => return Err(error),
        };
        let capsule = encode_datagram_capsule(CONNECT_UDP_CONTEXT_ID, payload)?;
        if capsule.capacity() > reservation.bytes() {
            return Err(EngineError::ResourceLimitExceeded);
        }
        let control = self.control.clone();
        let mut operation = DatagramOperationGuard {
            control: control.clone(),
            cancel_on_drop: true,
        };
        let result = control
            .run(deadline, async {
                let mut offset = 0;
                while offset < capsule.len() {
                    control.operation_deadline(deadline)?;
                    let written = self.transport.write(&capsule[offset..]).await?;
                    if written == 0 {
                        return Err(EngineError::TransferStalled);
                    }
                    offset += written;
                }
                control.operation_deadline(deadline)?;
                Ok(())
            })
            .await;
        match result {
            Ok(()) => {
                control.record_activity()?;
                operation.cancel_on_drop = false;
                Ok(DatagramOutcome::Queued)
            }
            Err(error) => {
                control.fail(error);
                Err(error)
            }
        }
    }

    /// Closes both directions with the semantics of [`DatagramControl::close`].
    pub fn close(&mut self) -> Result<(), EngineError> {
        self.control.close()
    }

    /// Cancels both directions with the semantics of [`DatagramControl::cancel`].
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.control.cancel()
    }
}

impl DatagramRecvHalf {
    /// Reports reliable H2 capsule delivery.
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::ReliableEncapsulation
    }

    /// Returns the negotiated payload ceiling in bytes, excluding capsule framing.
    pub const fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Returns the generation supplied when the association was opened.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns shared close and cancellation control for both directions.
    pub fn control(&self) -> DatagramControl {
        self.control.clone()
    }

    /// Receives with the payload and cancellation contract of [`DatagramAssociation::recv`].
    /// The send half can run concurrently.
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        if let Err(error) = self.control.check_open() {
            self.clear();
            return Err(error);
        }
        if let Err(error) = self.control.operation_deadline(deadline) {
            if self.control.is_closed() {
                self.clear();
            }
            return Err(error);
        }
        let mut read = self.read.take().ok_or(EngineError::ProtocolViolation)?;
        let control = self.control.clone();
        let mut operation = DatagramOperationGuard {
            control: control.clone(),
            cancel_on_drop: true,
        };
        let result = control
            .run(deadline, async {
                loop {
                    control.operation_deadline(deadline)?;
                    if read.read_offset < read.read_len {
                        let (consumed, datagram) = read.decoder.feed(
                            &read.read_buffer[read.read_offset..read.read_len],
                            &control.shared.options,
                        )?;
                        if consumed == 0 {
                            return Err(EngineError::ProtocolViolation);
                        }
                        read.read_offset += consumed;
                        if let Some(datagram) = datagram {
                            control.operation_deadline(deadline)?;
                            return Ok(datagram.into_payload());
                        }
                        continue;
                    }
                    match self.transport.read(&mut read.read_buffer).await? {
                        ReadOutcome::Data(length) => {
                            read.read_offset = 0;
                            read.read_len = length;
                        }
                        ReadOutcome::Eof => {
                            read.decoder.finish()?;
                            return Err(EngineError::TransportUnavailable);
                        }
                        ReadOutcome::Reset => return Err(EngineError::RemoteReset),
                        ReadOutcome::Cancelled => return Err(EngineError::Cancelled),
                        ReadOutcome::Truncated => return Err(EngineError::TruncatedStream),
                        ReadOutcome::Waiting => return Err(EngineError::TransferStalled),
                    }
                }
            })
            .await;
        match result {
            Ok(payload) => {
                if let Err(error) = control.record_activity() {
                    self.clear();
                    return Err(error);
                }
                self.read = Some(read);
                operation.cancel_on_drop = false;
                Ok(payload)
            }
            Err(error) => {
                control.fail(error);
                self.clear();
                Err(error)
            }
        }
    }

    /// Closes both directions and releases this half's receive buffers.
    pub fn close(&mut self) -> Result<(), EngineError> {
        let result = self.control.close();
        self.clear();
        result
    }

    /// Cancels both directions and releases this half's receive buffers.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        let result = self.control.cancel();
        self.clear();
        result
    }

    fn clear(&mut self) {
        self.read = None;
        self.transport.release_terminal_headers();
    }
}

struct DatagramOperationGuard {
    control: DatagramControl,
    cancel_on_drop: bool,
}

impl Drop for DatagramOperationGuard {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            // An interrupted capsule cannot be followed by another message.
            self.control.fail(EngineError::Cancelled);
        }
    }
}

struct DatagramAssociationCloseGuard {
    control: DatagramControl,
    reset_on_drop: bool,
}

impl Drop for DatagramAssociationCloseGuard {
    fn drop(&mut self) {
        if self.reset_on_drop {
            let _ = self.control.close();
        }
    }
}

struct DatagramAssociationOperation<'a> {
    association: &'a mut DatagramAssociation,
}

impl Drop for DatagramAssociationOperation<'_> {
    fn drop(&mut self) {
        if self.association.sender.control.is_closed() {
            self.association.receiver.clear();
        }
    }
}

/// Checks request syntax and credentials, opens UDP, and relays until the flow ends.
///
/// `open` must authorize the destination and any resolved peer, return a connected
/// socket that prevents IP fragmentation, and honor the supplied deadline. Work
/// that survives cancellation must stay bounded. Its result contains the socket,
/// a guard retained until this handler ends, and a payload limit in `1..=65_507`
/// bytes excluding IP and UDP headers.
///
/// Opening is capped by `config.open_timeout` and credential validity; a peer
/// reset cancels the open future. Credential validity also bounds the relay.
/// A sent rejection response returns `Ok(())`; handler or relay failures return an error.
pub async fn handle_h2_connect_udp<A, F, Fut, G>(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    authorizer: Arc<A>,
    config: H2Config,
    open: F,
) -> Result<(), EngineError>
where
    A: Authorizer + Send + Sync + 'static,
    F: FnOnce(AuthzDecision, Destination, Deadline) -> Fut,
    Fut: Future<Output = Result<(UdpSocket, G, usize), EngineError>>,
    G: Send + 'static,
{
    let _target_reservation = match config.reserve_memory(OPEN_METADATA_RESERVE_BYTES) {
        Ok(reservation) => reservation,
        Err(error) => return reject_udp(&mut respond, error),
    };
    let target = match target_of_connect_udp(&request) {
        Ok(target) => target,
        Err(error) => return reject_udp(&mut respond, error),
    };
    let decision = match check_h2_credential(&request, &*authorizer) {
        Ok(decision) => decision,
        Err(error) => return reject_udp(&mut respond, error),
    };
    let authorization_deadline = Deadline::after(decision.valid_for)?;
    let deadline = authorization_deadline.cap(config.open_timeout)?;
    let expected_peer = target
        .as_ip()
        .map(|address| std::net::SocketAddr::new(address, target.port()));
    let _pending_open = match config.reserve_open() {
        Ok(permit) => permit,
        Err(error) => return reject_udp(&mut respond, error),
    };
    let opened = tokio::select! {
        result = deadline.run(open(decision, target, deadline)) => result,
        reset = poll_fn(|cx| respond.poll_reset(cx)) => {
            return Err(reset.map_or_else(map_h2, |_| EngineError::RemoteReset));
        }
    };
    let (socket, _target_guard, target_payload_limit) = match opened {
        Ok(opened) => opened,
        Err(error) => return reject_udp(&mut respond, error),
    };
    let peer = match socket.peer_addr() {
        Ok(peer) => peer,
        Err(_) => return reject_udp(&mut respond, EngineError::TargetConnectFailed),
    };
    if expected_peer.is_some_and(|expected| normalized_peer(peer) != normalized_peer(expected)) {
        return reject_udp(&mut respond, EngineError::EgressDenied);
    }
    let mut options = DatagramOptions::from_h2_config(&config, 0, false);
    if target_payload_limit == 0 || target_payload_limit > options.limits.udp_payload_absolute_max {
        return reject_udp(&mut respond, EngineError::UnsupportedCapability);
    }
    options.path_payload_limit = Some(target_payload_limit);
    let prepared = match PreparedRelay::new(&options) {
        Ok(prepared) => prepared,
        Err(error) => return reject_udp(&mut respond, error),
    };
    if let Err(error) = authorization_deadline.remaining() {
        return reject_udp(&mut respond, error);
    }
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(
            CAPSULE_PROTOCOL,
            HeaderValue::from_static(CAPSULE_PROTOCOL_ENABLED),
        )
        .header(MAX_DATAGRAM_PAYLOAD, prepared.max_payload.to_string())
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    attach_h2_versions(response.headers_mut())?;
    let outbound = respond.send_response(response, false).map_err(map_h2)?;
    drop(_pending_open);
    authorization_deadline
        .run(relay_prepared(
            request.into_body(),
            outbound,
            socket,
            options,
            prepared,
            (config.max_header_count, config.max_header_bytes),
            Some(authorization_deadline),
        ))
        .await
}

struct OutboundCapsule {
    bytes: Bytes,
    offset: usize,
}

struct BudgetedBuffer {
    bytes: Vec<u8>,
    _reservation: ScopedMemoryReservation,
}

impl BudgetedBuffer {
    fn new(options: &DatagramOptions, length: usize) -> Result<Self, EngineError> {
        let reservation = options.reserve(length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| EngineError::ResourceLimitExceeded)?;
        if bytes.capacity() > reservation.bytes() {
            return Err(EngineError::ResourceLimitExceeded);
        }
        bytes.resize(length, 0);
        Ok(Self {
            bytes,
            _reservation: reservation,
        })
    }
}

impl AsRef<[u8]> for BudgetedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

struct RelaySender {
    stream: h2::SendStream<Bytes>,
    end_stream_sent: bool,
}

impl Drop for RelaySender {
    fn drop(&mut self) {
        if !self.end_stream_sent {
            self.stream.send_reset(h2::Reason::CANCEL);
        }
    }
}

/// Relays complete capsules for context ID zero to one connected UDP peer and back.
/// Empty UDP messages are preserved. Oversized UDP receives and UDP errors
/// classified as `MessageTooLarge` are dropped; capsule size or payload violations
/// fail the relay.
///
/// The caller must authorize the peer and prevent IP fragmentation on the socket.
/// Use `options.path_payload_limit` to cap payloads for the target path. An active
/// relay resets H2 output on error or cancellation; normal client EOF ends it.
/// Trailer count and bytes use `options.limits.decoded_header_fields` and
/// `options.limits.decoded_header_bytes`, including HTTP/2 field overhead.
pub async fn relay_h2_udp(
    inbound: RecvStream,
    outbound: h2::SendStream<Bytes>,
    socket: UdpSocket,
    options: DatagramOptions,
) -> Result<(), EngineError> {
    let prepared = PreparedRelay::new(&options)?;
    let header_limits = (
        options.limits.decoded_header_fields,
        options.limits.decoded_header_bytes,
    );
    relay_prepared(
        inbound,
        outbound,
        socket,
        options,
        prepared,
        header_limits,
        None,
    )
    .await
}

struct PreparedRelay {
    max_payload: usize,
    decoder: DatagramDecoder,
    udp_buffer: BudgetedBuffer,
}

impl PreparedRelay {
    fn new(options: &DatagramOptions) -> Result<Self, EngineError> {
        let max_payload = options.max_payload()?;
        // The extra byte lets an oversized UDP receive fail the payload check.
        let udp_buffer_len = max_payload
            .checked_add(1)
            .ok_or(EngineError::InvalidConfig)?;
        let udp_buffer = BudgetedBuffer::new(options, udp_buffer_len)?;
        Ok(Self {
            max_payload,
            decoder: DatagramDecoder::new(max_payload)?,
            udp_buffer,
        })
    }
}

async fn relay_prepared(
    mut inbound: RecvStream,
    outbound: h2::SendStream<Bytes>,
    socket: UdpSocket,
    options: DatagramOptions,
    prepared: PreparedRelay,
    header_limits: (usize, usize),
    lifetime_deadline: Option<Deadline>,
) -> Result<(), EngineError> {
    let PreparedRelay {
        max_payload,
        mut decoder,
        mut udp_buffer,
    } = prepared;
    let (max_header_count, max_header_bytes) = header_limits;
    let pinned_peer = socket
        .peer_addr()
        .map_err(|_| EngineError::TargetConnectFailed)?;
    let mut outbound = RelaySender {
        stream: outbound,
        end_stream_sent: false,
    };
    let mut inbound_bytes = Bytes::new();
    let mut toward_udp: Option<CapsuleDatagram> = None;
    let mut toward_client: Option<OutboundCapsule> = None;
    let mut inbound_open = true;
    let mut idle_deadline = Deadline::after(options.idle_timeout)?;
    loop {
        if let Some(deadline) = lifetime_deadline {
            deadline.remaining()?;
        }
        idle_deadline.remaining()?;
        if socket
            .peer_addr()
            .map_err(|_| EngineError::TargetConnectFailed)?
            != pinned_peer
        {
            return Err(EngineError::ProtocolViolation);
        }
        if !inbound_open && toward_client.is_none() {
            outbound
                .stream
                .send_data(Bytes::new(), true)
                .map_err(map_h2)?;
            outbound.end_stream_sent = true;
            return Ok(());
        }
        if toward_udp.is_none() && !inbound_bytes.is_empty() {
            let (consumed, datagram) = decoder.feed(&inbound_bytes, &options)?;
            if consumed == 0 {
                return Err(EngineError::ProtocolViolation);
            }
            inbound
                .flow_control()
                .release_capacity(consumed)
                .map_err(map_h2)?;
            inbound_bytes = if consumed == inbound_bytes.len() {
                Bytes::new()
            } else {
                inbound_bytes.slice(consumed..)
            };
            toward_udp = datagram;
        }
        if let Some(capsule) = &toward_client {
            outbound
                .stream
                .reserve_capacity(capsule.bytes.len() - capsule.offset);
        }
        tokio::select! {
            _ = tokio::time::sleep_until(idle_deadline.expires_at()) => {
                return Err(EngineError::DeadlineExceeded);
            }
            sent = async {
                let datagram = toward_udp.as_ref().ok_or(EngineError::ProtocolViolation)?;
                socket.send(datagram.payload()).await.map_err(|error| map_udp_error(&error))
            }, if toward_udp.is_some() => {
                let sent = match sent {
                    Ok(sent) => sent,
                    Err(EngineError::MessageTooLarge) => {
                        toward_udp = None;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let length = toward_udp.as_ref().ok_or(EngineError::ProtocolViolation)?.payload().len();
                if sent != length {
                    return Err(EngineError::TargetConnectFailed);
                }
                toward_udp = None;
                idle_deadline = Deadline::after(options.idle_timeout)?;
            }
            progress = poll_fn(|cx| {
                if let std::task::Poll::Ready(reset) = outbound.stream.poll_reset(cx) {
                    return std::task::Poll::Ready(Err(reset.map_or_else(map_h2, |_| EngineError::RemoteReset)));
                }
                if toward_client.is_none() {
                    return std::task::Poll::Pending;
                }
                poll_send_capacity(&mut outbound.stream, cx)
            }) => {
                let capacity = progress?;
                if capacity == 0 {
                    return Err(EngineError::TransferStalled);
                }
                let capsule = toward_client.as_mut().ok_or(EngineError::ProtocolViolation)?;
                let length = capacity.min(capsule.bytes.len() - capsule.offset);
                let bytes = capsule.bytes.slice(capsule.offset..capsule.offset + length);
                outbound.stream.send_data(bytes, false).map_err(map_h2)?;
                capsule.offset += length;
                if capsule.offset == capsule.bytes.len() {
                    toward_client = None;
                }
                idle_deadline = Deadline::after(options.idle_timeout)?;
            }
            received = socket.recv(&mut udp_buffer.bytes), if inbound_open && toward_client.is_none() => {
                let length = match received {
                    Ok(length) => length,
                    Err(error) if map_udp_error(&error) == EngineError::MessageTooLarge => continue,
                    Err(_) => return Err(EngineError::TargetConnectFailed),
                };
                if length <= max_payload {
                    let wire_size = capsule_wire_len(length)?;
                    if let Ok(reservation) = options.reserve(crate::retained_bytes_charge::<BudgetedBuffer>(wire_size)?) {
                        let bytes = encode_datagram_capsule(CONNECT_UDP_CONTEXT_ID, &udp_buffer.bytes[..length])?;
                        if crate::retained_bytes_charge::<BudgetedBuffer>(bytes.capacity())? > reservation.bytes() {
                            return Err(EngineError::ResourceLimitExceeded);
                        }
                        toward_client = Some(OutboundCapsule {
                            bytes: Bytes::from_owner(BudgetedBuffer {
                                bytes, _reservation: reservation,
                            }), offset: 0,
                        });
                    }
                }
                idle_deadline = Deadline::after(options.idle_timeout)?;
            }
            chunk = async {
                let chunk = inbound.data().await.transpose().map_err(map_h2)?;
                if chunk.is_none()
                    && let Some(trailers) = inbound.trailers().await.map_err(map_h2)?
                {
                    check_header_limits_with_bounds(
                        &trailers,
                        &[],
                        max_header_count,
                        max_header_bytes,
                    )?;
                }
                Ok::<_, EngineError>(chunk)
            }, if inbound_open && inbound_bytes.is_empty() && toward_udp.is_none() => {
                match chunk? {
                    Some(chunk) => {
                        if !chunk.is_empty() {
                            if chunk.len() > options.limits.stream_queue_per_direction {
                                return Err(EngineError::ResourceLimitExceeded);
                            }
                            let reservation = options.reserve(crate::retained_bytes_charge::<BudgetedBuffer>(chunk.len())?)?;
                            let mut bytes = Vec::new();
                            bytes.try_reserve_exact(chunk.len()).map_err(|_| EngineError::ResourceLimitExceeded)?;
                            if crate::retained_bytes_charge::<BudgetedBuffer>(bytes.capacity())? > reservation.bytes() {
                                return Err(EngineError::ResourceLimitExceeded);
                            }
                            bytes.extend_from_slice(&chunk);
                            inbound_bytes = Bytes::from_owner(BudgetedBuffer { bytes, _reservation: reservation });
                        }
                    }
                    None => {
                        decoder.finish()?;
                        inbound_open = false;
                    }
                }
            }
            _ = tokio::task::yield_now(), if toward_udp.is_none() && !inbound_bytes.is_empty() => {}
        }
    }
}

fn capsule_wire_len(payload_len: usize) -> Result<usize, EngineError> {
    payload_len
        .checked_add(wire_overhead(false, CONNECT_UDP_CONTEXT_ID, payload_len)?)
        .ok_or(EngineError::MessageTooLarge)
}

fn reject_udp(respond: &mut SendResponse<Bytes>, error: EngineError) -> Result<(), EngineError> {
    let status = match error {
        EngineError::AuthenticationDenied
        | EngineError::EgressDenied
        | EngineError::AuthorizationUnavailable => StatusCode::FORBIDDEN,
        EngineError::TargetConnectFailed | EngineError::TargetResolutionFailed => {
            StatusCode::BAD_GATEWAY
        }
        EngineError::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        EngineError::ResourceLimitExceeded => StatusCode::SERVICE_UNAVAILABLE,
        EngineError::UnsupportedCapability => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::BAD_REQUEST,
    };
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    respond.send_response(response, true).map_err(map_h2)?;
    Ok(())
}

fn normalized_peer(peer: std::net::SocketAddr) -> std::net::SocketAddr {
    let address = ariad_core::normalize_ip(peer.ip());
    if address == peer.ip() {
        peer
    } else {
        std::net::SocketAddr::new(address, peer.port())
    }
}

fn map_udp_error(error: &std::io::Error) -> EngineError {
    #[cfg(windows)]
    if error.raw_os_error() == Some(10_040) {
        // Winsock reports truncated datagrams as WSAEMSGSIZE.
        return EngineError::MessageTooLarge;
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64"
        )
    ))]
    if error.raw_os_error() == Some(90) {
        return EngineError::MessageTooLarge;
    }
    let _ = error;
    EngineError::TargetConnectFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::attach_credential;
    use crate::h2_tunnel::serve_h2_with_handler;
    use crate::host::StaticAuthorizer;
    use ariad_core::ResourceBudget;
    use http::HeaderMap;

    fn options() -> DatagramOptions {
        let config = H2Config {
            process_budget: MemoryBudget::new(128 * 1024).unwrap(),
            session_budget: MemoryBudget::new(128 * 1024).unwrap(),
            ..H2Config::default()
        };
        DatagramOptions::from_h2_config(&config, 7, false)
    }

    fn deadline() -> Deadline {
        Deadline::after(Duration::from_secs(3)).unwrap()
    }

    enum RelayEnd {
        Trailers(HeaderMap),
        Reset,
    }

    fn trailers(fields: usize, value_bytes: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_bytes(&vec![b'v'; value_bytes]).unwrap();
        for _ in 0..fields {
            headers.append("x-trailer", value.clone());
        }
        headers
    }

    async fn relay_trailer_case(
        raw: bool,
        max_header_count: usize,
        max_header_bytes: usize,
        end: RelayEnd,
        truncated: bool,
    ) -> (Result<(), EngineError>, bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let process = MemoryBudget::new(1024 * 1024).unwrap();
            let session_memory = MemoryBudget::new(1024 * 1024).unwrap();
            let process_opens = ResourceBudget::new(8).unwrap();
            let session_opens = ResourceBudget::new(8).unwrap();
            let config = H2Config {
                max_header_count,
                max_header_bytes,
                process_budget: process.clone(),
                session_budget: session_memory.clone(),
                process_opens: process_opens.clone(),
                session_opens: session_opens.clone(),
                ..H2Config::default()
            };
            let mut relay_options = DatagramOptions::from_h2_config(&config, 0, false);
            relay_options.limits.decoded_header_fields = max_header_count;
            relay_options.limits.decoded_header_bytes = max_header_bytes;
            relay_options.path_payload_limit = Some(1200);
            let partial_relay_charge = relay_options.max_payload().unwrap()
                + 1
                + if raw { 0 } else { OPEN_METADATA_RESERVE_BYTES }
                + crate::retained_bytes_charge::<CapsuleDatagram>(4).unwrap();
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(target_address).await.unwrap();
            let credential = Credential::from_bytes([0x11; 32]);
            let authorizer = Arc::new(StaticAuthorizer::new(Credential::from_bytes([0x11; 32]), 1));
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (relay_done, receive_relay_done) = tokio::sync::oneshot::channel();
            let (peer_done, mut receive_peer_done) = tokio::sync::oneshot::channel();
            let server = async {
                let mut builder = h2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder
                    .handshake::<_, Bytes>(server_io)
                    .await
                    .unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                let relay = async move {
                    if raw {
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .header(CAPSULE_PROTOCOL, "?1")
                            .body(())
                            .unwrap();
                        let outbound = respond.send_response(response, false).unwrap();
                        relay_h2_udp(request.into_body(), outbound, socket, relay_options).await
                    } else {
                        handle_h2_connect_udp(
                            request,
                            respond,
                            authorizer,
                            config,
                            move |_, _, _| async move { Ok((socket, (), 1200)) },
                        )
                        .await
                    }
                };
                tokio::pin!(relay);
                let result = tokio::select! {
                    result = &mut relay => result,
                    incoming = connection.accept() => {
                        panic!("connection ended before relay completion: {incoming:?}");
                    }
                };
                relay_done.send(()).unwrap();
                tokio::select! {
                    done = &mut receive_peer_done => done.unwrap(),
                    incoming = connection.accept() => {
                        match incoming {
                            None => {}
                            Some(Err(error)) => assert!(error.is_io(), "unexpected close: {error}"),
                            Some(Ok(_)) => panic!("unexpected request"),
                        }
                        receive_peer_done.await.unwrap();
                    }
                }
                result
            };
            let client = async {
                let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
                let peer = async {
                    while !client.is_extended_connect_protocol_enabled() {
                        tokio::task::yield_now().await;
                    }
                    let destination = Destination::Ip {
                        addr: target_address.ip(),
                        port: target_address.port(),
                    };
                    let mut request = connect_udp_template("proxy.example", &destination).unwrap();
                    attach_credential(&mut request, &credential).unwrap();
                    let (response, mut request_body) = client.send_request(request, false).unwrap();
                    let response = response.await.unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    let capsule = if truncated {
                        Bytes::from_static(&[0, 4, 0, b'a'])
                    } else {
                        Bytes::from(encode_datagram_capsule(0, b"complete").unwrap())
                    };
                    request_body.send_data(capsule, false).unwrap();
                    if matches!(&end, RelayEnd::Reset) {
                        // The reset must arrive after the decoder retains the partial capsule.
                        while process.used() != partial_relay_charge {
                            tokio::task::yield_now().await;
                        }
                    }
                    match end {
                        RelayEnd::Trailers(trailers) => request_body.send_trailers(trailers).unwrap(),
                        RelayEnd::Reset => request_body.send_reset(h2::Reason::CANCEL),
                    }
                    let mut response_body = response.into_body();
                    let reset = loop {
                        match response_body.data().await {
                            Some(Ok(chunk)) => assert!(chunk.is_empty()),
                            Some(Err(error)) => {
                                assert!(error.is_reset(), "unexpected stream error: {error}");
                                assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
                                break true;
                            }
                            None => {
                                assert!(response_body.trailers().await.unwrap().is_none());
                                break false;
                            }
                        }
                    };
                    receive_relay_done.await.unwrap();
                    peer_done.send(()).unwrap();
                    reset
                };
                tokio::select! {
                    reset = peer => reset,
                    result = connection => panic!("client connection ended before relay: {result:?}"),
                }
            };
            let outcome = tokio::join!(server, client);
            assert_eq!(process.used(), 0);
            assert_eq!(session_memory.used(), 0);
            assert_eq!(process_opens.used(), 0);
            assert_eq!(session_opens.used(), 0);
            drop(target);
            outcome
        })
        .await
        .expect("relay trailer completion")
    }

    #[tokio::test]
    async fn udp_trailer_field_limits_count_duplicate_values_at_the_boundary() {
        for raw in [false, true] {
            for max_header_count in [16, 64] {
                for fields in [max_header_count, max_header_count + 1] {
                    let rejected = fields > max_header_count;
                    let (result, reset) = relay_trailer_case(
                        raw,
                        max_header_count,
                        32 * 1024,
                        RelayEnd::Trailers(trailers(fields, 1)),
                        rejected,
                    )
                    .await;
                    assert_eq!(
                        result,
                        if rejected {
                            Err(EngineError::ResourceLimitExceeded)
                        } else {
                            Ok(())
                        },
                        "raw {raw}, fields {fields}"
                    );
                    assert_eq!(reset, rejected);
                }
            }
        }
    }

    #[tokio::test]
    async fn udp_trailer_byte_limits_include_field_overhead_before_capsule_finish() {
        let max_header_bytes = 4096;
        let value_bytes = max_header_bytes - 32 - "x-trailer".len();
        for raw in [false, true] {
            for excess in [0, 1] {
                let (result, reset) = relay_trailer_case(
                    raw,
                    16,
                    max_header_bytes,
                    RelayEnd::Trailers(trailers(1, value_bytes + excess)),
                    excess != 0,
                )
                .await;
                assert_eq!(
                    result,
                    if excess == 0 {
                        Ok(())
                    } else {
                        Err(EngineError::ResourceLimitExceeded)
                    },
                    "raw {raw}, excess {excess}"
                );
                assert_eq!(reset, excess != 0);
            }
        }
    }

    #[tokio::test]
    async fn udp_relay_reset_releases_decoder_and_open_quotas() {
        for raw in [false, true] {
            let (result, reset) = relay_trailer_case(raw, 16, 4096, RelayEnd::Reset, true).await;
            assert_eq!(result, Err(EngineError::RemoteReset));
            assert!(reset);
        }
    }

    #[tokio::test]
    async fn h2_capsule_responses_reject_forbidden_headers_and_preserve_authentication_errors() {
        for (status, forbidden_header, expected) in [
            (StatusCode::OK, None, Ok(())),
            (
                StatusCode::OK,
                Some(http::header::CONTENT_TYPE),
                Err(EngineError::ProtocolViolation),
            ),
            (
                StatusCode::OK,
                Some(http::header::CONTENT_LENGTH),
                Err(EngineError::ProtocolViolation),
            ),
            (
                StatusCode::UNAUTHORIZED,
                Some(http::header::CONTENT_TYPE),
                Err(EngineError::AuthenticationDenied),
            ),
            (
                StatusCode::FORBIDDEN,
                Some(http::header::CONTENT_LENGTH),
                Err(EngineError::AuthenticationDenied),
            ),
        ] {
            tokio::time::timeout(Duration::from_secs(3), async {
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let (reset_seen, receive_reset) = tokio::sync::oneshot::channel();
                let server = async {
                    let mut builder = h2::server::Builder::new();
                    builder.enable_connect_protocol();
                    let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
                    let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
                    let mut response = Response::builder()
                        .status(status)
                        .header(CAPSULE_PROTOCOL, "?1")
                        .body(())
                        .unwrap();
                    if let Some(name) = &forbidden_header {
                        let value = if name == http::header::CONTENT_LENGTH {
                            HeaderValue::from_static("0")
                        } else {
                            HeaderValue::from_static("application/octet-stream")
                        };
                        response.headers_mut().insert(name.clone(), value);
                    }
                    attach_h2_versions(response.headers_mut()).unwrap();
                    let mut body = respond.send_response(response, false).unwrap();
                    let reason = tokio::select! {
                        reset = poll_fn(|cx| body.poll_reset(cx)) => reset.unwrap(),
                        incoming = connection.accept() => {
                            panic!("connection ended before Capsule reset: {incoming:?}");
                        }
                    };
                    assert_eq!(reason, h2::Reason::CANCEL);
                    reset_seen.send(()).unwrap();
                    match connection.accept().await {
                        None => {}
                        Some(Err(error)) => assert!(error.is_io(), "unexpected close: {error}"),
                        Some(Ok(_)) => panic!("unexpected request"),
                    }
                };
                let client = async {
                    let session = H2Session::handshake(client_io, true).await.unwrap();
                    let destination = Destination::parse("1.1.1.1:53").unwrap();
                    let credential = Credential::from_bytes([0x11; 32]);
                    let options = options();
                    let process = options.process_memory.clone();
                    let session_memory = options.session_memory.clone();
                    let result = DatagramAssociation::open_h2(
                        &session,
                        "proxy.example",
                        &destination,
                        &credential,
                        options,
                        deadline(),
                    )
                    .await
                    .map(drop);
                    assert_eq!(
                        result, expected,
                        "status {status}, header {forbidden_header:?}"
                    );
                    receive_reset.await.unwrap();
                    assert_eq!(process.used(), 0);
                    assert_eq!(session_memory.used(), 0);
                    session.cancel();
                    assert_eq!(
                        session.close(Duration::from_secs(3)).await,
                        Err(EngineError::Cancelled)
                    );
                };
                tokio::join!(server, client);
            })
            .await
            .expect("Capsule response completion");
        }
    }

    fn capsule_with_zero_context(width: usize, payload: &[u8]) -> Vec<u8> {
        let mut context = [0u8; 8];
        context[0] = match width {
            1 => 0,
            2 => 0x40,
            4 => 0x80,
            8 => 0xc0,
            _ => panic!("invalid context width"),
        };
        let value_len = u64::try_from(width + payload.len()).expect("capsule length");
        let length = ariad_core::VarInt::encode(value_len).expect("capsule length encoding");
        let mut wire = vec![0];
        wire.extend_from_slice(length.as_slice());
        wire.extend_from_slice(&context[..width]);
        wire.extend_from_slice(payload);
        wire
    }

    #[test]
    fn zero_context_widths_accept_empty_and_maximum_payloads_at_every_chunk_size() {
        let options = options();
        for max_payload in [0, 1, 63, 64, 127, 128] {
            for width in [1, 2, 4, 8] {
                for payload_len in [0, max_payload] {
                    let expected = vec![0x5a; payload_len];
                    let wire = capsule_with_zero_context(width, &expected);
                    for chunk_size in 1..=wire.len() {
                        let mut decoder = DatagramDecoder::new(max_payload).unwrap();
                        let mut received = None;
                        for chunk in wire.chunks(chunk_size) {
                            let (consumed, datagram) = decoder.feed(chunk, &options).unwrap();
                            assert_eq!(consumed, chunk.len());
                            if let Some(datagram) = datagram {
                                assert!(received.is_none());
                                received = Some(datagram);
                            }
                        }
                        decoder.finish().unwrap();
                        let payload = received.expect("complete datagram").into_payload();
                        assert_eq!(
                            payload.as_bytes(),
                            expected,
                            "width {width}, max {max_payload}, chunk {chunk_size}"
                        );
                        let charge =
                            crate::retained_bytes_charge::<CapsuleDatagram>(width + payload_len)
                                .unwrap();
                        assert_eq!(options.process_memory.used(), charge);
                        assert_eq!(options.session_memory.used(), charge);
                        drop(payload);
                        assert_eq!(options.process_memory.used(), 0);
                        assert_eq!(options.session_memory.used(), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn every_context_width_rejects_one_byte_past_the_payload_limit() {
        let options = options();
        for max_payload in [0, 1, 63, 64, 127, 128] {
            for width in [1, 2, 4, 8] {
                let wire = capsule_with_zero_context(width, &vec![0x5a; max_payload + 1]);
                for chunk_size in 1..=wire.len() {
                    let mut decoder = DatagramDecoder::new(max_payload).unwrap();
                    let mut failure = None;
                    for chunk in wire.chunks(chunk_size) {
                        match decoder.feed(chunk, &options) {
                            Ok((consumed, None)) => assert_eq!(consumed, chunk.len()),
                            Ok((_, Some(_))) => panic!("oversized payload accepted"),
                            Err(error) => {
                                failure = Some(error);
                                break;
                            }
                        }
                    }
                    assert_eq!(
                        failure,
                        Some(EngineError::MessageTooLarge),
                        "width {width}, max {max_payload}, chunk {chunk_size}"
                    );
                    assert_eq!(options.process_memory.used(), 0);
                    assert_eq!(options.session_memory.used(), 0);
                    drop(decoder);
                }
            }
        }
    }

    #[test]
    fn decoder_reservation_lives_until_delivery_or_close() {
        let options = options();
        let charge = crate::retained_bytes_charge::<CapsuleDatagram>(4).unwrap();
        let mut decoder = DatagramDecoder::new(128).unwrap();
        let (consumed, datagram) = decoder.feed(&[0, 4, 0, b'a'], &options).unwrap();
        assert_eq!(consumed, 4);
        assert!(datagram.is_none());
        assert_eq!(options.process_memory.used(), charge);
        assert_eq!(options.session_memory.used(), charge);
        let (_, datagram) = decoder.feed(b"bc", &options).unwrap();
        let datagram = datagram.unwrap();
        assert_eq!(datagram.payload(), b"abc");
        assert_eq!(options.session_memory.used(), charge);
        let payload = datagram.into_payload();
        assert_eq!(payload.as_bytes(), b"abc");
        assert_eq!(options.session_memory.used(), charge);
        let tail = payload.clone().into_bytes().slice(2..);
        drop(payload);
        assert_eq!(options.session_memory.used(), charge);
        drop(tail);
        assert_eq!(options.session_memory.used(), 0);
        decoder.feed(&[0, 8, 0], &options).unwrap();
        assert_eq!(
            options.session_memory.used(),
            crate::retained_bytes_charge::<CapsuleDatagram>(8).unwrap()
        );
        drop(decoder);
        assert_eq!(options.session_memory.used(), 0);
    }

    #[test]
    fn unsupported_context_is_dropped_with_its_reservation() {
        let options = options();
        let mut decoder = DatagramDecoder::new(128).unwrap();
        let wire = encode_datagram_capsule(1, b"ignored").unwrap();
        let (consumed, datagram) = decoder.feed(&wire, &options).unwrap();
        assert_eq!(consumed, wire.len());
        assert!(datagram.is_none());
        assert_eq!(options.process_memory.used(), 0);
    }

    #[test]
    fn transport_slices_retain_full_backing_allocation_budget() {
        let options = options();
        let charge = crate::retained_bytes_charge::<BudgetedBuffer>(8).unwrap();
        let reservation = options.reserve(charge).unwrap();
        let bytes = Bytes::from_owner(BudgetedBuffer {
            bytes: vec![0; 8],
            _reservation: reservation,
        });
        let tail = bytes.slice(7..);
        drop(bytes);
        assert_eq!(options.process_memory.used(), charge);
        drop(tail);
        assert_eq!(options.process_memory.used(), 0);
    }

    #[test]
    fn unreliable_requirement_is_rejected_before_allocating() {
        let mut options = options();
        options.require_unreliable = true;
        assert_eq!(
            options.max_payload(),
            Err(EngineError::UnsupportedCapability)
        );
        assert_eq!(options.process_memory.used(), 0);
    }

    #[test]
    fn target_payload_limit_can_only_reduce_capsule_and_queue_limits() {
        let mut options = options();
        let capsule_limit = options.max_payload().unwrap();
        options.path_payload_limit = Some(1200);
        assert_eq!(options.max_payload(), Ok(1200));
        options.path_payload_limit = Some(65_507);
        assert_eq!(options.max_payload(), Ok(capsule_limit));
        options.limits.udp_queue_bytes = 900;
        assert_eq!(options.max_payload(), Ok(900));
        options.path_payload_limit = Some(0);
        assert_eq!(
            options.max_payload(),
            Err(EngineError::UnsupportedCapability)
        );
    }

    #[tokio::test]
    async fn split_h2_capsules_deliver_whole_datagrams_only_to_pinned_udp_peer() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let credential = Credential::from_bytes([0x11; 32]);
        let authorizer = Arc::new(StaticAuthorizer::new(Credential::from_bytes([0x11; 32]), 1));
        let (socket_address, receive_socket_address) = tokio::sync::oneshot::channel();
        let socket_address = Arc::new(std::sync::Mutex::new(Some(socket_address)));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_h2_with_handler(
            server_io,
            H2Config::default(),
            move |request, respond, config| {
                let authorizer = Arc::clone(&authorizer);
                let socket_address = Arc::clone(&socket_address);
                async move {
                    handle_h2_connect_udp(
                        request,
                        respond,
                        authorizer,
                        config,
                        move |_decision, destination, _deadline| async move {
                            assert_eq!(
                                destination,
                                Destination::Ip {
                                    addr: target_address.ip(),
                                    port: target_address.port()
                                }
                            );
                            let socket = UdpSocket::bind("127.0.0.1:0")
                                .await
                                .map_err(|_| EngineError::TargetConnectFailed)?;
                            socket
                                .connect(target_address)
                                .await
                                .map_err(|_| EngineError::TargetConnectFailed)?;
                            let address = socket
                                .local_addr()
                                .map_err(|_| EngineError::TargetConnectFailed)?;
                            if let Some(sender) = socket_address.lock().unwrap().take() {
                                let _ = sender.send(address);
                            }
                            Ok((socket, (), 1200))
                        },
                    )
                    .await
                }
            },
            async move {
                let _ = stopped.await;
            },
        ));
        let session = H2Session::handshake(client_io, true).await.unwrap();
        let destination = Destination::Ip {
            addr: target_address.ip(),
            port: target_address.port(),
        };
        let association = DatagramAssociation::open_h2(
            &session,
            "proxy.example",
            &destination,
            &credential,
            DatagramOptions::from_h2_config(session.config(), 7, false),
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(
            association.delivery_mode(),
            DeliveryMode::ReliableEncapsulation
        );
        assert_eq!(association.generation(), 7);
        assert_eq!(association.max_payload(), 1200);
        let (mut sender, mut receiver) = association.into_split();
        assert_eq!(sender.max_payload(), receiver.max_payload());
        assert_eq!(sender.generation(), receiver.generation());
        let relay_address = deadline()
            .run(async {
                receive_socket_address
                    .await
                    .map_err(|_| EngineError::TransportUnavailable)
            })
            .await
            .unwrap();
        let mut received = [0; 1024];
        for payload in [&b"first"[..], &b"first"[..], &b""[..], &b"last"[..]] {
            let receive = receiver.recv(deadline());
            tokio::pin!(receive);
            assert!(
                poll_fn(|cx| { std::task::Poll::Ready(receive.as_mut().poll(cx).is_pending()) })
                    .await
            );
            let (datagram, ()) = tokio::join!(receive, async {
                assert_eq!(
                    sender.send(payload, deadline()).await.unwrap(),
                    DatagramOutcome::Queued
                );
                let (length, peer) = deadline()
                    .run(async {
                        target
                            .recv_from(&mut received)
                            .await
                            .map_err(|_| EngineError::TargetConnectFailed)
                    })
                    .await
                    .unwrap();
                assert_eq!(&received[..length], payload);
                assert_eq!(peer, relay_address);
                foreign.send_to(b"spoof", relay_address).await.unwrap();
                target.send_to(payload, peer).await.unwrap();
            });
            assert_eq!(datagram.unwrap().as_bytes(), payload);
        }
        receiver.control().close().unwrap();
        assert_eq!(
            sender.send(b"closed", deadline()).await,
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(
            receiver.recv(deadline()).await,
            Err(EngineError::ProtocolViolation)
        );
        let _ = stop.send(());
        session.close(Duration::from_secs(3)).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Ok(()) | Err(EngineError::RemoteReset)),
            "unexpected server result: {result:?}"
        );
    }
}
