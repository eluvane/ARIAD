#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use ariad_core::{
    BindingId, BudgetLimits, CapsuleDecoder, Credential, DATAGRAM_CAPSULE, DatagramOutcome,
    DeadlineKind, DeliveryMode, Destination, EndpointDescriptor, EngineError,
    ScopedMemoryReservation, ScopedResourceReservation, VarInt, decode_varint, lab_cap,
    split_http_datagram,
};
use bytes::Bytes;
use http::uri::{Authority, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use quiche::h3::{Header, NameValue};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

use crate::Deadline;
use crate::connect::{
    EXPERIMENTAL_H2_BINDING_VERSION_HEADER, EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
    PROTOCOL_VERSION_TEXT, VersionText, attach_credential, connect_template, single_header_value,
};
use crate::datagram::DatagramPayload;
use crate::dir::ReadOutcome;
use crate::h2_tunnel::H2Config;
use crate::masque::{
    CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED, CONNECT_UDP, CONNECT_UDP_CONTEXT_ID,
    MAX_DATAGRAM_PAYLOAD, capsule_protocol_enabled, connect_udp_template,
    negotiated_datagram_payload, target_of_connect_udp_unversioned, validate_capsule_response,
};
use crate::native_tls::{NativeTlsConnector, NativeTlsServer};
use crate::response::classify_connect_status;
use crate::tls_policy::H3_ALPN;
use crate::trust::EchState;

pub const EXPERIMENTAL_H3_BINDING_VERSION_HEADER: &str = "x-ariad-h3-binding-version";
const H3_BINDING_VERSION: u16 = 0;
static H3_BINDING_VERSION_TEXT: VersionText = VersionText::new(H3_BINDING_VERSION);
const H3_VERSION_HEADERS: [(&str, &VersionText); 2] = [
    (
        EXPERIMENTAL_H3_BINDING_VERSION_HEADER,
        &H3_BINDING_VERSION_TEXT,
    ),
    (EXPERIMENTAL_PROTOCOL_VERSION_HEADER, &PROTOCOL_VERSION_TEXT),
];

const BODY_CHUNK_BYTES: usize = 16 * 1024;
const RECEIVE_PACKET_BYTES: usize = 65_535;
const SEND_PACKET_BYTES: usize = 1200;
const WORK_BATCH: usize = 64;
const CONTROL_STREAM_COUNT: usize = 3;
const CHANNEL_BLOCK_SLOTS: usize = 32;
const METADATA_RESERVE_BYTES: usize = 4096;
const CANCEL_CODE: u64 = 0x10c;
const H3_DATAGRAM_ERROR: u64 = 0x33;
const REQUEST_STREAM_ID_STRIDE: u64 = 4;
const MAX_QUARTER_STREAM_ID: u64 = ((1 << 62) - 1) / REQUEST_STREAM_ID_STRIDE;
// quiche 0.30 limits each CRYPTO receive level to 64 KiB.
const CRYPTO_BUFFER_BYTES: usize = 3 * 65_536;

pub(crate) fn require_safe_logging() -> Result<(), EngineError> {
    // quiche 0.30 QPACK logs header values at TRACE. Runtime filters can change,
    // so require a static ceiling before driver I/O.
    if log::STATIC_MAX_LEVEL > log::LevelFilter::Info {
        return Err(EngineError::UnsupportedCapability);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct H3Config {
    /// Application queue and protocol limits for this binding.
    pub limits: BudgetLimits,
    /// Budget pools, connection window, and operation timeouts.
    /// Memory caps in `limits` must match these pools. Session flow and open
    /// pools can enforce stricter caps.
    pub h2: H2Config,
    /// QUIC idle timeout. Zero disables the timeout.
    pub idle_timeout: Duration,
    /// CONNECT-UDP idle limit, starting at flow creation. Received datagrams
    /// that pass the flow's checks and queued sends restart the limit.
    pub datagram_idle_timeout: Duration,
}

impl H3Config {
    pub fn from_h2_config(h2: &H2Config) -> Result<Self, EngineError> {
        h2.validate()?;
        let mut limits = BudgetLimits::lab_small();
        limits.decoded_header_bytes = h2.max_header_bytes;
        limits.decoded_header_fields = h2.max_header_count;
        limits.stream_queue_per_direction = h2.direction_buffer_bytes;
        limits.control_reserve = h2.control_reserve_bytes;
        limits.active_flows_per_session = h2.max_concurrent_streams;
        limits.pending_egress_opens = h2.max_pending_opens;
        limits.session_application_budget = h2.session_budget.limit();
        limits.global_application_budget = h2.process_budget.limit();
        let config = Self {
            limits,
            h2: h2.clone(),
            idle_timeout: Duration::ZERO,
            datagram_idle_timeout: lab_cap(DeadlineKind::IdleUdp),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), EngineError> {
        self.limits.validate()?;
        self.h2.validate()?;
        if self.idle_timeout.as_millis() > u64::MAX as u128
            || self.datagram_idle_timeout.is_zero()
            || Instant::now()
                .checked_add(self.datagram_idle_timeout)
                .is_none()
            || Instant::now().checked_add(self.idle_timeout).is_none()
            || self.limits.stream_queue_per_direction < BODY_CHUNK_BYTES
            || self.limits.udp_queue_bytes < RECEIVE_PACKET_BYTES
            || self.limits.active_flows_per_session > self.h2.max_concurrent_streams
            || self.limits.session_application_budget != self.h2.session_budget.limit()
            || self.limits.global_application_budget != self.h2.process_budget.limit()
            || self.h2.session_opens.limit() > self.limits.pending_egress_opens
            || self.h2.session_flows.limit() > self.limits.active_flows_per_session
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }

    fn reserve(&self, bytes: usize) -> Result<ScopedMemoryReservation, EngineError> {
        self.h2.reserve_memory(bytes)
    }

    fn reserve_owned(&self, capacity: usize) -> Result<ScopedMemoryReservation, EngineError> {
        self.reserve(crate::retained_bytes_charge::<ChargedBuffer>(capacity)?)
    }

    fn native_datagram_capacity(&self) -> usize {
        self.limits
            .udp_queue_datagrams
            .min(self.limits.udp_queue_bytes / RECEIVE_PACKET_BYTES)
    }

    fn configure(&self, quic: &mut quiche::Config) -> Result<(), EngineError> {
        self.validate()?;
        quic.set_application_protos(&[H3_ALPN]).map_err(map_quic)?;
        quic.set_max_idle_timeout(self.idle_timeout.as_millis() as u64);
        quic.set_max_recv_udp_payload_size(RECEIVE_PACKET_BYTES);
        quic.set_max_send_udp_payload_size(SEND_PACKET_BYTES);
        quic.set_initial_max_data(u64::from(self.h2.initial_connection_window));
        quic.set_max_connection_window(u64::from(self.h2.initial_connection_window));
        quic.set_initial_max_stream_data_bidi_local(self.limits.stream_queue_per_direction as u64);
        quic.set_initial_max_stream_data_bidi_remote(self.limits.stream_queue_per_direction as u64);
        quic.set_max_stream_window(self.limits.stream_queue_per_direction as u64);
        quic.set_initial_max_stream_data_uni(self.limits.control_reserve as u64);
        quic.set_initial_max_streams_bidi(self.h2.session_flows.limit() as u64);
        quic.set_initial_max_streams_uni(CONTROL_STREAM_COUNT as u64);
        quic.set_disable_active_migration(true);
        quic.enable_dgram(
            true,
            self.native_datagram_capacity(),
            self.native_datagram_capacity(),
        );
        Ok(())
    }

    fn native_reservation(&self) -> Result<ScopedMemoryReservation, EngineError> {
        // Fixed charge for QUIC receive windows and driver buffers. This is not
        // an RSS bound; allocator metadata and TLS certificate objects are excluded.
        let reservation_bytes = (self.h2.initial_connection_window as usize)
            .checked_add(
                self.limits
                    .control_reserve
                    .checked_mul(CONTROL_STREAM_COUNT)
                    .ok_or(EngineError::ResourceLimitExceeded)?,
            )
            .and_then(|reservation_bytes| {
                reservation_bytes.checked_add(
                    self.native_datagram_capacity()
                        .checked_mul(RECEIVE_PACKET_BYTES)?,
                )
            })
            .and_then(|reservation_bytes| {
                reservation_bytes
                    .checked_add(RECEIVE_PACKET_BYTES + SEND_PACKET_BYTES + BODY_CHUNK_BYTES)
            })
            .and_then(|reservation_bytes| reservation_bytes.checked_add(CRYPTO_BUFFER_BYTES))
            .ok_or(EngineError::ResourceLimitExceeded)?;
        self.reserve(reservation_bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DriverState {
    Connecting,
    Ready {
        extended_connect: bool,
        native_datagram: bool,
        max_datagram_bytes: usize,
    },
    Draining,
    Closing(EngineError),
    Closed(Result<(), EngineError>),
}

struct SessionControl {
    commands: mpsc::Sender<Command>,
    wake: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
    state: watch::Receiver<DriverState>,
    task: Mutex<Option<JoinHandle<()>>>,
    config: H3Config,
    _metadata: Arc<ScopedMemoryReservation>,
}

impl SessionControl {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.wake.notify_one();
    }
}

impl Drop for SessionControl {
    fn drop(&mut self) {
        self.cancel();
        if let Ok(task) = self.task.get_mut()
            && let Some(task) = task.take()
        {
            // The close deadline bounds a detached task. Keep its CLOSE packet alive.
            if !matches!(*self.state.borrow(), DriverState::Closing(_)) {
                task.abort();
            }
        }
    }
}

/// A client session whose clones and CONNECT handles share one UDP driver.
#[derive(Clone)]
pub struct H3Session {
    endpoint: Arc<EndpointDescriptor>,
    shared: Arc<SessionControl>,
    address: SocketAddr,
}

/// A session for one peer. Dropping it requests driver cancellation.
pub struct H3ServerSession {
    incoming: mpsc::Receiver<H3Incoming>,
    shared: Arc<SessionControl>,
    address: SocketAddr,
}

/// A CONNECT request awaiting a response.
///
/// The caller must authenticate, authorize, and open the target before a
/// successful response. Dropping an unanswered request requests stream reset.
pub struct H3Incoming {
    pub request: Request<()>,
    shared: Weak<SessionControl>,
    handle: Option<FlowHandle>,
    datagram: bool,
    _allocation: ScopedMemoryReservation,
}

/// A CONNECT body. Dropping an unfinished handle requests stream reset.
pub struct H3Connect {
    read: H3ReadHalf,
    write: H3WriteHalf,
    status: StatusCode,
}

/// The read direction of a CONNECT body. Dropping it discards received data and
/// leaves a live write half usable.
pub struct H3ReadHalf {
    read_events: mpsc::Receiver<ReadEvent>,
    unread_body: Bytes,
    buffered_body_bytes: Arc<AtomicUsize>,
    // Drop receive storage before its metadata reservation.
    owner: Arc<ConnectOwner>,
}

/// The write direction of a CONNECT body. Call `end_write` to send FIN.
/// Dropping this half alone leaves a live read half usable.
pub struct H3WriteHalf {
    owner: Arc<ConnectOwner>,
}

/// A control handle that does not retain the session or flow permits.
#[derive(Clone)]
pub struct H3StreamControl {
    owner: Weak<ConnectOwner>,
    // Weak controls retain the Arc allocation after the I/O owners drop.
    _handle_memory: Arc<ScopedMemoryReservation>,
}

struct ConnectOwner {
    shared: Arc<SessionControl>,
    id: u64,
    status: StatusCode,
    response_headers: HeaderMap,
    read_finished: AtomicBool,
    write_closed: AtomicBool,
    read_abandoned: Arc<AtomicBool>,
    flow_terminal: Arc<Mutex<Option<EngineError>>>,
    _response_memory: Option<ScopedMemoryReservation>,
    _handle_memory: Arc<ScopedMemoryReservation>,
}

/// A CONNECT-UDP association that sends native QUIC DATAGRAM frames.
pub struct H3DatagramAssociation {
    send: H3DatagramSendHalf,
    recv: H3DatagramRecvHalf,
}

/// The send direction of a native datagram association.
pub struct H3DatagramSendHalf {
    generation: u64,
    max_payload: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    stream: H3WriteHalf,
}

/// The receive direction of a native datagram association. Dropping it discards
/// queued payloads and leaves a live send half usable.
pub struct H3DatagramRecvHalf {
    receives: mpsc::Receiver<Bytes>,
    generation: u64,
    max_payload: Arc<AtomicUsize>,
    queued_datagram_bytes: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    stream: H3ReadHalf,
}

/// A control handle that closes both datagram directions without waiting for I/O.
#[derive(Clone)]
pub struct H3DatagramControl {
    closed: Arc<AtomicBool>,
    stream: H3StreamControl,
}

struct ChargedBuffer {
    bytes: Vec<u8>,
    offset: usize,
    _allocation: ScopedMemoryReservation,
}

impl AsRef<[u8]> for ChargedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
}

// BufFactory cannot reject allocations. Its slice-copy callbacks use the fixed
// native charge; application-owned buffers carry separate reservations.
#[derive(Clone, Default, Debug)]
struct NativeBufFactory;

impl quiche::BufFactory for NativeBufFactory {
    type Buf = Bytes;
    type DgramBuf = Bytes;

    fn buf_from_slice(bytes: &[u8]) -> Bytes {
        Bytes::copy_from_slice(bytes)
    }

    fn dgram_buf_from_slice(bytes: &[u8]) -> Bytes {
        Self::buf_from_slice(bytes)
    }
}

enum ReadEvent {
    Data(Bytes),
    Finished,
    Reset,
}

struct FlowHandle {
    id: u64,
    status: StatusCode,
    headers: HeaderMap,
    read_events: mpsc::Receiver<ReadEvent>,
    buffered_body_bytes: Arc<AtomicUsize>,
    read_abandoned: Arc<AtomicBool>,
    datagrams: Option<mpsc::Receiver<Bytes>>,
    max_payload: Arc<AtomicUsize>,
    queued_datagram_bytes: Arc<AtomicUsize>,
    terminal: Arc<Mutex<Option<EngineError>>>,
    response_memory: Option<ScopedMemoryReservation>,
    handle_memory: Arc<ScopedMemoryReservation>,
}

enum Command {
    Open {
        headers: Vec<Header>,
        datagram: bool,
        deadline: Deadline,
        completion: oneshot::Sender<Result<FlowHandle, EngineError>>,
        allocation: ScopedMemoryReservation,
        flow_permit: ScopedResourceReservation,
        open_permit: ScopedResourceReservation,
    },
    Write {
        id: u64,
        bytes: Bytes,
        fin: bool,
        deadline: Deadline,
        completion: oneshot::Sender<Result<usize, EngineError>>,
    },
    Datagram {
        id: u64,
        bytes: Bytes,
        deadline: Deadline,
        completion: oneshot::Sender<Result<DatagramOutcome, EngineError>>,
    },
    Respond {
        id: u64,
        status: StatusCode,
        deadline: Deadline,
        completion: oneshot::Sender<Result<(), EngineError>>,
    },
    Reset {
        id: u64,
    },
    Drain {
        deadline: Deadline,
    },
}

struct PendingWrite {
    bytes: Bytes,
    fin: bool,
    deadline: Deadline,
    completion: oneshot::Sender<Result<usize, EngineError>>,
}

struct PendingResponse {
    status: StatusCode,
    deadline: Deadline,
    completion: oneshot::Sender<Result<(), EngineError>>,
}

struct Flow {
    read_sender: mpsc::Sender<ReadEvent>,
    // Includes queued body data and the handle's partially read chunk.
    buffered_body_bytes: Arc<AtomicUsize>,
    read_abandoned: Arc<AtomicBool>,
    datagrams: Option<mpsc::Sender<Bytes>>,
    max_payload: Arc<AtomicUsize>,
    queued_datagram_bytes: Arc<AtomicUsize>,
    peer_max_payload: usize,
    open_completion: Option<oneshot::Sender<Result<FlowHandle, EngineError>>>,
    // Client handles wait here for a final response. Server handles belong to H3Incoming.
    handle: Option<FlowHandle>,
    opening_deadline: Option<Deadline>,
    pending_write: Option<PendingWrite>,
    readable: bool,
    remote_finished: bool,
    local_finished: bool,
    read_finish_attempted: bool,
    // Clients require a successful response. Servers require queued final headers.
    response_ready: bool,
    datagram: bool,
    _allocation: Option<ScopedMemoryReservation>,
    _flow_permit: ScopedResourceReservation,
    open_permit: Option<ScopedResourceReservation>,
    pending_response: Option<PendingResponse>,
    terminal: Arc<Mutex<Option<EngineError>>>,
    capsules: Option<CapsuleDecoder>,
    capsule_allocation: Option<ScopedMemoryReservation>,
    datagram_idle_deadline: Option<Deadline>,
    _handle_memory: Arc<ScopedMemoryReservation>,
}

impl Flow {
    fn datagram_ready(&self) -> bool {
        self.datagram && self.response_ready && !self.remote_finished
    }

    fn fail_pending_operations(&mut self, error: EngineError) {
        set_terminal(&self.terminal, error);
        if let Some(completion) = self.open_completion.take() {
            let _ = completion.send(Err(error));
        }
        if let Some(write) = self.pending_write.take() {
            let _ = write.completion.send(Err(error));
        }
        if let Some(response) = self.pending_response.take() {
            let _ = response.completion.send(Err(error));
        }
    }
}

struct PendingPacket {
    length: usize,
    info: quiche::SendInfo,
}

struct Driver {
    connection: quiche::Connection<NativeBufFactory>,
    http: Option<quiche::h3::Connection>,
    socket: UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    config: H3Config,
    commands: mpsc::Receiver<Command>,
    flows: BTreeMap<u64, Flow>,
    // A strong reference would keep SessionControl alive after all external handles drop.
    shared: Weak<SessionControl>,
    wake: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
    status: watch::Sender<DriverState>,
    incoming: Option<mpsc::Sender<H3Incoming>>,
    trust: Option<NativeTlsConnector>,
    startup_deadline: Deadline,
    draining_deadline: Option<Deadline>,
    peer_goaway: bool,
    receive_packet: Vec<u8>,
    send_packet: Vec<u8>,
    pending_packet: Option<PendingPacket>,
    socket_send_blocked: bool,
    pending_opens: VecDeque<Command>,
    goaway_id: u64,
    goaway_sent: bool,
    receive_body: Vec<u8>,
    close_requested: bool,
    connection_error: Option<EngineError>,
    _native_memory: ScopedMemoryReservation,
    _metadata: Arc<ScopedMemoryReservation>,
}

async fn connect_socket(
    socket: &UdpSocket,
    peer: SocketAddr,
    deadline: Deadline,
) -> Result<SocketAddr, EngineError> {
    deadline
        .run(async {
            socket
                .connect(peer)
                .await
                .map_err(|_| EngineError::TransportUnavailable)
        })
        .await?;
    socket
        .local_addr()
        .map_err(|_| EngineError::TransportUnavailable)
}

impl H3Session {
    /// Connect the socket and wait for verified TLS, HTTP/3, and peer SETTINGS.
    /// The handshake timeout caps `deadline`. Compiled DEBUG or TRACE logging
    /// returns `UnsupportedCapability` before socket I/O or budget reservations.
    pub async fn connect(
        socket: UdpSocket,
        endpoint: &EndpointDescriptor,
        peer: SocketAddr,
        trust: &NativeTlsConnector,
        config: H3Config,
        deadline: Deadline,
    ) -> Result<Self, EngineError> {
        require_safe_logging()?;
        trust.validate_endpoint(endpoint, BindingId::H3)?;
        config.validate()?;
        if peer.port() == 0 {
            return Err(EngineError::InvalidConfig);
        }
        let deadline = deadline.cap(config.h2.handshake_timeout)?;
        let local = connect_socket(&socket, peer, deadline).await?;
        let native_memory = config.native_reservation()?;
        let mut quic_config = trust.quiche_config()?;
        config.configure(&mut quic_config)?;
        let mut cid = [0u8; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut cid).map_err(|_| EngineError::TransportUnavailable)?;
        let cid = quiche::ConnectionId::from_ref(&cid);
        let server_name = if endpoint.identity_hostname.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(endpoint.identity_hostname.as_str())
        };
        let mut connection = quiche::connect_with_buffer_factory::<NativeBufFactory>(
            server_name,
            &cid,
            local,
            peer,
            &mut quic_config,
        )
        .map_err(map_quic)?;
        trust.configure_quiche_identity(&mut connection, endpoint)?;
        let metadata = shared_metadata_reservation(&config, false)?;
        let (shared, driver) = make_driver(
            connection,
            socket,
            local,
            peer,
            DriverSetup {
                config,
                deadline,
                trust: Some(trust.clone()),
                incoming: None,
                native_memory,
                metadata,
            },
        )?;
        spawn_driver(&shared, driver)?;
        wait_ready(&shared, deadline).await?;
        deadline.remaining()?;
        Ok(Self {
            shared,
            endpoint: Arc::new(endpoint.clone()),
            address: peer,
        })
    }

    pub fn endpoint(&self) -> &EndpointDescriptor {
        &self.endpoint
    }
    pub fn endpoint_id(&self) -> u64 {
        self.endpoint.id
    }
    pub fn trust_group(&self) -> u64 {
        self.endpoint.trust_group
    }
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
    pub const fn binding(&self) -> BindingId {
        BindingId::H3
    }
    pub const fn ech(&self) -> EchState {
        EchState::Unsupported
    }

    pub fn native_datagram_enabled(&self) -> bool {
        matches!(
            *self.shared.state.borrow(),
            DriverState::Ready {
                native_datagram: true,
                ..
            }
        )
    }

    pub fn extended_connect_enabled(&self) -> bool {
        matches!(
            *self.shared.state.borrow(),
            DriverState::Ready {
                extended_connect: true,
                ..
            }
        )
    }

    /// Return the driver error, or `TransportUnavailable` after a normal close.
    pub fn driver_error(&self) -> Option<EngineError> {
        driver_error(&self.shared)
    }

    /// Wait until the driver releases its socket and native buffers. Handles may
    /// retain application buffers and metadata charges after this returns.
    pub async fn wait_closed(&self) -> Result<(), EngineError> {
        wait_closed(&self.shared).await
    }

    /// Request driver cancellation. `wait_closed` waits for it to stop.
    pub fn cancel(&self) {
        self.shared.cancel();
    }

    /// Request GOAWAY and drain existing flows within the drain timeout and `deadline`.
    pub async fn shutdown(&self, deadline: Deadline) -> Result<(), EngineError> {
        shutdown(&self.shared, deadline).await
    }

    /// Send CONNECT and wait for a successful final response. The open timeout
    /// caps `deadline`; a timeout can occur after the request has been sent.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
        credential: &Credential,
        deadline: Deadline,
    ) -> Result<H3Connect, EngineError> {
        let request = connect_template(destination)?;
        let handle = self
            .open_request(request, credential, false, deadline)
            .await?;
        Ok(connect_from_handle(self.shared.clone(), handle))
    }

    /// Open CONNECT-UDP with peer support for extended CONNECT and native DATAGRAM.
    /// The open timeout caps `deadline`. `generation` is local metadata.
    pub async fn open_datagram(
        &self,
        proxy: &str,
        target: &Destination,
        credential: &Credential,
        generation: u64,
        deadline: Deadline,
    ) -> Result<H3DatagramAssociation, EngineError> {
        if !self.native_datagram_enabled() || !self.extended_connect_enabled() {
            return Err(EngineError::UnsupportedCapability);
        }
        let request = connect_udp_template(proxy, target)?;
        let mut handle = self
            .open_request(request, credential, true, deadline)
            .await?;
        if !capsule_protocol_enabled(&handle.headers) {
            reset_command(&self.shared, handle.id)?;
            return Err(EngineError::UnsupportedCapability);
        }
        let Some(receives) = handle.datagrams.take() else {
            let _ = reset_command(&self.shared, handle.id);
            return Err(EngineError::ProtocolViolation);
        };
        let max_payload = handle.max_payload.clone();
        let queued_datagram_bytes = handle.queued_datagram_bytes.clone();
        Ok(datagram_from_stream(
            connect_from_handle(self.shared.clone(), handle),
            receives,
            generation,
            max_payload,
            queued_datagram_bytes,
        ))
    }

    async fn open_request(
        &self,
        mut request: Request<()>,
        credential: &Credential,
        datagram: bool,
        deadline: Deadline,
    ) -> Result<FlowHandle, EngineError> {
        request
            .headers_mut()
            .remove(EXPERIMENTAL_H2_BINDING_VERSION_HEADER);
        attach_h3_versions(request.headers_mut());
        attach_credential(&mut request, credential)?;
        let headers = request_headers(&request, datagram)?;
        check_ready(&self.shared)?;
        let deadline = deadline.cap(self.shared.config.h2.open_timeout)?;
        let header_bytes = header_size(&headers, &self.shared.config)?;
        let allocation = self.shared.config.reserve(
            header_bytes
                .checked_mul(2)
                .and_then(|size| size.checked_add(headers.len() * 32))
                .ok_or(EngineError::ResourceLimitExceeded)?,
        )?;
        let flow_permit = self.shared.config.h2.reserve_flow()?;
        let open_permit = self.shared.config.h2.reserve_open()?;
        let (completion, completion_rx) = oneshot::channel();
        let command = Command::Open {
            headers,
            datagram,
            deadline,
            completion,
            allocation,
            flow_permit,
            open_permit,
        };
        send_command(&self.shared, command, deadline).await?;
        let handle = wait_completion(&self.shared, completion_rx, deadline).await?;
        if let Err(error) = classify_connect_status(handle.status) {
            let _ = reset_command(&self.shared, handle.id);
            return Err(error);
        }
        Ok(handle)
    }
}

impl H3Connect {
    pub const fn status(&self) -> StatusCode {
        self.status
    }
    pub fn response_headers(&self) -> &HeaderMap {
        &self.read.owner.response_headers
    }

    /// Split into independently usable directions with one terminal state.
    /// The last I/O owner requests reset unless both directions finished.
    pub fn into_split(self) -> (H3ReadHalf, H3WriteHalf) {
        (self.read, self.write)
    }

    pub fn control(&self) -> H3StreamControl {
        self.read.control()
    }

    pub(crate) fn reserve_metadata(
        &self,
        bytes: usize,
    ) -> Result<ScopedMemoryReservation, EngineError> {
        self.read.owner.shared.config.reserve(bytes)
    }

    /// Return the number of body bytes accepted by QUIC, which may be less than
    /// the input length. This does not acknowledge receipt by the peer.
    /// Dropping a pending write future requests stream reset.
    pub async fn write(&mut self, bytes: &[u8], deadline: Deadline) -> Result<usize, EngineError> {
        self.write.write(bytes, deadline).await
    }

    /// Queue FIN and close the local write side when QUIC accepts it.
    pub async fn end_write(&mut self, deadline: Deadline) -> Result<(), EngineError> {
        self.write.end_write(deadline).await
    }

    /// Read body data or a terminal outcome. An empty output slice is rejected.
    /// Dropping a pending read preserves queued data. A deadline that expires
    /// while waiting for a read event marks the stream terminal.
    pub async fn read(
        &mut self,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<ReadOutcome, EngineError> {
        self.read.read(out, deadline).await
    }

    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.read.reset()
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.read.cancel()
    }
}

impl H3ReadHalf {
    pub fn control(&self) -> H3StreamControl {
        H3StreamControl {
            owner: Arc::downgrade(&self.owner),
            _handle_memory: self.owner._handle_memory.clone(),
        }
    }

    /// Read body data or a terminal outcome. Dropping a pending future preserves
    /// queued data. A timeout while waiting marks both directions terminal.
    pub async fn read(
        &mut self,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<ReadOutcome, EngineError> {
        deadline.remaining()?;
        if out.is_empty() {
            return Err(EngineError::ProtocolViolation);
        }
        loop {
            deadline.remaining()?;
            if let Some(error) = self.owner.terminal_error() {
                self.release_reads();
                return read_error(error);
            }
            if !self.unread_body.is_empty() {
                let length = out.len().min(self.unread_body.len());
                out[..length].copy_from_slice(&self.unread_body[..length]);
                self.unread_body = self.unread_body.slice(length..);
                self.buffered_body_bytes
                    .fetch_sub(length, Ordering::Relaxed);
                self.owner.shared.wake.notify_one();
                return Ok(ReadOutcome::Data(length));
            }
            if self.owner.read_finished.load(Ordering::Relaxed) {
                return Ok(ReadOutcome::Eof);
            }
            let received = deadline
                .run(async {
                    self.read_events.recv().await.ok_or_else(|| {
                        driver_error(&self.owner.shared).unwrap_or(EngineError::TruncatedStream)
                    })
                })
                .await;
            match received {
                Ok(ReadEvent::Data(bytes)) => self.unread_body = bytes,
                Ok(ReadEvent::Finished) => {
                    self.owner.read_finished.store(true, Ordering::Relaxed);
                }
                Ok(ReadEvent::Reset) => {
                    let error = self
                        .owner
                        .terminal_error()
                        .unwrap_or(EngineError::RemoteReset);
                    self.release_reads();
                    return read_error(error);
                }
                Err(error) => {
                    let error = self.owner.operation_error(error);
                    set_terminal(&self.owner.flow_terminal, error);
                    let _ = reset_command(&self.owner.shared, self.owner.id);
                    return read_error(error);
                }
            }
        }
    }

    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.finish(EngineError::RemoteReset)
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.finish(EngineError::Cancelled)
    }

    fn finish(&mut self, error: EngineError) -> Result<(), EngineError> {
        let first = self.owner.mark_terminal(error);
        self.release_reads();
        if first {
            reset_command(&self.owner.shared, self.owner.id)?;
        }
        Ok(())
    }

    fn release_reads(&mut self) {
        let unread_bytes = self.unread_body.len();
        self.unread_body = Bytes::new();
        self.buffered_body_bytes
            .fetch_sub(unread_bytes, Ordering::Relaxed);
        self.read_events.close();
        while let Ok(event) = self.read_events.try_recv() {
            if let ReadEvent::Data(bytes) = event {
                self.buffered_body_bytes
                    .fetch_sub(bytes.len(), Ordering::Relaxed);
            }
        }
    }
}

impl Drop for H3ReadHalf {
    fn drop(&mut self) {
        // Publish abandonment before closing the receiver, so the driver keeps the writer.
        self.owner.read_abandoned.store(true, Ordering::Release);
        self.release_reads();
        self.owner.shared.wake.notify_one();
    }
}

impl H3WriteHalf {
    pub fn control(&self) -> H3StreamControl {
        H3StreamControl {
            owner: Arc::downgrade(&self.owner),
            _handle_memory: self.owner._handle_memory.clone(),
        }
    }

    /// Accept a prefix into QUIC without acknowledging peer delivery.
    /// Dropping a pending future requests reset of both directions.
    pub async fn write(&mut self, bytes: &[u8], deadline: Deadline) -> Result<usize, EngineError> {
        deadline.remaining()?;
        self.check_write()?;
        if bytes.is_empty() {
            return Err(EngineError::ProtocolViolation);
        }
        let length = bytes.len().min(BODY_CHUNK_BYTES);
        let bytes = charged_copy(&self.owner.shared.config, &bytes[..length])?;
        self.write_buffer(bytes, false, deadline).await
    }

    /// Queue FIN and close the local write side when QUIC accepts it.
    pub async fn end_write(&mut self, deadline: Deadline) -> Result<(), EngineError> {
        deadline.remaining()?;
        self.check_write()?;
        self.write_buffer(Bytes::new(), true, deadline).await?;
        self.owner.write_closed.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), EngineError> {
        self.owner.finish(EngineError::RemoteReset)
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.owner.finish(EngineError::Cancelled)
    }

    async fn write_buffer(
        &mut self,
        bytes: Bytes,
        fin: bool,
        deadline: Deadline,
    ) -> Result<usize, EngineError> {
        let mut reset = ResetOnDrop::new(self.owner.shared.clone(), self.owner.id);
        let (completion, completion_rx) = oneshot::channel();
        send_command(
            &self.owner.shared,
            Command::Write {
                id: self.owner.id,
                bytes,
                fin,
                deadline,
                completion,
            },
            deadline,
        )
        .await
        .map_err(|error| {
            let error = self.owner.operation_error(error);
            set_terminal(&self.owner.flow_terminal, error);
            error
        })?;
        let write_outcome = wait_completion(&self.owner.shared, completion_rx, deadline)
            .await
            .map_err(|error| self.owner.operation_error(error));
        if let Err(error) = write_outcome {
            set_terminal(&self.owner.flow_terminal, error);
        } else {
            reset.disarm();
        }
        write_outcome
    }

    fn check_write(&self) -> Result<(), EngineError> {
        if let Some(error) = self.owner.terminal_error() {
            return Err(error);
        }
        if self.owner.write_closed.load(Ordering::Relaxed) || !self.owner.status.is_success() {
            return Err(EngineError::ProtocolViolation);
        }
        if let Some(error) = driver_error(&self.owner.shared) {
            return Err(error);
        }
        Ok(())
    }
}

impl H3StreamControl {
    /// Request reset of both directions. Returns `Cancelled` after the last I/O owner drops.
    pub fn reset(&self) -> Result<(), EngineError> {
        self.owner
            .upgrade()
            .ok_or(EngineError::Cancelled)?
            .finish(EngineError::RemoteReset)
    }

    /// Request cancellation of both directions and wake pending operations.
    pub fn cancel(&self) -> Result<(), EngineError> {
        self.owner
            .upgrade()
            .ok_or(EngineError::Cancelled)?
            .finish(EngineError::Cancelled)
    }
}

impl ConnectOwner {
    fn terminal_error(&self) -> Option<EngineError> {
        *self
            .flow_terminal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn operation_error(&self, error: EngineError) -> EngineError {
        if error == EngineError::DeadlineExceeded {
            error
        } else {
            self.terminal_error().unwrap_or(error)
        }
    }

    fn mark_terminal(&self, error: EngineError) -> bool {
        let first = set_terminal(&self.flow_terminal, error);
        if first {
            self.write_closed.store(true, Ordering::Relaxed);
        }
        first
    }

    fn finish(&self, error: EngineError) -> Result<(), EngineError> {
        if self.mark_terminal(error) {
            reset_command(&self.shared, self.id)?;
        }
        Ok(())
    }
}

impl Drop for ConnectOwner {
    fn drop(&mut self) {
        if self.terminal_error().is_none()
            && !(self.read_finished.load(Ordering::Relaxed)
                && self.write_closed.load(Ordering::Relaxed))
        {
            let _ = reset_command(&self.shared, self.id);
        }
    }
}

impl H3DatagramAssociation {
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::UnreliableNative
    }
    pub const fn generation(&self) -> u64 {
        self.send.generation
    }
    /// Latest payload ceiling in bytes, after QUIC/H3 overhead and peer limits.
    pub fn max_payload(&self) -> usize {
        self.send.max_payload()
    }

    /// Split into independently usable send and receive directions.
    /// Closing either half closes the association; dropping one keeps the other usable.
    pub fn into_split(self) -> (H3DatagramSendHalf, H3DatagramRecvHalf) {
        (self.send, self.recv)
    }

    pub fn control(&self) -> H3DatagramControl {
        self.send.control()
    }

    /// Queue one whole payload. `Queued` does not promise delivery; a timeout
    /// can occur after the datagram has entered the native send queue.
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        self.send.send(payload, deadline).await
    }

    /// Receive one payload. Its owner retains the memory charge after it leaves
    /// the receive queue, including when the payload is empty.
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        self.recv.recv(deadline).await
    }

    /// Discard queued receive payloads and cancel the CONNECT flow.
    pub fn close(&mut self) -> Result<(), EngineError> {
        self.recv.close()
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.close()
    }
}

impl H3DatagramSendHalf {
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::UnreliableNative
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn max_payload(&self) -> usize {
        self.max_payload.load(Ordering::Relaxed)
    }
    pub fn control(&self) -> H3DatagramControl {
        H3DatagramControl {
            stream: self.stream.control(),
            closed: self.closed.clone(),
        }
    }

    /// Queue one whole payload. Native delivery remains unacknowledged.
    /// A queued datagram can still be sent after the future is dropped.
    pub async fn send(
        &mut self,
        payload: &[u8],
        deadline: Deadline,
    ) -> Result<DatagramOutcome, EngineError> {
        deadline.remaining()?;
        self.check_open()?;
        if payload.len() > self.max_payload() {
            return Err(EngineError::MessageTooLarge);
        }
        let owner = &self.stream.owner;
        let quarter_stream_id = VarInt::encode(owner.id / REQUEST_STREAM_ID_STRIDE)?;
        let context = VarInt::encode(CONNECT_UDP_CONTEXT_ID)?;
        let size = payload
            .len()
            .checked_add(quarter_stream_id.as_slice().len() + context.as_slice().len())
            .ok_or(EngineError::MessageTooLarge)?;
        let allocation = match owner.shared.config.reserve_owned(size) {
            Ok(allocation) => allocation,
            Err(EngineError::ResourceLimitExceeded) => return Ok(DatagramOutcome::Dropped),
            Err(error) => return Err(error),
        };
        let mut bytes = allocate_owned_vec(size, &allocation)?;
        bytes.extend_from_slice(quarter_stream_id.as_slice());
        bytes.extend_from_slice(context.as_slice());
        bytes.extend_from_slice(payload);
        let bytes = Bytes::from_owner(ChargedBuffer {
            bytes,
            offset: 0,
            _allocation: allocation,
        });
        let (completion, completion_rx) = oneshot::channel();
        let command = Command::Datagram {
            id: owner.id,
            bytes,
            deadline,
            completion,
        };
        match owner.shared.commands.try_send(command) {
            Ok(()) => owner.shared.wake.notify_one(),
            Err(mpsc::error::TrySendError::Full(_)) => return Ok(DatagramOutcome::Dropped),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.check_open()?;
                return Err(EngineError::TransportUnavailable);
            }
        }
        let sent = wait_completion(&owner.shared, completion_rx, deadline).await;
        if matches!(sent, Err(error) if error != EngineError::DeadlineExceeded) {
            self.check_open()?;
        }
        sent
    }

    pub fn close(&mut self) -> Result<(), EngineError> {
        self.closed.store(true, Ordering::Release);
        self.stream.cancel()
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.close()
    }

    fn check_open(&self) -> Result<(), EngineError> {
        check_datagram_open(&self.stream.owner, &self.closed)
    }
}

impl H3DatagramRecvHalf {
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::UnreliableNative
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn max_payload(&self) -> usize {
        self.max_payload.load(Ordering::Relaxed)
    }
    pub fn control(&self) -> H3DatagramControl {
        H3DatagramControl {
            stream: self.stream.control(),
            closed: self.closed.clone(),
        }
    }

    /// Receive an owned payload whose memory charge follows its bytes.
    /// Dropping a pending future or timing out leaves the association usable.
    pub async fn recv(&mut self, deadline: Deadline) -> Result<DatagramPayload, EngineError> {
        deadline.remaining()?;
        self.check_open()?;
        let received = deadline.run(self.dequeue()).await;
        let bytes = match received {
            Ok(bytes) => bytes,
            Err(error) => {
                if error != EngineError::DeadlineExceeded
                    && let Err(terminal) = self.check_open()
                {
                    return Err(terminal);
                }
                return Err(error);
            }
        };
        self.check_open()?;
        Ok(DatagramPayload::from_bytes(bytes))
    }

    pub fn close(&mut self) -> Result<(), EngineError> {
        self.closed.store(true, Ordering::Release);
        self.release_receives();
        self.stream.cancel()
    }

    pub fn cancel(&mut self) -> Result<(), EngineError> {
        self.close()
    }

    fn check_open(&mut self) -> Result<(), EngineError> {
        let result = check_datagram_open(&self.stream.owner, &self.closed);
        if result.is_err() {
            self.release_receives();
        }
        result
    }

    async fn dequeue(&mut self) -> Result<Bytes, EngineError> {
        let bytes = self.receives.recv().await.ok_or_else(|| {
            driver_error(&self.stream.owner.shared).unwrap_or(EngineError::RemoteReset)
        })?;
        // Account for the dequeue before a deadline can discard its result.
        self.queued_datagram_bytes
            .fetch_sub(bytes.len(), Ordering::Relaxed);
        self.stream.owner.shared.wake.notify_one();
        Ok(bytes)
    }

    fn release_receives(&mut self) {
        self.receives.close();
        while let Ok(bytes) = self.receives.try_recv() {
            self.queued_datagram_bytes
                .fetch_sub(bytes.len(), Ordering::Relaxed);
        }
    }
}

impl Drop for H3DatagramRecvHalf {
    fn drop(&mut self) {
        self.release_receives();
        self.stream.owner.shared.wake.notify_one();
    }
}

impl H3DatagramControl {
    /// Close both directions and wake pending receives. Returns `Cancelled`
    /// after the last I/O owner drops.
    pub fn close(&self) -> Result<(), EngineError> {
        self.closed.store(true, Ordering::Release);
        self.stream.cancel()
    }

    pub fn cancel(&self) -> Result<(), EngineError> {
        self.close()
    }
}

fn check_datagram_open(owner: &ConnectOwner, closed: &AtomicBool) -> Result<(), EngineError> {
    if closed.load(Ordering::Acquire) {
        return Err(EngineError::ProtocolViolation);
    }
    if let Some(error) = owner.terminal_error() {
        return Err(error);
    }
    if let Some(error) = driver_error(&owner.shared) {
        return Err(error);
    }
    Ok(())
}

fn charged_copy(config: &H3Config, bytes: &[u8]) -> Result<Bytes, EngineError> {
    let allocation = config.reserve_owned(bytes.len())?;
    let mut copy = allocate_owned_vec(bytes.len(), &allocation)?;
    copy.extend_from_slice(bytes);
    Ok(Bytes::from_owner(ChargedBuffer {
        bytes: copy,
        offset: 0,
        _allocation: allocation,
    }))
}

fn allocate_vec(
    capacity: usize,
    allocation: &ScopedMemoryReservation,
) -> Result<Vec<u8>, EngineError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    if capacity > allocation.bytes() || bytes.capacity() > capacity {
        return Err(EngineError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn allocate_owned_vec(
    capacity: usize,
    allocation: &ScopedMemoryReservation,
) -> Result<Vec<u8>, EngineError> {
    let bytes = allocate_vec(capacity, allocation)?;
    if crate::retained_bytes_charge::<ChargedBuffer>(bytes.capacity())? > allocation.bytes() {
        return Err(EngineError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn connect_from_handle(shared: Arc<SessionControl>, handle: FlowHandle) -> H3Connect {
    let owner = Arc::new(ConnectOwner {
        shared,
        id: handle.id,
        status: handle.status,
        response_headers: handle.headers,
        read_finished: AtomicBool::new(false),
        write_closed: AtomicBool::new(false),
        read_abandoned: handle.read_abandoned,
        flow_terminal: handle.terminal,
        _response_memory: handle.response_memory,
        _handle_memory: handle.handle_memory,
    });
    H3Connect {
        status: handle.status,
        read: H3ReadHalf {
            owner: owner.clone(),
            read_events: handle.read_events,
            unread_body: Bytes::new(),
            buffered_body_bytes: handle.buffered_body_bytes,
        },
        write: H3WriteHalf { owner },
    }
}

fn datagram_from_stream(
    stream: H3Connect,
    receives: mpsc::Receiver<Bytes>,
    generation: u64,
    max_payload: Arc<AtomicUsize>,
    queued_datagram_bytes: Arc<AtomicUsize>,
) -> H3DatagramAssociation {
    let (read, write) = stream.into_split();
    let closed = Arc::new(AtomicBool::new(false));
    H3DatagramAssociation {
        send: H3DatagramSendHalf {
            stream: write,
            generation,
            max_payload: max_payload.clone(),
            closed: closed.clone(),
        },
        recv: H3DatagramRecvHalf {
            stream: read,
            receives,
            generation,
            max_payload,
            queued_datagram_bytes,
            closed,
        },
    }
}

fn set_terminal(terminal: &Mutex<Option<EngineError>>, error: EngineError) -> bool {
    let mut terminal = terminal.lock().unwrap_or_else(|error| error.into_inner());
    if terminal.is_some() {
        false
    } else {
        *terminal = Some(error);
        true
    }
}

fn feed_capsules(config: &H3Config, flow: &mut Flow, mut input: &[u8]) -> Result<(), EngineError> {
    while !input.is_empty() {
        let decoder = flow
            .capsules
            .as_mut()
            .ok_or(EngineError::ProtocolViolation)?;
        let (consumed, capsule) = decoder.feed(input, |size| {
            if flow.capsule_allocation.is_some() {
                return Err(EngineError::ProtocolViolation);
            }
            flow.capsule_allocation = Some(config.reserve_owned(size)?);
            Ok(())
        })?;
        if consumed == 0 {
            return Err(EngineError::ProtocolViolation);
        }
        input = &input[consumed..];
        if let Some(capsule) = capsule {
            if capsule.kind != DATAGRAM_CAPSULE {
                continue;
            }
            let allocation = flow
                .capsule_allocation
                .take()
                .ok_or(EngineError::ProtocolViolation)?;
            if crate::retained_bytes_charge::<ChargedBuffer>(capsule.value.capacity())?
                > allocation.bytes()
            {
                return Err(EngineError::ResourceLimitExceeded);
            }
            let (context, payload) = split_http_datagram(&capsule.value)?;
            if context != CONNECT_UDP_CONTEXT_ID
                || payload.len() > config.limits.udp_payload_absolute_max
            {
                continue;
            }
            let offset = capsule.value.len() - payload.len();
            let bytes = Bytes::from_owner(ChargedBuffer {
                bytes: capsule.value,
                offset,
                _allocation: allocation,
            });
            flow.datagram_idle_deadline = Some(Deadline::after(config.datagram_idle_timeout)?);
            queue_datagram(config, flow, bytes);
        }
    }
    Ok(())
}

fn queue_datagram(config: &H3Config, flow: &Flow, payload: Bytes) {
    let Some(sender) = &flow.datagrams else {
        return;
    };
    if datagram_queue_full(config, flow, sender, payload.len()) {
        return;
    }
    enqueue_datagram(flow, sender, payload);
}

fn datagram_queue_full(
    config: &H3Config,
    flow: &Flow,
    sender: &mpsc::Sender<Bytes>,
    length: usize,
) -> bool {
    sender.capacity() == 0
        || flow
            .queued_datagram_bytes
            .load(Ordering::Relaxed)
            .checked_add(length)
            .is_none_or(|bytes| bytes > config.limits.udp_queue_bytes)
}

fn enqueue_datagram(flow: &Flow, sender: &mpsc::Sender<Bytes>, payload: Bytes) {
    let length = payload.len();
    flow.queued_datagram_bytes
        .fetch_add(length, Ordering::Relaxed);
    if sender.try_send(payload).is_err() {
        flow.queued_datagram_bytes
            .fetch_sub(length, Ordering::Relaxed);
    }
}

// A cancelled write may already be queued. Keep reset armed until its completion succeeds.
struct ResetOnDrop {
    shared: Arc<SessionControl>,
    id: Option<u64>,
}

impl ResetOnDrop {
    fn new(shared: Arc<SessionControl>, id: u64) -> Self {
        Self {
            shared,
            id: Some(id),
        }
    }
    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let _ = reset_command(&self.shared, id);
        }
    }
}

fn attach_h3_versions(headers: &mut HeaderMap) {
    for (name, version) in H3_VERSION_HEADERS {
        headers.insert(name, version.header_value());
    }
}

fn validate_h3_versions(headers: &HeaderMap) -> Result<(), EngineError> {
    for (name, expected) in H3_VERSION_HEADERS {
        if single_header_value(headers, name)?
            .is_none_or(|value| value.as_bytes() != expected.as_bytes())
        {
            return Err(EngineError::ProtocolViolation);
        }
    }
    if headers.contains_key(EXPERIMENTAL_H2_BINDING_VERSION_HEADER) {
        return Err(EngineError::ProtocolViolation);
    }
    Ok(())
}

fn response_headers(status: StatusCode) -> Vec<Header> {
    let [binding, protocol] =
        H3_VERSION_HEADERS.map(|(name, version)| Header::new(name.as_bytes(), version.as_bytes()));
    vec![
        Header::new(b":status", status.as_str().as_bytes()),
        protocol,
        binding,
    ]
}

fn request_headers(request: &Request<()>, datagram: bool) -> Result<Vec<Header>, EngineError> {
    let authority = request
        .uri()
        .authority()
        .ok_or(EngineError::InvalidConfig)?;
    let mut headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":authority", authority.as_str().as_bytes()),
    ];
    if datagram {
        headers.push(Header::new(b":protocol", CONNECT_UDP.as_bytes()));
        headers.push(Header::new(b":scheme", b"https"));
        headers.push(Header::new(b":path", request.uri().path().as_bytes()));
    }
    for (name, value) in request.headers() {
        headers.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    Ok(headers)
}

fn header_size(headers: &[Header], config: &H3Config) -> Result<usize, EngineError> {
    if headers.len() > config.limits.decoded_header_fields {
        return Err(EngineError::ResourceLimitExceeded);
    }
    let bytes = headers.iter().try_fold(0usize, |total, header| {
        total
            .checked_add(header.name().len())
            .and_then(|total| total.checked_add(header.value().len()))
            .ok_or(EngineError::ResourceLimitExceeded)
    })?;
    if bytes > config.limits.decoded_header_bytes {
        return Err(EngineError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn header_memory(bytes: usize, fields: usize) -> Result<usize, EngineError> {
    bytes
        .checked_mul(2)
        .and_then(|size| size.checked_add(fields.checked_mul(128)?))
        .and_then(|size| size.checked_add(1024))
        .ok_or(EngineError::ResourceLimitExceeded)
}

fn read_error(error: EngineError) -> Result<ReadOutcome, EngineError> {
    match error {
        EngineError::RemoteReset => Ok(ReadOutcome::Reset),
        EngineError::Cancelled => Ok(ReadOutcome::Cancelled),
        EngineError::TruncatedStream => Ok(ReadOutcome::Truncated),
        other => Err(other),
    }
}

fn map_quic(error: quiche::Error) -> EngineError {
    match error {
        quiche::Error::TlsFail => EngineError::PeerIdentityFailed,
        quiche::Error::StreamReset(_) | quiche::Error::StreamStopped(_) => EngineError::RemoteReset,
        quiche::Error::BufferTooShort => EngineError::MessageTooLarge,
        quiche::Error::StreamLimit => EngineError::ResourceLimitExceeded,
        _ => EngineError::TransportUnavailable,
    }
}

fn map_h3(error: quiche::h3::Error) -> EngineError {
    match error {
        quiche::h3::Error::TransportError(error) => map_quic(error),
        _ => EngineError::ProtocolViolation,
    }
}

fn check_ready(shared: &SessionControl) -> Result<(), EngineError> {
    match *shared.state.borrow() {
        DriverState::Ready { .. } => Ok(()),
        DriverState::Closing(error) | DriverState::Closed(Err(error)) => Err(error),
        DriverState::Connecting | DriverState::Draining | DriverState::Closed(Ok(())) => {
            Err(EngineError::TransportUnavailable)
        }
    }
}

fn driver_error(shared: &SessionControl) -> Option<EngineError> {
    match *shared.state.borrow() {
        DriverState::Closing(error) | DriverState::Closed(Err(error)) => Some(error),
        DriverState::Closed(Ok(())) => Some(EngineError::TransportUnavailable),
        _ => None,
    }
}

async fn send_command(
    shared: &SessionControl,
    command: Command,
    deadline: Deadline,
) -> Result<(), EngineError> {
    deadline
        .run(async {
            shared
                .commands
                .send(command)
                .await
                .map_err(|_| driver_error(shared).unwrap_or(EngineError::TransportUnavailable))
        })
        .await?;
    shared.wake.notify_one();
    Ok(())
}

async fn wait_completion<T>(
    shared: &SessionControl,
    completion: oneshot::Receiver<Result<T, EngineError>>,
    deadline: Deadline,
) -> Result<T, EngineError> {
    deadline
        .run(async {
            completion
                .await
                .map_err(|_| driver_error(shared).unwrap_or(EngineError::TransportUnavailable))?
        })
        .await
}

fn active_command_completion<T>(
    completion: oneshot::Sender<Result<T, EngineError>>,
    deadline: Deadline,
) -> Option<oneshot::Sender<Result<T, EngineError>>> {
    if completion.is_closed() {
        return None;
    }
    if let Err(error) = deadline.remaining() {
        let _ = completion.send(Err(error));
        return None;
    }
    Some(completion)
}

fn reset_command(shared: &SessionControl, id: u64) -> Result<(), EngineError> {
    match shared.commands.try_send(Command::Reset { id }) {
        Ok(()) => {
            shared.wake.notify_one();
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            shared.cancel();
            Err(EngineError::ResourceLimitExceeded)
        }
    }
}

async fn wait_ready(shared: &SessionControl, deadline: Deadline) -> Result<(), EngineError> {
    let mut state = shared.state.clone();
    deadline
        .run(async {
            loop {
                match *state.borrow_and_update() {
                    DriverState::Ready { .. } => return Ok(()),
                    DriverState::Closing(error) | DriverState::Closed(Err(error)) => {
                        return Err(error);
                    }
                    DriverState::Closed(Ok(())) | DriverState::Draining => {
                        return Err(EngineError::TransportUnavailable);
                    }
                    DriverState::Connecting => {}
                }
                state
                    .changed()
                    .await
                    .map_err(|_| EngineError::TransportUnavailable)?;
            }
        })
        .await
}

async fn wait_closed(shared: &SessionControl) -> Result<(), EngineError> {
    let mut state = shared.state.clone();
    loop {
        if let DriverState::Closed(result) = *state.borrow_and_update() {
            return result;
        }
        state
            .changed()
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
    }
}

async fn shutdown(shared: &SessionControl, deadline: Deadline) -> Result<(), EngineError> {
    if matches!(*shared.state.borrow(), DriverState::Closed(_)) {
        return wait_closed(shared).await;
    }
    if matches!(*shared.state.borrow(), DriverState::Closing(_)) {
        return deadline.run(wait_closed(shared)).await;
    }
    let result = async {
        let deadline = deadline.cap(shared.config.h2.drain_timeout)?;
        send_command(shared, Command::Drain { deadline }, deadline).await?;
        deadline.run(wait_closed(shared)).await
    }
    .await;
    if matches!(*shared.state.borrow(), DriverState::Closing(_)) {
        return deadline.run(wait_closed(shared)).await;
    }
    if result.is_err() {
        shared.cancel();
        if let Some(task) = shared
            .task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            task.abort();
        }
        let _ = wait_closed(shared).await;
    }
    result
}

impl H3ServerSession {
    /// Owns one UDP socket for one peer. A shared listener needs CID routing.
    /// The handshake timeout caps `deadline`. Compiled DEBUG or TRACE logging
    /// returns `UnsupportedCapability` before socket I/O or budget reservations.
    pub async fn accept(
        socket: UdpSocket,
        tls: &NativeTlsServer,
        config: H3Config,
        deadline: Deadline,
    ) -> Result<Self, EngineError> {
        require_safe_logging()?;
        config.validate()?;
        let deadline = deadline.cap(config.h2.handshake_timeout)?;
        let native_memory = config.native_reservation()?;
        let mut initial = allocate_vec(RECEIVE_PACKET_BYTES, &native_memory)?;
        initial.resize(RECEIVE_PACKET_BYTES, 0);
        let (length, peer) = deadline
            .run(async {
                socket
                    .recv_from(&mut initial)
                    .await
                    .map_err(|_| EngineError::TransportUnavailable)
            })
            .await?;
        let header = quiche::Header::from_slice(&mut initial[..length], quiche::MAX_CONN_ID_LEN)
            .map_err(map_quic)?;
        if header.ty != quiche::Type::Initial
            || !quiche::version_is_supported(header.version)
            || length < quiche::MIN_CLIENT_INITIAL_LEN
        {
            return Err(EngineError::ProtocolViolation);
        }
        let local = connect_socket(&socket, peer, deadline).await?;
        let mut quic_config = tls.quiche_config()?;
        config.configure(&mut quic_config)?;
        let mut cid = [0u8; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut cid).map_err(|_| EngineError::TransportUnavailable)?;
        let cid = quiche::ConnectionId::from_ref(&cid);
        let mut connection = quiche::accept_with_buf_factory::<NativeBufFactory>(
            &cid,
            None,
            local,
            peer,
            &mut quic_config,
        )
        .map_err(map_quic)?;
        connection
            .recv(
                &mut initial[..length],
                quiche::RecvInfo {
                    from: peer,
                    to: local,
                },
            )
            .map_err(map_quic)?;
        drop(initial);
        let metadata = shared_metadata_reservation(&config, true)?;
        let (incoming, requests) = mpsc::channel(config.limits.pending_egress_opens);
        let (shared, driver) = make_driver(
            connection,
            socket,
            local,
            peer,
            DriverSetup {
                config,
                deadline,
                trust: None,
                incoming: Some(incoming),
                native_memory,
                metadata,
            },
        )?;
        spawn_driver(&shared, driver)?;
        wait_ready(&shared, deadline).await?;
        deadline.remaining()?;
        Ok(Self {
            shared,
            incoming: requests,
            address: peer,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn incoming(&mut self, deadline: Deadline) -> Result<H3Incoming, EngineError> {
        deadline
            .run(async {
                self.incoming.recv().await.ok_or_else(|| {
                    driver_error(&self.shared).unwrap_or(EngineError::TransportUnavailable)
                })
            })
            .await
    }

    /// Request GOAWAY and drain existing flows within the drain timeout and `deadline`.
    pub async fn shutdown(&self, deadline: Deadline) -> Result<(), EngineError> {
        shutdown(&self.shared, deadline).await
    }

    /// Wait until the driver releases its socket and native buffers. Handles may
    /// retain application buffers and metadata charges after this returns.
    pub async fn wait_closed(&self) -> Result<(), EngineError> {
        wait_closed(&self.shared).await
    }

    /// Request driver cancellation. `wait_closed` waits for it to stop.
    pub fn cancel(&self) {
        self.shared.cancel();
    }
}

impl Drop for H3ServerSession {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl H3Incoming {
    /// Whether the accepted request used extended CONNECT-UDP.
    pub const fn is_datagram(&self) -> bool {
        self.datagram
    }

    /// Parse the declared target without authorizing or connecting it.
    pub fn destination(&self) -> Result<Destination, EngineError> {
        if self.datagram {
            target_of_connect_udp_unversioned(&self.request)
        } else {
            Destination::parse(
                self.request
                    .uri()
                    .authority()
                    .ok_or(EngineError::ProtocolViolation)?
                    .as_str(),
            )
        }
    }

    /// Queue a final response. Successful CONNECT-UDP uses `respond_datagram`.
    pub async fn respond(
        mut self,
        status: StatusCode,
        deadline: Deadline,
    ) -> Result<H3Connect, EngineError> {
        if self.datagram && status.is_success() {
            return Err(EngineError::ProtocolViolation);
        }
        self.send_response(status, deadline).await?;
        let shared = self.shared.upgrade().ok_or(EngineError::Cancelled)?;
        let mut handle = self.handle.take().ok_or(EngineError::ProtocolViolation)?;
        handle.status = status;
        let stream = connect_from_handle(shared, handle);
        if !status.is_success() {
            stream
                .write
                .owner
                .write_closed
                .store(true, Ordering::Relaxed);
        }
        Ok(stream)
    }

    /// Queue a 200 response and return a native association. `generation` is
    /// local metadata and is not sent on the wire.
    pub async fn respond_datagram(
        mut self,
        generation: u64,
        deadline: Deadline,
    ) -> Result<H3DatagramAssociation, EngineError> {
        if !self.datagram {
            return Err(EngineError::ProtocolViolation);
        }
        if self
            .handle
            .as_ref()
            .is_none_or(|handle| handle.max_payload.load(Ordering::Relaxed) == 0)
        {
            return Err(EngineError::UnsupportedCapability);
        }
        self.send_response(StatusCode::OK, deadline).await?;
        let shared = self.shared.upgrade().ok_or(EngineError::Cancelled)?;
        let mut handle = self.handle.take().ok_or(EngineError::ProtocolViolation)?;
        handle.status = StatusCode::OK;
        let receives = handle
            .datagrams
            .take()
            .ok_or(EngineError::ProtocolViolation)?;
        let max_payload = handle.max_payload.clone();
        let queued_datagram_bytes = handle.queued_datagram_bytes.clone();
        Ok(datagram_from_stream(
            connect_from_handle(shared, handle),
            receives,
            generation,
            max_payload,
            queued_datagram_bytes,
        ))
    }

    async fn send_response(
        &self,
        status: StatusCode,
        deadline: Deadline,
    ) -> Result<(), EngineError> {
        deadline.remaining()?;
        if status.is_informational() {
            return Err(EngineError::InvalidConfig);
        }
        let shared = self.shared.upgrade().ok_or(EngineError::Cancelled)?;
        let id = self
            .handle
            .as_ref()
            .ok_or(EngineError::ProtocolViolation)?
            .id;
        let (completion, completion_rx) = oneshot::channel();
        send_command(
            &shared,
            Command::Respond {
                id,
                status,
                deadline,
                completion,
            },
            deadline,
        )
        .await?;
        wait_completion(&shared, completion_rx, deadline).await
    }
}

impl Drop for H3Incoming {
    fn drop(&mut self) {
        if let (Some(handle), Some(shared)) = (&self.handle, self.shared.upgrade()) {
            let _ = reset_command(&shared, handle.id);
        }
    }
}

struct DriverSetup {
    config: H3Config,
    deadline: Deadline,
    trust: Option<NativeTlsConnector>,
    incoming: Option<mpsc::Sender<H3Incoming>>,
    native_memory: ScopedMemoryReservation,
    metadata: Arc<ScopedMemoryReservation>,
}

fn make_driver(
    connection: quiche::Connection<NativeBufFactory>,
    socket: UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    setup: DriverSetup,
) -> Result<(Arc<SessionControl>, Driver), EngineError> {
    let DriverSetup {
        config,
        deadline,
        trust,
        incoming,
        native_memory,
        metadata,
    } = setup;
    let (commands, receiver) = mpsc::channel(config.limits.active_flows_per_session);
    let (status, state) = watch::channel(DriverState::Connecting);
    let wake = Arc::new(Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(SessionControl {
        commands,
        wake: wake.clone(),
        cancelled: cancelled.clone(),
        state,
        task: Mutex::new(None),
        config: config.clone(),
        _metadata: metadata.clone(),
    });
    let mut receive_packet = allocate_vec(RECEIVE_PACKET_BYTES, &native_memory)?;
    receive_packet.resize(RECEIVE_PACKET_BYTES, 0);
    let mut send_packet = allocate_vec(SEND_PACKET_BYTES, &native_memory)?;
    send_packet.resize(SEND_PACKET_BYTES, 0);
    let mut receive_body = allocate_vec(BODY_CHUNK_BYTES, &native_memory)?;
    receive_body.resize(BODY_CHUNK_BYTES, 0);
    let driver = Driver {
        connection,
        http: None,
        socket,
        local,
        peer,
        config,
        commands: receiver,
        flows: BTreeMap::new(),
        shared: Arc::downgrade(&shared),
        wake,
        cancelled,
        status,
        incoming,
        trust,
        startup_deadline: deadline,
        draining_deadline: None,
        peer_goaway: false,
        receive_packet,
        send_packet,
        pending_packet: None,
        socket_send_blocked: false,
        pending_opens: VecDeque::new(),
        goaway_id: 0,
        goaway_sent: false,
        receive_body,
        close_requested: false,
        connection_error: None,
        _native_memory: native_memory,
        _metadata: metadata,
    };
    Ok((shared, driver))
}

fn shared_metadata_reservation(
    config: &H3Config,
    server: bool,
) -> Result<Arc<ScopedMemoryReservation>, EngineError> {
    let command_slots = channel_slots(config.limits.active_flows_per_session)?;
    let incoming_slots = if server {
        channel_slots(config.limits.pending_egress_opens)?
    } else {
        0
    };
    let size = command_slots
        .checked_mul(std::mem::size_of::<Command>())
        .and_then(|size| {
            size.checked_add(incoming_slots.checked_mul(std::mem::size_of::<H3Incoming>())?)
        })
        .and_then(|size| size.checked_add(std::mem::size_of::<SessionControl>()))
        .and_then(|size| size.checked_add(METADATA_RESERVE_BYTES))
        .ok_or(EngineError::ResourceLimitExceeded)?;
    Ok(Arc::new(config.reserve(size)?))
}

fn channel_slots(capacity: usize) -> Result<usize, EngineError> {
    capacity
        .checked_add(CHANNEL_BLOCK_SLOTS - 1)
        .map(|slots| slots / CHANNEL_BLOCK_SLOTS * CHANNEL_BLOCK_SLOTS)
        .ok_or(EngineError::ResourceLimitExceeded)
}

fn peer_datagram_enabled(
    http: &quiche::h3::Connection,
    connection: &quiche::Connection<NativeBufFactory>,
) -> bool {
    http.extended_connect_enabled_by_peer() && http.dgram_enabled_by_peer(connection)
}

fn spawn_driver(shared: &SessionControl, driver: Driver) -> Result<(), EngineError> {
    let status = driver.status.clone();
    let mut owned = DriverTask {
        driver: Some(driver),
        status,
        outcome: None,
    };
    let task = tokio::spawn(async move {
        owned.outcome = Some(match &mut owned.driver {
            Some(driver) => driver.run().await,
            None => Err(EngineError::Cancelled),
        });
        drop(owned);
    });
    match shared.task.lock() {
        Ok(mut slot) => {
            *slot = Some(task);
            Ok(())
        }
        Err(_) => {
            task.abort();
            Err(EngineError::TransportUnavailable)
        }
    }
}

struct DriverTask {
    driver: Option<Driver>,
    status: watch::Sender<DriverState>,
    outcome: Option<Result<(), EngineError>>,
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        let outcome = self
            .driver
            .as_ref()
            .and_then(|driver| driver.connection_error)
            .map_or(self.outcome.unwrap_or(Err(EngineError::Cancelled)), Err);
        if let Some(mut driver) = self.driver.take() {
            driver.fail_pending_operations(
                outcome.err().unwrap_or(EngineError::TransportUnavailable),
            );
            drop(driver);
        }
        // Publish completion after the socket and native buffers are released.
        let _ = self.status.send(DriverState::Closed(outcome));
    }
}

impl Driver {
    async fn run(&mut self) -> Result<(), EngineError> {
        let outcome = self.drive().await;
        self.connection_error.map_or(outcome, Err)
    }

    async fn drive(&mut self) -> Result<(), EngineError> {
        loop {
            if self.cancelled.load(Ordering::Acquire) && self.connection_error.is_none() {
                return Err(EngineError::Cancelled);
            }
            if self
                .connection
                .timeout_instant()
                .is_some_and(|at| at <= std::time::Instant::now())
            {
                self.connection.on_timeout();
            }
            if self.connection.is_closed() {
                return if self.draining_deadline.is_some() {
                    Ok(())
                } else if self.connection.is_timed_out() {
                    Err(EngineError::DeadlineExceeded)
                } else {
                    Err(EngineError::TransportUnavailable)
                };
            }
            if self.connection_error.is_none() {
                if self.http.is_none() && self.connection.is_established() {
                    if let Some(trust) = &self.trust {
                        trust.verify_quiche(&mut self.connection)?;
                    }
                    if self.connection.application_proto() != H3_ALPN
                        || self.connection.is_in_early_data()
                    {
                        return Err(EngineError::ProtocolViolation);
                    }
                    let mut config = quiche::h3::Config::new().map_err(map_h3)?;
                    config.enable_extended_connect(true);
                    config.set_qpack_max_table_capacity(0);
                    config.set_qpack_blocked_streams(0);
                    config
                        .set_max_field_section_size(self.config.limits.decoded_header_bytes as u64);
                    config.set_max_priority_update_size(
                        self.config.limits.control_message_max as u64,
                    );
                    self.http = Some(
                        quiche::h3::Connection::with_transport(&mut self.connection, &config)
                            .map_err(map_h3)?,
                    );
                }
                self.poll_http()?;
                self.publish_ready();
                if matches!(*self.status.borrow(), DriverState::Connecting) {
                    self.startup_deadline.remaining()?;
                }
                self.process_commands()?;
                self.advance_flows()?;
                self.receive_datagrams()?;
                self.update_datagram_limits()?;
                self.collect_flows();
            }
            if let Some(deadline) = self.draining_deadline {
                deadline.remaining()?;
                if !self.goaway_sent && self.connection_error.is_none() {
                    let id = if self.connection.is_server() {
                        self.goaway_id
                    } else {
                        0
                    };
                    if let Some(http) = &mut self.http {
                        match http.send_goaway(&mut self.connection, id) {
                            Ok(()) => self.goaway_sent = true,
                            Err(quiche::h3::Error::Done)
                            | Err(quiche::h3::Error::StreamBlocked) => {}
                            Err(error) => return Err(map_h3(error)),
                        }
                    }
                }
                if self.flows.is_empty()
                    && self.pending_opens.is_empty()
                    && self.goaway_sent
                    && !self.close_requested
                {
                    self.connection.close(true, 0, b"").map_err(map_quic)?;
                    self.close_requested = true;
                }
            }
            // Keep send_packet unchanged while a packet waits for pacing or socket readiness.
            if self.pending_packet.is_none() {
                match self.connection.send(&mut self.send_packet) {
                    Ok((length, info)) => {
                        self.pending_packet = Some(PendingPacket { length, info })
                    }
                    Err(quiche::Error::Done) => {}
                    Err(error) => return Err(map_quic(error)),
                }
            }
            let wake_at = self.next_wake_at();
            let send_at = self
                .pending_packet
                .as_ref()
                .map(|packet| Instant::from_std(packet.info.at))
                .unwrap_or(wake_at);
            let has_pending_packet = self.pending_packet.is_some();
            tokio::select! {
                _ = self.wake.notified() => {},
                _ = sleep_until(wake_at) => {
                    if self.connection.timeout_instant().is_some_and(|at| at <= std::time::Instant::now()) {
                        self.connection.on_timeout();
                    }
                },
                result = self.socket.recv(&mut self.receive_packet) => {
                    let length = result.map_err(|_| EngineError::TransportUnavailable)?;
                    match self.connection.recv(&mut self.receive_packet[..length],
                        quiche::RecvInfo { from: self.peer, to: self.local }) {
                        Ok(_) | Err(quiche::Error::Done) | Err(quiche::Error::InvalidPacket)
                            | Err(quiche::Error::CryptoFail) => {},
                        Err(error) => return Err(map_quic(error)),
                    }
                },
                result = self.socket.writable(), if has_pending_packet && self.socket_send_blocked => {
                    result.map_err(|_| EngineError::TransportUnavailable)?;
                    self.socket_send_blocked = false;
                },
                _ = async {
                    // Due packets must not wait for the next timer tick.
                    if send_at > Instant::now() {
                        sleep_until(send_at).await;
                    }
                }, if has_pending_packet && !self.socket_send_blocked => {
                    if self.cancelled.load(Ordering::Acquire) && self.connection_error.is_none() { return Err(EngineError::Cancelled); }
                    let packet = self.pending_packet.as_ref().ok_or(EngineError::ProtocolViolation)?;
                    if packet.info.to != self.peer || packet.info.from != self.local {
                        return Err(EngineError::UnsupportedCapability);
                    }
                    match self.socket.try_send(&self.send_packet[..packet.length]) {
                        Ok(length) if length == packet.length => {
                            self.pending_packet = None;
                            self.socket_send_blocked = false;
                        },
                        Ok(_) => return Err(EngineError::TransportUnavailable),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            self.socket_send_blocked = true;
                        },
                        Err(_) => return Err(EngineError::TransportUnavailable),
                    }
                },
            }
        }
    }

    fn next_wake_at(&self) -> Instant {
        let mut wake_at = self
            .connection
            .timeout_instant()
            .map(Instant::from_std)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
        if matches!(*self.status.borrow(), DriverState::Connecting) {
            wake_at = wake_at.min(self.startup_deadline.expires_at());
        }
        if let Some(deadline) = self.draining_deadline {
            wake_at = wake_at.min(deadline.expires_at());
        }
        for flow in self.flows.values() {
            if let Some(deadline) = flow.opening_deadline {
                wake_at = wake_at.min(deadline.expires_at());
            }
            if let Some(deadline) = flow.datagram_idle_deadline {
                wake_at = wake_at.min(deadline.expires_at());
            }
            if let Some(write) = &flow.pending_write {
                wake_at = wake_at.min(write.deadline.expires_at());
            }
            if let Some(response) = &flow.pending_response {
                wake_at = wake_at.min(response.deadline.expires_at());
            }
        }
        for command in &self.pending_opens {
            if let Command::Open { deadline, .. } = command {
                wake_at = wake_at.min(deadline.expires_at());
            }
        }
        wake_at
    }

    fn publish_ready(&mut self) {
        if self.draining_deadline.is_some() {
            return;
        }
        let Some(http) = &self.http else {
            return;
        };
        if http.peer_settings_raw().is_none() {
            return;
        }
        let extended_connect = http.extended_connect_enabled_by_peer();
        let max_datagram_bytes = self.connection.dgram_max_writable_len().unwrap_or(0);
        let native_datagram = peer_datagram_enabled(http, &self.connection)
            && VarInt::encode(CONNECT_UDP_CONTEXT_ID)
                .is_ok_and(|context| max_datagram_bytes > context.as_slice().len());
        let ready = DriverState::Ready {
            extended_connect,
            native_datagram,
            max_datagram_bytes,
        };
        if *self.status.borrow() != ready {
            let _ = self.status.send(ready);
        }
    }

    fn process_commands(&mut self) -> Result<(), EngineError> {
        let pending_open_count = self.pending_opens.len().min(WORK_BATCH);
        for _ in 0..pending_open_count {
            if let Some(command) = self.pending_opens.pop_front() {
                self.handle_command(command)?;
            }
        }
        for _ in 0..WORK_BATCH {
            match self.commands.try_recv() {
                Ok(command) => self.handle_command(command)?,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Err(EngineError::Cancelled),
            }
        }
        if !self.commands.is_empty() {
            self.wake.notify_one();
        }
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<(), EngineError> {
        match command {
            Command::Open {
                headers,
                datagram,
                deadline,
                completion,
                allocation,
                flow_permit,
                open_permit,
            } => {
                let Some(completion) = active_command_completion(completion, deadline) else {
                    return Ok(());
                };
                if self.draining_deadline.is_some() || self.peer_goaway {
                    let _ = completion.send(Err(EngineError::TransportUnavailable));
                    return Ok(());
                }
                let Some(http) = self.http.as_mut() else {
                    let _ = completion.send(Err(EngineError::TransportUnavailable));
                    return Ok(());
                };
                if datagram && !peer_datagram_enabled(http, &self.connection) {
                    let _ = completion.send(Err(EngineError::UnsupportedCapability));
                    return Ok(());
                }
                let id = match http.send_request(&mut self.connection, &headers, false) {
                    Ok(id) => id,
                    Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
                        self.pending_opens.push_back(Command::Open {
                            headers,
                            datagram,
                            deadline,
                            completion,
                            allocation,
                            flow_permit,
                            open_permit,
                        });
                        return Ok(());
                    }
                    Err(error) => {
                        let _ = completion.send(Err(map_h3(error)));
                        return Ok(());
                    }
                };
                let (mut state, handle) = match self.new_flow(
                    id,
                    datagram,
                    flow_permit,
                    Some(open_permit),
                    Some(allocation),
                ) {
                    Ok(handles) => handles,
                    Err(error) => {
                        self.reset_flow(id, error);
                        let _ = completion.send(Err(error));
                        return Ok(());
                    }
                };
                state.open_completion = Some(completion);
                state.handle = Some(handle);
                state.opening_deadline = Some(deadline);
                self.flows.insert(id, state);
            }
            Command::Write {
                id,
                bytes,
                fin,
                deadline,
                completion,
            } => {
                let Some(flow) = self.flows.get_mut(&id) else {
                    let _ = completion.send(Err(EngineError::RemoteReset));
                    return Ok(());
                };
                if flow.pending_write.is_some() || flow.local_finished || !flow.response_ready {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                    return Ok(());
                }
                flow.pending_write = Some(PendingWrite {
                    bytes,
                    fin,
                    deadline,
                    completion,
                });
            }
            Command::Datagram {
                id,
                bytes,
                deadline,
                completion,
            } => {
                let Some(completion) = active_command_completion(completion, deadline) else {
                    return Ok(());
                };
                let Some(flow) = self.flows.get_mut(&id) else {
                    let _ = completion.send(Err(EngineError::RemoteReset));
                    return Ok(());
                };
                if !flow.datagram_ready() {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                    return Ok(());
                }
                let queued = self
                    .connection
                    .dgram_send_queue_byte_size()
                    .checked_add(bytes.len());
                let outcome = if queued.is_none_or(|size| size > self.config.limits.udp_queue_bytes)
                    || self.connection.dgram_send_queue_len()
                        >= self.config.native_datagram_capacity()
                {
                    Ok(DatagramOutcome::Dropped)
                } else {
                    match self.connection.dgram_send_buf(bytes) {
                        Ok(()) => Ok(DatagramOutcome::Queued),
                        Err(quiche::Error::Done) => Ok(DatagramOutcome::Dropped),
                        Err(error) => Err(map_quic(error)),
                    }
                };
                if outcome == Ok(DatagramOutcome::Queued) {
                    flow.datagram_idle_deadline =
                        Some(Deadline::after(self.config.datagram_idle_timeout)?);
                }
                let _ = completion.send(outcome);
            }
            Command::Respond {
                id,
                status,
                deadline,
                completion,
            } => {
                let Some(flow) = self.flows.get_mut(&id) else {
                    let _ = completion.send(Err(EngineError::RemoteReset));
                    return Ok(());
                };
                if flow.response_ready || flow.pending_response.is_some() {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                    return Ok(());
                }
                if flow.datagram
                    && status.is_success()
                    && let Err(error) = validate_capsule_response(status, &HeaderMap::new())
                {
                    let _ = completion.send(Err(error));
                    return Ok(());
                }
                flow.pending_response = Some(PendingResponse {
                    status,
                    deadline,
                    completion,
                });
            }
            Command::Reset { id } => self.reset_flow(id, EngineError::RemoteReset),
            Command::Drain { deadline } => {
                self.cap_drain_deadline(deadline);
                let _ = self.status.send(DriverState::Draining);
            }
        }
        Ok(())
    }

    fn cap_drain_deadline(&mut self, deadline: Deadline) {
        self.draining_deadline = Some(self.draining_deadline.map_or(deadline, |current| {
            Deadline::at(current.expires_at().min(deadline.expires_at()))
        }));
    }

    fn new_flow(
        &self,
        id: u64,
        datagram: bool,
        flow_permit: ScopedResourceReservation,
        open_permit: Option<ScopedResourceReservation>,
        allocation: Option<ScopedMemoryReservation>,
    ) -> Result<(Flow, FlowHandle), EngineError> {
        let read_queue_capacity =
            self.config.limits.stream_queue_per_direction / BODY_CHUNK_BYTES + 1;
        let read_queue_slots = channel_slots(read_queue_capacity)?;
        let datagram_queue_slots = if datagram {
            channel_slots(self.config.limits.udp_queue_datagrams)?
        } else {
            0
        };
        let handle_bytes = read_queue_slots
            .checked_mul(std::mem::size_of::<ReadEvent>())
            .and_then(|size| {
                size.checked_add(datagram_queue_slots.checked_mul(std::mem::size_of::<Bytes>())?)
            })
            .and_then(|size| size.checked_add(std::mem::size_of::<ConnectOwner>()))
            .and_then(|size| size.checked_add(METADATA_RESERVE_BYTES))
            .ok_or(EngineError::ResourceLimitExceeded)?;
        // A handle can outlive its flow entry, so both retain the receive queue charge.
        let handle_memory = Arc::new(self.config.reserve(handle_bytes)?);
        let (read_sender, read_events) = mpsc::channel(read_queue_capacity);
        let buffered_body_bytes = Arc::new(AtomicUsize::new(0));
        let read_abandoned = Arc::new(AtomicBool::new(false));
        let queued_datagram_bytes = Arc::new(AtomicUsize::new(0));
        let max_payload = Arc::new(AtomicUsize::new(0));
        let terminal = Arc::new(Mutex::new(None));
        let capsules = if datagram {
            Some(CapsuleDecoder::new(
                self.config
                    .limits
                    .udp_payload_absolute_max
                    .checked_add(VarInt::MAX_ENCODED_LEN)
                    .ok_or(EngineError::InvalidConfig)?,
            )?)
        } else {
            None
        };
        let (datagrams, receives) = if datagram {
            let (sender, receiver) = mpsc::channel(self.config.limits.udp_queue_datagrams);
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let state = Flow {
            read_sender,
            buffered_body_bytes: buffered_body_bytes.clone(),
            read_abandoned: read_abandoned.clone(),
            datagrams,
            max_payload: max_payload.clone(),
            queued_datagram_bytes: queued_datagram_bytes.clone(),
            open_completion: None,
            handle: None,
            opening_deadline: None,
            pending_write: None,
            readable: false,
            remote_finished: false,
            local_finished: false,
            read_finish_attempted: false,
            response_ready: false,
            datagram,
            _allocation: allocation,
            _flow_permit: flow_permit,
            open_permit,
            pending_response: None,
            terminal: terminal.clone(),
            capsules,
            capsule_allocation: None,
            peer_max_payload: self.config.limits.udp_payload_absolute_max,
            datagram_idle_deadline: if datagram {
                Some(Deadline::after(self.config.datagram_idle_timeout)?)
            } else {
                None
            },
            _handle_memory: handle_memory.clone(),
        };
        let handle = FlowHandle {
            id,
            status: StatusCode::CONTINUE,
            headers: HeaderMap::new(),
            read_events,
            buffered_body_bytes,
            read_abandoned,
            datagrams: receives,
            max_payload,
            queued_datagram_bytes,
            terminal,
            response_memory: None,
            handle_memory,
        };
        Ok((state, handle))
    }

    fn poll_http(&mut self) -> Result<(), EngineError> {
        if self.http.is_none() {
            return Ok(());
        }
        for _ in 0..WORK_BATCH {
            let event = self
                .http
                .as_mut()
                .ok_or(EngineError::ProtocolViolation)?
                .poll(&mut self.connection);
            match event {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => self.headers(id, list)?,
                Ok((id, quiche::h3::Event::Data)) => {
                    let Some(flow) = self.flows.get_mut(&id) else {
                        self.reset_flow(id, EngineError::ProtocolViolation);
                        continue;
                    };
                    if flow.open_completion.is_some() {
                        self.reset_flow(id, EngineError::ProtocolViolation);
                    } else {
                        flow.readable = true;
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) => {
                    if self
                        .flows
                        .get(&id)
                        .is_some_and(|flow| flow.open_completion.is_some())
                    {
                        self.reset_flow(id, EngineError::TruncatedStream);
                    } else if let Some(flow) = self.flows.get_mut(&id) {
                        flow.remote_finished = true;
                    }
                }
                Ok((id, quiche::h3::Event::Reset(_))) => {
                    self.reset_flow(id, EngineError::RemoteReset)
                }
                Ok((id, quiche::h3::Event::PriorityUpdate)) => {
                    let _ = self
                        .http
                        .as_mut()
                        .and_then(|http| http.take_last_priority_update(id).ok());
                }
                Ok((_, quiche::h3::Event::GoAway)) => self.peer_goaway = true,
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(error) => return Err(map_h3(error)),
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn headers(&mut self, id: u64, list: Vec<Header>) -> Result<(), EngineError> {
        let header_bytes = header_size(&list, &self.config)?;
        if !id.is_multiple_of(REQUEST_STREAM_ID_STRIDE) {
            return Err(EngineError::ProtocolViolation);
        }
        if self.flows.get(&id).is_some_and(|flow| flow.response_ready) {
            let _allocation = self
                .config
                .reserve(header_memory(header_bytes, list.len())?)?;
            let mut trailers = HeaderMap::new();
            for header in &list {
                if header.name().starts_with(b":") {
                    self.reset_flow(id, EngineError::ProtocolViolation);
                    return Ok(());
                }
                append_header(&mut trailers, header)?;
            }
            if [
                EXPERIMENTAL_H3_BINDING_VERSION_HEADER,
                EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
                crate::connect::EXPERIMENTAL_CREDENTIAL_HEADER,
                CAPSULE_PROTOCOL,
            ]
            .into_iter()
            .any(|name| trailers.contains_key(name))
            {
                self.reset_flow(id, EngineError::ProtocolViolation);
            }
            return Ok(());
        }
        if self.connection.is_server() {
            if self.flows.contains_key(&id) {
                self.reset_flow(id, EngineError::ProtocolViolation);
                return Ok(());
            }
            if self.draining_deadline.is_some() {
                self.reset_flow(id, EngineError::TransportUnavailable);
                return Ok(());
            }
            let allocation = match self
                .config
                .reserve(header_memory(header_bytes, list.len())?)
            {
                Ok(allocation) => allocation,
                Err(error) => {
                    self.reset_flow(id, error);
                    return Ok(());
                }
            };
            let (request, datagram) = parse_request(&list)?;
            if datagram
                && !self
                    .http
                    .as_ref()
                    .is_some_and(|http| peer_datagram_enabled(http, &self.connection))
            {
                self.reset_flow(id, EngineError::UnsupportedCapability);
                return Ok(());
            }
            let flow_permit = match self.config.h2.reserve_flow() {
                Ok(permit) => permit,
                Err(error) => {
                    self.reset_flow(id, error);
                    return Ok(());
                }
            };
            let open_permit = match self.config.h2.reserve_open() {
                Ok(open_permit) => open_permit,
                Err(error) => {
                    self.reset_flow(id, error);
                    return Ok(());
                }
            };
            let (mut state, handle) =
                match self.new_flow(id, datagram, flow_permit, Some(open_permit), None) {
                    Ok(handles) => handles,
                    Err(error) => {
                        self.reset_flow(id, error);
                        return Ok(());
                    }
                };
            state.opening_deadline = Some(Deadline::after(self.config.h2.open_timeout)?);
            self.flows.insert(id, state);
            self.goaway_id = self.goaway_id.max(
                id.checked_add(REQUEST_STREAM_ID_STRIDE)
                    .ok_or(EngineError::ProtocolViolation)?,
            );
            let incoming = H3Incoming {
                request,
                datagram,
                handle: Some(handle),
                shared: self.shared.clone(),
                _allocation: allocation,
            };
            match self
                .incoming
                .as_ref()
                .ok_or(EngineError::ProtocolViolation)?
                .try_send(incoming)
            {
                Ok(()) => {}
                Err(_) => self.reset_flow(id, EngineError::ResourceLimitExceeded),
            }
        } else {
            let allocation = match self
                .config
                .reserve(header_memory(header_bytes, list.len())?)
            {
                Ok(allocation) => allocation,
                Err(error) => {
                    self.reset_flow(id, error);
                    return Ok(());
                }
            };
            let (status, headers) = parse_response(&list)?;
            if status.is_informational() {
                if status == StatusCode::SWITCHING_PROTOCOLS {
                    return Err(EngineError::ProtocolViolation);
                }
                return Ok(());
            }
            validate_h3_versions(&headers)?;
            let Some(flow) = self.flows.get_mut(&id) else {
                return Err(EngineError::ProtocolViolation);
            };
            if flow.datagram {
                if status.is_success() {
                    validate_capsule_response(status, &headers)?;
                }
                flow.peer_max_payload = negotiated_datagram_payload(&headers)?
                    .unwrap_or(self.config.limits.udp_payload_absolute_max);
            }
            let mut handle = flow.handle.take().ok_or(EngineError::ProtocolViolation)?;
            handle.status = status;
            handle.headers = headers;
            handle.response_memory = Some(allocation);
            flow.response_ready = status.is_success();
            flow.opening_deadline = None;
            flow.open_permit = None;
            if let Some(completion) = flow.open_completion.take() {
                if completion.send(Ok(handle)).is_err() {
                    self.reset_flow(id, EngineError::Cancelled);
                }
            } else {
                return Err(EngineError::ProtocolViolation);
            }
        }
        Ok(())
    }

    fn advance_flows(&mut self) -> Result<(), EngineError> {
        let ids: Vec<u64> = self.flows.keys().copied().collect();
        for id in ids {
            let mut reset = None;
            let Some(flow) = self.flows.get_mut(&id) else {
                continue;
            };
            let complete = flow.remote_finished
                && flow.local_finished
                && flow.read_finish_attempted
                && !flow.readable
                && flow.buffered_body_bytes.load(Ordering::Relaxed) == 0;
            let read_closed = flow.read_sender.is_closed();
            let read_abandoned = flow.read_abandoned.load(Ordering::Acquire);
            if (read_closed && !read_abandoned && !complete)
                || flow
                    .open_completion
                    .as_ref()
                    .is_some_and(oneshot::Sender::is_closed)
            {
                reset = Some(EngineError::Cancelled);
            }
            if let Some(deadline) = flow.opening_deadline
                && deadline.remaining().is_err()
            {
                reset = Some(EngineError::DeadlineExceeded);
            }
            if let Some(deadline) = flow.datagram_idle_deadline
                && deadline.remaining().is_err()
            {
                reset = Some(EngineError::DeadlineExceeded);
            }
            if let Some(error) = *flow
                .terminal
                .lock()
                .unwrap_or_else(|error| error.into_inner())
            {
                reset = Some(error);
            }
            if let Some(error) = reset {
                self.reset_flow(id, error);
                continue;
            }
            if let Some(PendingResponse {
                status,
                deadline,
                completion,
            }) = flow.pending_response.take()
            {
                if completion.is_closed() || deadline.remaining().is_err() {
                    let _ = completion.send(Err(EngineError::DeadlineExceeded));
                    reset = Some(EngineError::Cancelled);
                } else {
                    let mut headers = response_headers(status);
                    if flow.datagram && status.is_success() {
                        headers.push(Header::new(
                            CAPSULE_PROTOCOL.as_bytes(),
                            CAPSULE_PROTOCOL_ENABLED.as_bytes(),
                        ));
                        let maximum = flow.max_payload.load(Ordering::Relaxed);
                        if maximum == 0 {
                            let _ = completion.send(Err(EngineError::UnsupportedCapability));
                            self.reset_flow(id, EngineError::UnsupportedCapability);
                            continue;
                        }
                        headers.push(Header::new(
                            MAX_DATAGRAM_PAYLOAD.as_bytes(),
                            maximum.to_string().as_bytes(),
                        ));
                    }
                    match self
                        .http
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .send_response(&mut self.connection, id, &headers, !status.is_success())
                    {
                        Ok(()) => {
                            flow.response_ready = true;
                            flow.local_finished = !status.is_success();
                            flow.open_permit = None;
                            flow.opening_deadline = None;
                            let _ = completion.send(Ok(()));
                        }
                        Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                            flow.pending_response = Some(PendingResponse {
                                status,
                                deadline,
                                completion,
                            });
                        }
                        Err(error) => {
                            let error = map_h3(error);
                            let _ = completion.send(Err(error));
                            reset = Some(error);
                        }
                    }
                }
            }
            if let Some(mut write) = flow.pending_write.take() {
                let completion_closed = write.completion.is_closed();
                if completion_closed || write.deadline.remaining().is_err() {
                    let _ = write.completion.send(Err(EngineError::DeadlineExceeded));
                    reset = Some(if completion_closed {
                        EngineError::Cancelled
                    } else {
                        EngineError::DeadlineExceeded
                    });
                } else {
                    let length = write.bytes.len();
                    match self
                        .http
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .send_body_zc(&mut self.connection, id, &mut write.bytes, write.fin)
                    {
                        Ok(written) => {
                            flow.local_finished |= write.fin && written == length;
                            let _ = write.completion.send(Ok(written));
                        }
                        Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                            flow.pending_write = Some(write)
                        }
                        Err(error) => {
                            let error = map_h3(error);
                            let _ = write.completion.send(Err(error));
                            reset = Some(error);
                        }
                    }
                }
            }
            if reset.is_none()
                && flow.readable
                && flow.response_ready
                && !flow.datagram
                && !read_abandoned
            {
                for _ in 0..WORK_BATCH {
                    if flow.read_sender.capacity() == 0
                        || flow.buffered_body_bytes.load(Ordering::Relaxed)
                            > self
                                .config
                                .limits
                                .stream_queue_per_direction
                                .saturating_sub(BODY_CHUNK_BYTES)
                    {
                        break;
                    }
                    let allocation = match self.config.reserve_owned(BODY_CHUNK_BYTES) {
                        Ok(allocation) => allocation,
                        Err(EngineError::ResourceLimitExceeded) => break,
                        Err(error) => return Err(error),
                    };
                    let mut bytes = allocate_owned_vec(BODY_CHUNK_BYTES, &allocation)?;
                    bytes.resize(BODY_CHUNK_BYTES, 0);
                    match self
                        .http
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .recv_body(&mut self.connection, id, &mut bytes)
                    {
                        Ok(length) => {
                            bytes.truncate(length);
                            if length == 0 {
                                continue;
                            }
                            let bytes = Bytes::from_owner(ChargedBuffer {
                                bytes,
                                offset: 0,
                                _allocation: allocation,
                            });
                            flow.buffered_body_bytes
                                .fetch_add(length, Ordering::Relaxed);
                            if flow.read_sender.try_send(ReadEvent::Data(bytes)).is_err() {
                                flow.buffered_body_bytes
                                    .fetch_sub(length, Ordering::Relaxed);
                                if !flow.read_abandoned.load(Ordering::Acquire) {
                                    reset = Some(EngineError::Cancelled);
                                }
                                break;
                            }
                        }
                        Err(quiche::h3::Error::Done) => {
                            flow.readable = false;
                            break;
                        }
                        Err(error) => {
                            reset = Some(map_h3(error));
                            break;
                        }
                    }
                }
            }
            if reset.is_none()
                && flow.readable
                && flow.response_ready
                && !flow.datagram
                && read_abandoned
            {
                for _ in 0..WORK_BATCH {
                    match self
                        .http
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .recv_body(&mut self.connection, id, &mut self.receive_body)
                    {
                        Ok(_) => {}
                        Err(quiche::h3::Error::Done) => {
                            flow.readable = false;
                            break;
                        }
                        Err(error) => {
                            reset = Some(map_h3(error));
                            break;
                        }
                    }
                }
            }
            if reset.is_none() && flow.readable && flow.response_ready && flow.datagram {
                for _ in 0..WORK_BATCH {
                    match self
                        .http
                        .as_mut()
                        .ok_or(EngineError::ProtocolViolation)?
                        .recv_body(&mut self.connection, id, &mut self.receive_body)
                    {
                        Ok(length) => {
                            if length == 0 {
                                break;
                            }
                            if let Err(error) =
                                feed_capsules(&self.config, flow, &self.receive_body[..length])
                            {
                                reset = Some(error);
                                break;
                            }
                        }
                        Err(quiche::h3::Error::Done) => {
                            flow.readable = false;
                            break;
                        }
                        Err(error) => {
                            reset = Some(map_h3(error));
                            break;
                        }
                    }
                }
            }
            if flow.remote_finished
                && !flow.readable
                && !flow.read_finish_attempted
                && (flow.read_sender.capacity() != 0 || read_abandoned)
            {
                if let Some(capsules) = &flow.capsules {
                    reset = Some(capsules.finish().err().unwrap_or(EngineError::RemoteReset));
                }
                let _ = flow.read_sender.try_send(ReadEvent::Finished);
                flow.read_finish_attempted = true;
            }
            if let Some(error) = reset {
                self.reset_flow(id, error);
            }
        }
        Ok(())
    }

    fn receive_datagrams(&mut self) -> Result<(), EngineError> {
        for _ in 0..WORK_BATCH {
            let bytes = match self.connection.dgram_recv_buf() {
                Ok(bytes) => bytes,
                Err(quiche::Error::Done) => return Ok(()),
                Err(error) => return Err(map_quic(error)),
            };
            self.receive_datagram(&bytes)?;
            if self.connection_error.is_some() {
                return Ok(());
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    fn receive_datagram(&mut self, bytes: &[u8]) -> Result<(), EngineError> {
        let (id, value) = match http_datagram_stream_id(bytes) {
            Ok(datagram) => datagram,
            Err(_) => return self.close_datagram_error(),
        };
        let Some(flow) = self.flows.get_mut(&id) else {
            return Ok(());
        };
        if !flow.datagram_ready() {
            return Ok(());
        }
        let (context, payload) = split_http_datagram(value)?;
        if context != CONNECT_UDP_CONTEXT_ID
            || payload.len() > self.config.limits.udp_payload_absolute_max
        {
            return Ok(());
        }
        let Some(sender) = &flow.datagrams else {
            return Ok(());
        };
        flow.datagram_idle_deadline = Some(Deadline::after(self.config.datagram_idle_timeout)?);
        if datagram_queue_full(&self.config, flow, sender, payload.len()) {
            return Ok(());
        }
        let payload = match charged_copy(&self.config, payload) {
            Ok(payload) => payload,
            Err(EngineError::ResourceLimitExceeded) => return Ok(()),
            Err(error) => return Err(error),
        };
        enqueue_datagram(flow, sender, payload);
        Ok(())
    }

    fn close_datagram_error(&mut self) -> Result<(), EngineError> {
        if self.connection_error.is_some() {
            return Ok(());
        }
        self.connection_error = Some(EngineError::ProtocolViolation);
        let deadline = Deadline::after(self.config.h2.drain_timeout)?;
        self.cap_drain_deadline(deadline);
        self.close_requested = true;
        self.pending_packet = None;
        self.socket_send_blocked = false;
        let _ = self
            .status
            .send(DriverState::Closing(EngineError::ProtocolViolation));
        self.commands.close();
        self.fail_pending_operations(EngineError::ProtocolViolation);
        self.flows.clear();
        while let Ok(command) = self.commands.try_recv() {
            match command {
                Command::Open { completion, .. } => {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                }
                Command::Write { completion, .. } => {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                }
                Command::Datagram { completion, .. } => {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                }
                Command::Respond { completion, .. } => {
                    let _ = completion.send(Err(EngineError::ProtocolViolation));
                }
                Command::Reset { .. } | Command::Drain { .. } => {}
            }
        }
        match self.connection.close(true, H3_DATAGRAM_ERROR, b"") {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(error) => Err(map_quic(error)),
        }
    }

    fn update_datagram_limits(&mut self) -> Result<(), EngineError> {
        let context_bytes = VarInt::encode(CONNECT_UDP_CONTEXT_ID)?.as_slice().len();
        for (&id, flow) in &self.flows {
            if flow.datagram {
                // QUIC's limit still includes the HTTP Datagram stream and context IDs.
                let overhead = VarInt::encode(id / REQUEST_STREAM_ID_STRIDE)?
                    .as_slice()
                    .len()
                    + context_bytes;
                let maximum = self
                    .connection
                    .dgram_max_writable_len()
                    .unwrap_or(0)
                    .saturating_sub(overhead)
                    .min(self.config.limits.udp_payload_absolute_max)
                    .min(flow.peer_max_payload);
                flow.max_payload.store(maximum, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn collect_flows(&mut self) {
        self.flows.retain(|id, flow| {
            !(flow.read_finish_attempted
                && flow.local_finished
                && self.connection.stream_closed(*id))
        });
    }

    fn reset_flow(&mut self, id: u64, error: EngineError) {
        let datagram = self.flows.get(&id).is_some_and(|flow| flow.datagram);
        self.connection.dgram_purge_outgoing(|bytes| {
            decode_varint(bytes).is_ok_and(|(quarter_stream_id, _)| {
                quarter_stream_id.checked_mul(REQUEST_STREAM_ID_STRIDE) == Some(id)
            })
        });
        if datagram {
            self.pending_packet = None;
            self.socket_send_blocked = false;
        }
        let _ = self
            .connection
            .stream_shutdown(id, quiche::Shutdown::Read, CANCEL_CODE);
        let _ = self
            .connection
            .stream_shutdown(id, quiche::Shutdown::Write, CANCEL_CODE);
        if let Some(http) = &mut self.http {
            // quiche 0.30 needs an H3 call after QUIC shutdown to remove its
            // request state. The shut write side cannot emit these bodies.
            let _ = http.send_body_zc(&mut self.connection, id, &mut Bytes::new(), true);
            if self.connection.is_server() {
                let _ = http.send_response(
                    &mut self.connection,
                    id,
                    &[Header::new(b":status", b"503")],
                    true,
                );
            }
        }
        if let Some(mut flow) = self.flows.remove(&id) {
            flow.fail_pending_operations(error);
            let _ = flow.read_sender.try_send(ReadEvent::Reset);
        }
    }

    fn fail_pending_operations(&mut self, error: EngineError) {
        for flow in self.flows.values_mut() {
            flow.fail_pending_operations(error);
        }
        while let Some(command) = self.pending_opens.pop_front() {
            if let Command::Open { completion, .. } = command {
                let _ = completion.send(Err(error));
            }
        }
    }
}

fn http_datagram_stream_id(bytes: &[u8]) -> Result<(u64, &[u8]), EngineError> {
    let (quarter_stream_id, value) = decode_varint(bytes)?;
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(EngineError::ProtocolViolation);
    }
    Ok((quarter_stream_id * REQUEST_STREAM_ID_STRIDE, value))
}

fn parse_response(list: &[Header]) -> Result<(StatusCode, HeaderMap), EngineError> {
    let mut status = None;
    let mut headers = HeaderMap::new();
    let mut regular_headers_seen = false;
    for header in list {
        if header.name() == b":status" && !regular_headers_seen && status.is_none() {
            let value = StatusCode::from_bytes(header.value())
                .map_err(|_| EngineError::ProtocolViolation)?;
            if value.as_u16() < 100 {
                return Err(EngineError::ProtocolViolation);
            }
            status = Some(value);
        } else if header.name().starts_with(b":") {
            return Err(EngineError::ProtocolViolation);
        } else {
            regular_headers_seen = true;
            append_header(&mut headers, header)?;
        }
    }
    Ok((status.ok_or(EngineError::ProtocolViolation)?, headers))
}

fn parse_request(list: &[Header]) -> Result<(Request<()>, bool), EngineError> {
    let mut pseudo_headers: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
    let mut headers = HeaderMap::new();
    let mut regular_headers_seen = false;
    for header in list {
        if header.name().starts_with(b":") {
            if regular_headers_seen
                || pseudo_headers
                    .insert(header.name(), header.value())
                    .is_some()
            {
                return Err(EngineError::ProtocolViolation);
            }
        } else {
            regular_headers_seen = true;
            append_header(&mut headers, header)?;
        }
    }
    validate_h3_versions(&headers)?;
    if pseudo_headers.get(b":method".as_slice()).copied() != Some(b"CONNECT".as_slice()) {
        return Err(EngineError::ProtocolViolation);
    }
    let authority = std::str::from_utf8(
        pseudo_headers
            .get(b":authority".as_slice())
            .copied()
            .ok_or(EngineError::ProtocolViolation)?,
    )
    .map_err(|_| EngineError::ProtocolViolation)?;
    let parsed_authority = authority
        .parse::<Authority>()
        .map_err(|_| EngineError::ProtocolViolation)?;
    let datagram = pseudo_headers.contains_key(b":protocol".as_slice());
    let uri = if datagram {
        if pseudo_headers.len() != 5
            || pseudo_headers.get(b":protocol".as_slice()).copied() != Some(CONNECT_UDP.as_bytes())
            || pseudo_headers.get(b":scheme".as_slice()).copied() != Some(b"https".as_slice())
            || !capsule_protocol_enabled(&headers)
        {
            return Err(EngineError::ProtocolViolation);
        }
        let path = std::str::from_utf8(
            pseudo_headers
                .get(b":path".as_slice())
                .copied()
                .ok_or(EngineError::ProtocolViolation)?,
        )
        .map_err(|_| EngineError::ProtocolViolation)?;
        if !path.starts_with('/') {
            return Err(EngineError::ProtocolViolation);
        }
        let parsed_path = path
            .parse::<PathAndQuery>()
            .map_err(|_| EngineError::ProtocolViolation)?;
        // PathAndQuery removes fragments. Reject a change to the received path.
        if parsed_path.as_str() != path {
            return Err(EngineError::ProtocolViolation);
        }
        http::Uri::builder()
            .scheme("https")
            .authority(parsed_authority)
            .path_and_query(parsed_path)
            .build()
            .map_err(|_| EngineError::ProtocolViolation)?
    } else {
        if pseudo_headers.len() != 2 {
            return Err(EngineError::ProtocolViolation);
        }
        Destination::parse(authority).map_err(|_| EngineError::ProtocolViolation)?;
        http::Uri::builder()
            .authority(parsed_authority)
            .build()
            .map_err(|_| EngineError::ProtocolViolation)?
    };
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(http::Version::HTTP_3)
        .uri(uri)
        .body(())
        .map_err(|_| EngineError::ProtocolViolation)?;
    *request.headers_mut() = headers;
    if datagram {
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static(CONNECT_UDP));
        target_of_connect_udp_unversioned(&request)?;
    }
    Ok((request, datagram))
}

fn append_header(headers: &mut HeaderMap, header: &Header) -> Result<(), EngineError> {
    if header.name().iter().any(u8::is_ascii_uppercase) {
        return Err(EngineError::ProtocolViolation);
    }
    let name = HeaderName::from_bytes(header.name()).map_err(|_| EngineError::ProtocolViolation)?;
    if matches!(
        name.as_str(),
        "connection"
            | "transfer-encoding"
            | "upgrade"
            | "keep-alive"
            | "proxy-connection"
            | "content-length"
    ) {
        return Err(EngineError::ProtocolViolation);
    }
    if name.as_str() == "te" && header.value() != b"trailers" {
        return Err(EngineError::ProtocolViolation);
    }
    let mut value =
        HeaderValue::from_bytes(header.value()).map_err(|_| EngineError::ProtocolViolation)?;
    if name.as_str() == crate::connect::EXPERIMENTAL_CREDENTIAL_HEADER {
        value.set_sensitive(true);
    }
    headers
        .try_append(name, value)
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ariad_core::{MemoryBudget, ResourceBudget};
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    fn config() -> H3Config {
        let h2 = H2Config {
            process_budget: MemoryBudget::new(16 * 1024 * 1024).unwrap(),
            session_budget: MemoryBudget::new(4 * 1024 * 1024).unwrap(),
            process_flows: ResourceBudget::new(64).unwrap(),
            session_flows: ResourceBudget::new(64).unwrap(),
            process_opens: ResourceBudget::new(8).unwrap(),
            session_opens: ResourceBudget::new(8).unwrap(),
            ..H2Config::default()
        };
        H3Config::from_h2_config(&h2).unwrap()
    }

    #[test]
    fn h3_versions_require_one_supported_value_for_each_header() {
        let mut headers = HeaderMap::new();
        attach_h3_versions(&mut headers);
        assert_eq!(validate_h3_versions(&headers), Ok(()));
        for name in [
            EXPERIMENTAL_H3_BINDING_VERSION_HEADER,
            EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
        ] {
            let mut missing = headers.clone();
            missing.remove(name);
            assert_eq!(
                validate_h3_versions(&missing),
                Err(EngineError::ProtocolViolation)
            );
            let mut duplicate = headers.clone();
            duplicate.append(name, headers[name].clone());
            assert_eq!(
                validate_h3_versions(&duplicate),
                Err(EngineError::ProtocolViolation)
            );
            let mut invalid = headers.clone();
            invalid.insert(name, HeaderValue::from_static("00"));
            assert_eq!(
                validate_h3_versions(&invalid),
                Err(EngineError::ProtocolViolation)
            );
        }
        headers.insert(
            EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
            HeaderValue::from_static("0"),
        );
        assert_eq!(
            validate_h3_versions(&headers),
            Err(EngineError::ProtocolViolation)
        );
    }

    #[test]
    fn h3_memory_limits_must_match_the_charged_pools() {
        for session_bytes in [2 * 1024 * 1024, 8 * 1024 * 1024] {
            let mut config = config();
            config.limits.session_application_budget = session_bytes;
            assert_eq!(config.limits.validate(), Ok(()));
            assert_eq!(config.validate(), Err(EngineError::InvalidConfig));
            assert_eq!(config.h2.session_budget.used(), 0);
        }
        for process_bytes in [8 * 1024 * 1024, 32 * 1024 * 1024] {
            let mut config = config();
            config.limits.global_application_budget = process_bytes;
            assert_eq!(config.limits.validate(), Ok(()));
            assert_eq!(config.validate(), Err(EngineError::InvalidConfig));
            assert_eq!(config.h2.process_budget.used(), 0);
        }
    }

    #[test]
    fn h3_admission_pools_cannot_exceed_the_declared_flow_and_open_caps() {
        let mut flow_config = config();
        flow_config.limits.active_flows_per_session = 16;
        assert_eq!(flow_config.limits.validate(), Ok(()));
        assert_eq!(flow_config.validate(), Err(EngineError::InvalidConfig));
        assert_eq!(flow_config.h2.session_flows.used(), 0);

        let mut open_config = config();
        open_config.limits.pending_egress_opens = 4;
        assert_eq!(open_config.limits.validate(), Ok(()));
        assert_eq!(open_config.validate(), Err(EngineError::InvalidConfig));
        assert_eq!(open_config.h2.session_opens.used(), 0);
    }

    #[test]
    fn h3_allows_stricter_admission_pools_and_binding_specific_limits() {
        let mut config = config();
        config.h2.session_flows = ResourceBudget::new(16).unwrap();
        config.h2.session_opens = ResourceBudget::new(4).unwrap();
        config.limits.decoded_header_bytes = 16 * 1024;
        config.limits.decoded_header_fields = 32;
        config.limits.stream_queue_per_direction = 64 * 1024;
        config.limits.control_reserve = 32 * 1024;
        assert_ne!(
            config.limits.decoded_header_bytes,
            config.h2.max_header_bytes
        );
        assert_ne!(
            config.limits.decoded_header_fields,
            config.h2.max_header_count
        );
        assert_ne!(
            config.limits.stream_queue_per_direction,
            config.h2.direction_buffer_bytes
        );
        assert_ne!(
            config.limits.control_reserve,
            config.h2.control_reserve_bytes
        );
        assert_eq!(config.validate(), Ok(()));
    }

    fn queued_connect() -> (H3Connect, mpsc::Receiver<Command>) {
        let config = config();
        let metadata = shared_metadata_reservation(&config, false).unwrap();
        let (commands, receiver) = mpsc::channel(1);
        let (_, state) = watch::channel(DriverState::Ready {
            extended_connect: true,
            native_datagram: true,
            max_datagram_bytes: 1200,
        });
        let shared = Arc::new(SessionControl {
            commands,
            wake: Arc::new(Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
            state,
            task: Mutex::new(None),
            config,
            _metadata: metadata,
        });
        let (_, read_events) = mpsc::channel(1);
        let handle_memory = Arc::new(shared.config.reserve(METADATA_RESERVE_BYTES).unwrap());
        let stream = connect_from_handle(
            shared,
            FlowHandle {
                id: 256,
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                read_events,
                buffered_body_bytes: Arc::new(AtomicUsize::new(0)),
                read_abandoned: Arc::new(AtomicBool::new(false)),
                datagrams: None,
                max_payload: Arc::new(AtomicUsize::new(1197)),
                queued_datagram_bytes: Arc::new(AtomicUsize::new(0)),
                terminal: Arc::new(Mutex::new(None)),
                response_memory: None,
                handle_memory,
            },
        );
        (stream, receiver)
    }

    fn queued_association() -> (H3DatagramAssociation, mpsc::Receiver<Command>) {
        let (stream, receiver) = queued_connect();
        let (_, receives) = mpsc::channel(1);
        (
            datagram_from_stream(
                stream,
                receives,
                1,
                Arc::new(AtomicUsize::new(1197)),
                Arc::new(AtomicUsize::new(0)),
            ),
            receiver,
        )
    }

    async fn unestablished_driver() -> (Arc<SessionControl>, Driver) {
        let config = config();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let native_memory = config.native_reservation().unwrap();
        let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.configure(&mut quic_config).unwrap();
        let cid = quiche::ConnectionId::from_ref(b"parser-test");
        let connection = quiche::connect_with_buffer_factory::<NativeBufFactory>(
            Some("unit.test"),
            &cid,
            local,
            local,
            &mut quic_config,
        )
        .unwrap();
        let metadata = shared_metadata_reservation(&config, false).unwrap();
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        make_driver(
            connection,
            socket,
            local,
            local,
            DriverSetup {
                config,
                deadline,
                trust: None,
                incoming: None,
                native_memory,
                metadata,
            },
        )
        .unwrap()
    }

    #[test]
    fn http_datagram_quarter_stream_id_has_the_quic_stream_bound() {
        let maximum = VarInt::encode(MAX_QUARTER_STREAM_ID).unwrap();
        assert_eq!(
            http_datagram_stream_id(maximum.as_slice()),
            Ok(((1 << 62) - 4, b"".as_slice()))
        );
        let invalid = VarInt::encode(MAX_QUARTER_STREAM_ID + 1).unwrap();
        assert_eq!(
            http_datagram_stream_id(invalid.as_slice()),
            Err(EngineError::ProtocolViolation)
        );
        for truncated in [b"".as_slice(), b"\xc0\x00".as_slice()] {
            assert_eq!(
                http_datagram_stream_id(truncated),
                Err(EngineError::ProtocolViolation)
            );
        }
    }

    #[tokio::test]
    async fn unknown_valid_datagram_streams_drop_without_closing_the_connection() {
        let (_shared, mut driver) = unestablished_driver().await;
        for quarter_stream_id in [0, MAX_QUARTER_STREAM_ID] {
            for value in [
                b"".as_slice(),
                b"\xc0\x00".as_slice(),
                b"\x00packet".as_slice(),
            ] {
                let mut bytes = VarInt::encode(quarter_stream_id)
                    .unwrap()
                    .as_slice()
                    .to_vec();
                bytes.extend_from_slice(value);
                assert_eq!(driver.receive_datagram(&bytes), Ok(()));
                assert!(driver.connection_error.is_none());
                assert!(driver.connection.local_error().is_none());
                assert!(driver.draining_deadline.is_none());
            }
        }
    }

    #[tokio::test]
    async fn receive_closed_datagram_stream_drops_unparsed_payloads() {
        let (shared, mut driver) = unestablished_driver().await;
        let flow_permit = shared.config.h2.reserve_flow().unwrap();
        let (mut flow, mut handle) = driver.new_flow(0, true, flow_permit, None, None).unwrap();
        flow.response_ready = true;
        flow.remote_finished = true;
        driver.flows.insert(0, flow);
        for bytes in [
            b"\x00".as_slice(),
            b"\x00\xc0\x00".as_slice(),
            b"\x00\x00packet".as_slice(),
        ] {
            assert_eq!(driver.receive_datagram(bytes), Ok(()));
        }
        assert!(matches!(
            handle.datagrams.as_mut().unwrap().try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(driver.connection_error.is_none());
        assert!(driver.connection.local_error().is_none());
        assert!(driver.draining_deadline.is_none());
    }

    #[tokio::test]
    async fn active_datagram_stream_validates_context_before_delivery() {
        let (shared, mut driver) = unestablished_driver().await;
        let flow_permit = shared.config.h2.reserve_flow().unwrap();
        let (mut flow, mut handle) = driver.new_flow(0, true, flow_permit, None, None).unwrap();
        flow.response_ready = true;
        driver.flows.insert(0, flow);
        for bytes in [b"\x00".as_slice(), b"\x00\xc0\x00".as_slice()] {
            assert_eq!(
                driver.receive_datagram(bytes),
                Err(EngineError::ProtocolViolation)
            );
        }
        driver.receive_datagram(b"\x00\x00packet").unwrap();
        assert_eq!(
            handle.datagrams.as_mut().unwrap().try_recv().unwrap(),
            b"packet".as_slice()
        );
    }

    #[tokio::test]
    async fn invalid_datagram_stream_id_fails_pending_and_blocked_operations() {
        let (shared, mut driver) = unestablished_driver().await;
        let flow_permit = shared.config.h2.reserve_flow().unwrap();
        let (mut flow, handle) = driver.new_flow(0, true, flow_permit, None, None).unwrap();
        let terminal = flow.terminal.clone();
        let (open_completion, open_result) = oneshot::channel();
        flow.open_completion = Some(open_completion);
        flow.handle = Some(handle);
        driver.flows.insert(0, flow);
        let (queued_completion, queued_result) = oneshot::channel();
        assert!(
            shared
                .commands
                .try_send(Command::Write {
                    id: 0,
                    bytes: Bytes::new(),
                    fin: false,
                    deadline: Deadline::after(Duration::from_secs(1)).unwrap(),
                    completion: queued_completion,
                })
                .is_ok()
        );
        while shared.commands.capacity() != 0 {
            assert!(shared.commands.try_send(Command::Reset { id: 4 }).is_ok());
        }
        let (blocked_completion, _blocked_result) = oneshot::channel();
        let mut blocked = Box::pin(send_command(
            &shared,
            Command::Write {
                id: 0,
                bytes: Bytes::new(),
                fin: false,
                deadline: Deadline::after(Duration::from_secs(1)).unwrap(),
                completion: blocked_completion,
            },
            Deadline::after(Duration::from_secs(1)).unwrap(),
        ));
        assert!(poll_fn(|context| Poll::Ready(blocked.as_mut().poll(context).is_pending())).await);
        let earlier = Deadline::after(Duration::from_millis(100)).unwrap();
        driver.draining_deadline = Some(earlier);
        let invalid = VarInt::encode(MAX_QUARTER_STREAM_ID + 1).unwrap();
        assert_eq!(driver.receive_datagram(invalid.as_slice()), Ok(()));
        assert_eq!(
            driver.connection_error,
            Some(EngineError::ProtocolViolation)
        );
        assert!(matches!(
            *shared.state.borrow(),
            DriverState::Closing(EngineError::ProtocolViolation)
        ));
        assert_eq!(
            driver.draining_deadline.unwrap().expires_at(),
            earlier.expires_at()
        );
        driver.close_datagram_error().unwrap();
        assert_eq!(
            driver.draining_deadline.unwrap().expires_at(),
            earlier.expires_at()
        );
        assert!(driver.close_requested);
        assert!(driver.flows.is_empty());
        assert!(matches!(
            open_result.await,
            Ok(Err(EngineError::ProtocolViolation))
        ));
        assert_eq!(
            queued_result.await.unwrap(),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(blocked.await, Err(EngineError::ProtocolViolation));
        assert_eq!(
            *terminal.lock().unwrap(),
            Some(EngineError::ProtocolViolation)
        );
        assert_eq!(check_ready(&shared), Err(EngineError::ProtocolViolation));
        assert_eq!(driver_error(&shared), Some(EngineError::ProtocolViolation));
        assert_eq!(driver.run().await, Err(EngineError::ProtocolViolation));
    }

    #[tokio::test]
    async fn last_control_drop_keeps_the_bounded_protocol_close_task_alive() {
        let (shared, mut driver) = unestablished_driver().await;
        driver.close_datagram_error().unwrap();
        let expires_at = driver.draining_deadline.unwrap().expires_at();
        assert_eq!(Arc::strong_count(&shared), 1);
        let weak = Arc::downgrade(&shared);
        let (resume, resumed) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            resumed.await.unwrap();
            assert_eq!(driver.draining_deadline.unwrap().expires_at(), expires_at);
            assert_eq!(driver.run().await, Err(EngineError::ProtocolViolation));
            let _ = completed.send(());
        });
        *shared.task.lock().unwrap() = Some(task);
        drop(shared);
        assert!(weak.upgrade().is_none());
        resume.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), completion)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn closing_waits_for_driver_release_and_keeps_its_error_on_task_drop() {
        let (shared, mut driver) = unestablished_driver().await;
        driver.close_datagram_error().unwrap();
        let status = driver.status.clone();
        let owned = DriverTask {
            driver: Some(driver),
            status,
            outcome: None,
        };
        let retained = shared.config.h2.process_budget.used();
        let mut closed = Box::pin(wait_closed(&shared));
        assert!(poll_fn(|context| Poll::Ready(closed.as_mut().poll(context).is_pending())).await);
        drop(owned);
        assert_eq!(closed.await, Err(EngineError::ProtocolViolation));
        assert!(shared.config.h2.process_budget.used() < retained);
    }

    #[tokio::test]
    async fn last_control_drop_aborts_a_task_before_protocol_closing() {
        let (shared, driver) = unestablished_driver().await;
        let (_resume, resumed) = oneshot::channel::<()>();
        let (completed, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            resumed.await.unwrap();
            drop(driver);
            let _ = completed.send(());
        });
        *shared.task.lock().unwrap() = Some(task);
        drop(shared);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), completion)
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn shutdown_waits_for_protocol_closing_without_requesting_abort() {
        for close_before_poll in [false, true] {
            let (shared, mut driver) = unestablished_driver().await;
            while shared.commands.capacity() != 0 {
                assert!(shared.commands.try_send(Command::Reset { id: 4 }).is_ok());
            }
            if close_before_poll {
                driver.close_datagram_error().unwrap();
            }
            let mut shutting_down = Box::pin(shutdown(
                &shared,
                Deadline::after(Duration::from_secs(1)).unwrap(),
            ));
            assert!(
                poll_fn(|context| Poll::Ready(shutting_down.as_mut().poll(context).is_pending()))
                    .await
            );
            if !close_before_poll {
                driver.close_datagram_error().unwrap();
                assert!(
                    poll_fn(|context| Poll::Ready(
                        shutting_down.as_mut().poll(context).is_pending()
                    ))
                    .await
                );
            }
            assert!(!shared.cancelled.load(Ordering::Acquire));
            let status = driver.status.clone();
            drop(DriverTask {
                driver: Some(driver),
                status,
                outcome: None,
            });
            assert_eq!(shutting_down.await, Err(EngineError::ProtocolViolation));
        }
    }

    #[tokio::test]
    async fn dropped_read_half_keeps_writer_and_weak_control_keeps_only_metadata_charge() {
        let (stream, mut commands) = queued_connect();
        let budget = stream.read.owner.shared.config.h2.process_budget.clone();
        let charge = stream.read.owner._handle_memory.bytes();
        let control = stream.control();
        let (reader, mut writer) = stream.into_split();
        drop(reader);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let (written, ()) = tokio::join!(writer.write(b"still-open", deadline), async {
            match commands.recv().await.unwrap() {
                Command::Write {
                    id,
                    bytes,
                    fin,
                    completion,
                    ..
                } => {
                    assert_eq!(id, 256);
                    assert!(!fin);
                    assert_eq!(bytes.as_ref(), b"still-open");
                    completion.send(Ok(bytes.len())).unwrap();
                }
                _ => panic!("expected a write after reader drop"),
            }
        });
        assert_eq!(written, Ok(10));
        drop(writer);
        assert!(matches!(
            commands.recv().await,
            Some(Command::Reset { id: 256 })
        ));
        assert_eq!(control.cancel(), Err(EngineError::Cancelled));
        assert_eq!(budget.used(), charge);
        drop(control);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn dropped_finished_writer_keeps_reader_and_final_eof_avoids_reset() {
        let (stream, mut commands) = queued_connect();
        let (mut reader, mut writer) = stream.into_split();
        let (events, read_events) = mpsc::channel(2);
        reader.read_events = read_events;
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let (ended, ()) = tokio::join!(writer.end_write(deadline), async {
            match commands.recv().await.unwrap() {
                Command::Write {
                    bytes,
                    fin,
                    completion,
                    ..
                } => {
                    assert!(bytes.is_empty());
                    assert!(fin);
                    completion.send(Ok(0)).unwrap();
                }
                _ => panic!("expected FIN"),
            }
        });
        assert_eq!(ended, Ok(()));
        drop(writer);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let bytes = charged_copy(&reader.owner.shared.config, b"reply").unwrap();
        reader
            .buffered_body_bytes
            .fetch_add(bytes.len(), Ordering::Relaxed);
        assert!(events.send(ReadEvent::Data(bytes)).await.is_ok());
        assert!(events.send(ReadEvent::Finished).await.is_ok());
        let mut out = [0u8; 5];
        assert_eq!(
            reader.read(&mut out, deadline).await,
            Ok(ReadOutcome::Data(5))
        );
        assert_eq!(&out, b"reply");
        assert_eq!(reader.read(&mut out, deadline).await, Ok(ReadOutcome::Eof));
        drop(reader);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn control_cancellation_preserves_its_reason_in_a_pending_write_completion() {
        let (stream, mut commands) = queued_connect();
        let control = stream.control();
        let (_reader, mut writer) = stream.into_split();
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let (written, ()) = tokio::join!(writer.write(b"pending", deadline), async {
            let completion = match commands.recv().await.unwrap() {
                Command::Write { completion, .. } => completion,
                _ => panic!("expected a pending write"),
            };
            control.cancel().unwrap();
            assert!(matches!(
                commands.recv().await,
                Some(Command::Reset { id: 256 })
            ));
            completion.send(Err(EngineError::RemoteReset)).unwrap();
        });
        assert_eq!(written, Err(EngineError::Cancelled));
    }

    #[tokio::test]
    async fn command_queue_timeout_preserves_write_deadline_for_both_halves() {
        let (stream, mut commands) = queued_connect();
        let (mut reader, mut writer) = stream.into_split();
        assert!(
            writer
                .owner
                .shared
                .commands
                .try_send(Command::Reset { id: 0 })
                .is_ok()
        );
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let mut pending = Box::pin(writer.write(b"pending", deadline));
        assert!(poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await);
        assert_eq!(pending.await, Err(EngineError::DeadlineExceeded));
        assert!(writer.owner.shared.cancelled.load(Ordering::Acquire));
        let next_deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let mut out = [0xa5; 8];
        assert_eq!(
            reader.read(&mut out, next_deadline).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(out, [0xa5; 8]);
        assert_eq!(
            writer.write(b"later", next_deadline).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert!(matches!(commands.try_recv(), Ok(Command::Reset { id: 0 })));
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn driver_write_expiry_records_the_deadline_before_waking_both_halves() {
        let (shared, mut driver) = unestablished_driver().await;
        let memory = shared.config.h2.process_budget.clone();
        let flows = shared.config.h2.process_flows.clone();
        let flow_permit = shared.config.h2.reserve_flow().unwrap();
        let (mut flow, mut handle) = driver.new_flow(0, false, flow_permit, None, None).unwrap();
        flow.response_ready = true;
        handle.status = StatusCode::OK;
        driver.flows.insert(0, flow);
        let stream = connect_from_handle(shared.clone(), handle);
        let (mut reader, mut writer) = stream.into_split();
        let (completion, result) = oneshot::channel();
        driver
            .handle_command(Command::Write {
                id: 0,
                bytes: charged_copy(&shared.config, b"expired").unwrap(),
                fin: false,
                deadline: Deadline::at(Instant::now()),
                completion,
            })
            .unwrap();
        driver.advance_flows().unwrap();
        let write_outcome = tokio::time::timeout(Duration::from_secs(1), result)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(write_outcome, Err(EngineError::DeadlineExceeded));
        assert!(driver.flows.is_empty());
        assert_eq!(flows.used(), 0);
        assert_eq!(
            reader.owner.terminal_error(),
            Some(EngineError::DeadlineExceeded)
        );
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let mut out = [0xa5; 8];
        assert_eq!(
            reader.read(&mut out, deadline).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(out, [0xa5; 8]);
        assert_eq!(
            writer.write(b"later", deadline).await,
            Err(EngineError::DeadlineExceeded)
        );
        drop(reader);
        drop(writer);
        drop(driver);
        drop(shared);
        assert_eq!(memory.used(), 0);
    }

    #[tokio::test]
    async fn unsafe_logging_rejects_client_and_server_before_io_or_reservation() {
        if log::STATIC_MAX_LEVEL <= log::LevelFilter::Info {
            return;
        }
        let fixture = crate::native_tls::test_support::CertificateFixture::new(false);
        let trust = NativeTlsConnector::new(fixture.policy()).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = config();
        let session_budget = config.h2.session_budget.clone();
        let process_budget = config.h2.process_budget.clone();
        let result = H3Session::connect(
            client,
            &fixture.endpoint(BindingId::H3),
            peer.local_addr().unwrap(),
            &trust,
            config.clone(),
            Deadline::after(Duration::from_secs(1)).unwrap(),
        )
        .await;
        assert!(matches!(result, Err(EngineError::UnsupportedCapability)));
        assert_eq!(session_budget.used(), 0);
        assert_eq!(process_budget.used(), 0);
        assert_eq!(
            peer.try_recv_from(&mut [0; 1200]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = H3ServerSession::accept(
            server,
            &fixture.server(),
            config,
            Deadline::after(Duration::from_secs(1)).unwrap(),
        )
        .await;
        assert!(matches!(result, Err(EngineError::UnsupportedCapability)));
        assert_eq!(session_budget.used(), 0);
        assert_eq!(process_budget.used(), 0);
    }

    #[tokio::test]
    async fn unsafe_logging_rejects_h3_policy_before_host_dns_and_socket_hooks() {
        if log::STATIC_MAX_LEVEL <= log::LevelFilter::Info {
            return;
        }
        struct UnusedHost;

        impl crate::BootstrapResolver for UnusedHost {
            fn resolve<'a>(
                &'a self,
                _hostname: &'a str,
                _port: u16,
                _max_addresses: usize,
            ) -> crate::BootstrapResolution<'a> {
                panic!("unsupported H3 must not resolve")
            }
        }

        impl crate::SocketFactory for UnusedHost {
            fn create_tcp(
                &self,
                _address: SocketAddr,
            ) -> Result<tokio::net::TcpSocket, EngineError> {
                panic!("unsupported H3 must not create a socket")
            }

            fn create_udp(&self, _address: SocketAddr) -> Result<socket2::Socket, EngineError> {
                panic!("unsupported H3 must not create a socket")
            }
        }

        let fixture = crate::native_tls::test_support::CertificateFixture::new(false);
        let host = crate::HostServices::new(
            Arc::new(UnusedHost),
            Arc::new(UnusedHost),
            vec![fixture.policy()],
            2,
        )
        .unwrap();
        let mut endpoint = fixture.endpoint(BindingId::H3);
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        assert_eq!(
            host.resolve_endpoint(&endpoint, 443, deadline).await,
            Err(EngineError::UnsupportedCapability)
        );
        endpoint.bindings.push(BindingId::H2);
        assert_eq!(host.supports_endpoint(&endpoint), Ok(()));
        assert_eq!(host.supports_binding(&endpoint, BindingId::H2), Ok(()));
        let result = host
            .connect_h3_verified(
                &endpoint,
                "127.0.0.1:443".parse().unwrap(),
                config(),
                deadline,
            )
            .await;
        assert!(matches!(result, Err(EngineError::UnsupportedCapability)));
    }

    #[test]
    fn h3_connect_has_only_method_authority_and_its_own_binding() {
        let destination = Destination::parse("example.test:443").unwrap();
        let mut request = connect_template(&destination).unwrap();
        request
            .headers_mut()
            .remove(EXPERIMENTAL_H2_BINDING_VERSION_HEADER);
        attach_h3_versions(request.headers_mut());
        attach_credential(&mut request, &Credential::from_bytes([0x42; 32])).unwrap();
        let list = request_headers(&request, false).unwrap();
        assert_eq!(
            list.iter()
                .filter(|header| header.name().starts_with(b":"))
                .count(),
            2
        );
        let (request, datagram) = parse_request(&list).unwrap();
        assert!(!datagram);
        assert_eq!(request.version(), http::Version::HTTP_3);
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            "example.test:443"
        );
        assert!(request.headers()[crate::connect::EXPERIMENTAL_CREDENTIAL_HEADER].is_sensitive());
    }

    #[test]
    fn h3_connect_udp_uses_canonical_masque_target_and_rejects_h2_binding() {
        let destination = Destination::parse("[2001:db8::1]:53").unwrap();
        let mut request = connect_udp_template("proxy.test", &destination).unwrap();
        assert!(matches!(
            parse_request(&request_headers(&request, true).unwrap()),
            Err(EngineError::ProtocolViolation)
        ));
        request
            .headers_mut()
            .remove(EXPERIMENTAL_H2_BINDING_VERSION_HEADER);
        attach_h3_versions(request.headers_mut());
        let (decoded, datagram) = parse_request(&request_headers(&request, true).unwrap()).unwrap();
        assert!(datagram);
        assert_eq!(target_of_connect_udp_unversioned(&decoded), Ok(destination));
        let mut invalid = request_headers(&request, true).unwrap();
        invalid.push(Header::new(
            b":path",
            b"/.well-known/masque/udp/example.test/0/",
        ));
        assert!(matches!(
            parse_request(&invalid),
            Err(EngineError::ProtocolViolation)
        ));
    }

    fn datagram_request_headers(proxy: &str, target: &str) -> Vec<Header> {
        let mut request =
            connect_udp_template(proxy, &Destination::parse(target).unwrap()).unwrap();
        request
            .headers_mut()
            .remove(EXPERIMENTAL_H2_BINDING_VERSION_HEADER);
        attach_h3_versions(request.headers_mut());
        request_headers(&request, true).unwrap()
    }

    #[test]
    fn h3_connect_udp_rejects_components_that_form_a_valid_uri_only_when_joined() {
        for (authority, path) in [
            ("proxy.test", ":443/.well-known/masque/udp/example.test/53/"),
            ("proxy.test/.well-known/masque/udp/example.test/53", "/"),
        ] {
            let mut headers = datagram_request_headers("proxy.test", "example.test:53");
            for header in &mut headers {
                if header.name() == b":authority" {
                    *header = Header::new(b":authority", authority.as_bytes());
                } else if header.name() == b":path" {
                    *header = Header::new(b":path", path.as_bytes());
                }
            }
            assert!(matches!(
                parse_request(&headers),
                Err(EngineError::ProtocolViolation)
            ));
        }
    }

    #[test]
    fn h3_connect_udp_preserves_valid_authority_and_path_components() {
        for (proxy, target) in [
            ("proxy.test", "example.test:53"),
            ("proxy.test:443", "[2001:db8::1]:53"),
            ("[2001:db8::2]:443", "192.0.2.1:53"),
        ] {
            let headers = datagram_request_headers(proxy, target);
            let original_path = headers
                .iter()
                .find(|header| header.name() == b":path")
                .unwrap()
                .value();
            let (request, datagram) = parse_request(&headers).unwrap();
            assert!(datagram);
            assert_eq!(request.uri().scheme_str(), Some("https"));
            assert_eq!(request.uri().authority().unwrap().as_str(), proxy);
            assert_eq!(request.uri().path().as_bytes(), original_path);
            assert_eq!(
                target_of_connect_udp_unversioned(&request),
                Ok(Destination::parse(target).unwrap())
            );
        }
    }

    #[test]
    fn h3_connect_udp_requires_nonempty_authority_and_original_origin_form_path() {
        for (authority, path) in [
            ("", "/.well-known/masque/udp/example.test/53/"),
            ("proxy.test", ""),
            (
                "proxy.test",
                "https://proxy.test/.well-known/masque/udp/example.test/53/",
            ),
            (
                "proxy.test",
                "/.well-known/masque/udp/example.test/53/#fragment",
            ),
        ] {
            let mut headers = datagram_request_headers("proxy.test", "example.test:53");
            for header in &mut headers {
                if header.name() == b":authority" {
                    *header = Header::new(b":authority", authority.as_bytes());
                } else if header.name() == b":path" {
                    *header = Header::new(b":path", path.as_bytes());
                }
            }
            assert!(matches!(
                parse_request(&headers),
                Err(EngineError::ProtocolViolation)
            ));
        }
    }

    #[test]
    fn h3_capsule_request_rejects_content_type_without_changing_connect() {
        let mut datagram_headers = datagram_request_headers("proxy.test", "example.test:53");
        datagram_headers.push(Header::new(b"content-type", b"application/octet-stream"));
        assert!(matches!(
            parse_request(&datagram_headers),
            Err(EngineError::ProtocolViolation)
        ));
        let mut request =
            connect_template(&Destination::parse("example.test:443").unwrap()).unwrap();
        request
            .headers_mut()
            .remove(EXPERIMENTAL_H2_BINDING_VERSION_HEADER);
        attach_h3_versions(request.headers_mut());
        let mut connect_headers = request_headers(&request, false).unwrap();
        connect_headers.push(Header::new(b"content-type", b"application/octet-stream"));
        let (request, datagram) = parse_request(&connect_headers).unwrap();
        assert!(!datagram);
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/octet-stream"
        );
    }

    #[test]
    fn large_h3_header_list_returns_a_resource_error_without_unwinding() {
        let mut headers = vec![Header::new(b":status", b"200")];
        for index in 0..40_000 {
            headers.push(Header::new(format!("x-{index}").as_bytes(), b"v"));
        }
        let mut config = config();
        config.limits.decoded_header_fields = headers.len();
        config.limits.decoded_header_bytes = 2 * 1024 * 1024;
        assert_eq!(config.validate(), Ok(()));
        assert!(header_size(&headers, &config).is_ok());
        assert!(matches!(
            std::panic::catch_unwind(|| parse_response(&headers)),
            Ok(Err(EngineError::ResourceLimitExceeded))
        ));
    }

    #[tokio::test]
    async fn capsule_responses_are_validated_before_flow_publication() {
        for (status, content_type, datagram, invalid) in [
            (StatusCode::NO_CONTENT, false, true, true),
            (StatusCode::RESET_CONTENT, false, true, true),
            (StatusCode::PARTIAL_CONTENT, false, true, true),
            (StatusCode::OK, true, true, true),
            (StatusCode::OK, false, true, false),
            (StatusCode::UNAUTHORIZED, true, true, false),
            (StatusCode::NO_CONTENT, true, false, false),
        ] {
            let (shared, mut driver) = unestablished_driver().await;
            let permit = shared.config.h2.reserve_flow().unwrap();
            let (mut flow, handle) = driver.new_flow(0, datagram, permit, None, None).unwrap();
            let (completion, mut result) = oneshot::channel();
            flow.open_completion = Some(completion);
            flow.handle = Some(handle);
            driver.flows.insert(0, flow);
            let mut headers = vec![
                Header::new(b":status", status.as_str().as_bytes()),
                Header::new(
                    EXPERIMENTAL_PROTOCOL_VERSION_HEADER.as_bytes(),
                    PROTOCOL_VERSION_TEXT.as_bytes(),
                ),
                Header::new(
                    EXPERIMENTAL_H3_BINDING_VERSION_HEADER.as_bytes(),
                    H3_BINDING_VERSION_TEXT.as_bytes(),
                ),
                Header::new(
                    CAPSULE_PROTOCOL.as_bytes(),
                    CAPSULE_PROTOCOL_ENABLED.as_bytes(),
                ),
            ];
            if content_type {
                headers.push(Header::new(b"content-type", b"application/octet-stream"));
            }
            if invalid {
                assert_eq!(
                    driver.headers(0, headers),
                    Err(EngineError::ProtocolViolation)
                );
                assert!(!driver.flows[&0].response_ready);
                assert!(matches!(
                    result.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
            } else {
                assert_eq!(driver.headers(0, headers), Ok(()));
                let handle = result.try_recv().unwrap().unwrap();
                assert_eq!(handle.status, status);
                assert_eq!(driver.flows[&0].response_ready, status.is_success());
                if status == StatusCode::UNAUTHORIZED {
                    assert_eq!(
                        classify_connect_status(handle.status),
                        Err(EngineError::AuthenticationDenied)
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn forbidden_capsule_status_is_not_queued_by_a_response_command() {
        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::PARTIAL_CONTENT,
        ] {
            let (shared, mut driver) = unestablished_driver().await;
            let permit = shared.config.h2.reserve_flow().unwrap();
            let (flow, _handle) = driver.new_flow(0, true, permit, None, None).unwrap();
            driver.flows.insert(0, flow);
            let (completion, result) = oneshot::channel();
            assert_eq!(
                driver.handle_command(Command::Respond {
                    id: 0,
                    status,
                    deadline: Deadline::after(Duration::from_secs(1)).unwrap(),
                    completion,
                }),
                Ok(())
            );
            assert_eq!(result.await.unwrap(), Err(EngineError::ProtocolViolation));
            assert!(driver.flows[&0].pending_response.is_none());
            assert!(!driver.flows[&0].response_ready);
        }
    }

    #[test]
    fn empty_owned_payload_remains_charged_until_last_clone() {
        let config = config();
        let payload = charged_copy(&config, b"").unwrap();
        let charge = config.h2.session_budget.used();
        assert!(charge >= std::mem::size_of::<ChargedBuffer>());
        let clone = payload.clone();
        drop(payload);
        assert_eq!(config.h2.session_budget.used(), charge);
        drop(clone);
        assert_eq!(config.h2.session_budget.used(), 0);
        assert_eq!(config.h2.process_budget.used(), 0);
    }

    #[tokio::test]
    async fn expired_datagram_send_does_not_allocate_or_enqueue() {
        let (mut association, mut commands) = queued_association();
        let budget = association
            .send
            .stream
            .owner
            .shared
            .config
            .h2
            .session_budget
            .clone();
        let before = budget.used();
        assert_eq!(
            association
                .send(b"packet", Deadline::at(Instant::now()))
                .await,
            Err(EngineError::DeadlineExceeded)
        );
        assert_eq!(budget.used(), before);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn discarded_dequeued_datagram_releases_its_queue_count_and_charge() {
        let (mut association, _commands) = queued_association();
        let budget = association
            .recv
            .stream
            .owner
            .shared
            .config
            .h2
            .session_budget
            .clone();
        let before = budget.used();
        let (sender, receives) = mpsc::channel(1);
        association.recv.receives = receives;
        let bytes =
            charged_copy(&association.recv.stream.owner.shared.config, b"discarded").unwrap();
        association
            .recv
            .queued_datagram_bytes
            .fetch_add(bytes.len(), Ordering::Relaxed);
        assert!(sender.try_send(bytes).is_ok());
        let queued_bytes = association.recv.queued_datagram_bytes.clone();
        let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
        let mut pending = Box::pin(deadline.run(async {
            let bytes = association.recv.dequeue().await?;
            std::future::pending::<()>().await;
            Ok(bytes)
        }));
        assert!(poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending())).await);
        assert_eq!(queued_bytes.load(Ordering::Relaxed), 0);
        assert!(budget.used() > before);
        let discarded = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap();
        assert!(matches!(discarded, Err(EngineError::DeadlineExceeded)));
        assert_eq!(
            association
                .recv
                .queued_datagram_bytes
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(budget.used(), before);
        assert_eq!(association.recv.check_open(), Ok(()));

        let bytes = charged_copy(&association.recv.stream.owner.shared.config, b"next").unwrap();
        association
            .recv
            .queued_datagram_bytes
            .fetch_add(bytes.len(), Ordering::Relaxed);
        assert!(sender.try_send(bytes).is_ok());
        let payload = association
            .recv(Deadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        assert_eq!(payload.as_bytes(), b"next");
        assert_eq!(
            association
                .recv
                .queued_datagram_bytes
                .load(Ordering::Relaxed),
            0
        );
        assert!(budget.used() > before);
        drop(payload);
        assert_eq!(budget.used(), before);
    }

    #[tokio::test]
    async fn h3_datagram_command_contains_quarter_stream_id_context_and_whole_payload() {
        let (mut association, mut commands) = queued_association();
        let deadline = Deadline::after(Duration::from_secs(5)).unwrap();
        let (outcome, ()) = tokio::join!(association.send(b"packet", deadline), async {
            match commands.recv().await.unwrap() {
                Command::Datagram {
                    id,
                    bytes,
                    completion,
                    ..
                } => {
                    assert_eq!(id, 256);
                    assert_eq!(bytes.as_ref(), b"\x40\x40\x00packet");
                    let _ = completion.send(Ok(DatagramOutcome::Queued));
                }
                _ => panic!("expected whole datagram command"),
            }
        });
        assert_eq!(outcome, Ok(DatagramOutcome::Queued));
    }
}
