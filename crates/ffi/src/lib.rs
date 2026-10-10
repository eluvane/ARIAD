//! Synchronous H2 handles with one runtime driver thread per engine.
//! Blocking network calls must run on native threads outside Tokio tasks.
//! UI and async hosts must dispatch these calls to host worker threads.
//! Network tasks advance between calls. Stream read/write and association
//! send/recv use independent locks. Registry and owner locks cover bookkeeping,
//! never network waits. Overlapping calls can return [`ARIAD_ERROR_BUSY`] for
//! an occupied direction or a contended bookkeeping lock.
//!
//! Input pointers are borrowed only for the call; retained inputs are copied.
//! Each nonempty input range must stay initialized, readable, and unmodified
//! within one live allocation. Outputs must stay aligned, writable, and exclusively accessible
//! for the call. Output ranges must not overlap any other argument range. Output
//! storage need not be initialized. Pointer validity is the caller's obligation;
//! null, length, and handle checks cannot establish it. Non-null handle, count,
//! and metadata outputs are cleared before other validation.
//! Concurrent teardown does not end another call's pointer lifetime.
//!
//! `timeout_ms` sets one network operation deadline in milliseconds, in
//! `1..=ARIAD_MAX_TIMEOUT_MS`. Transport phase limits can shorten it. Failed writes
//! can have accepted bytes; a timeout does not establish rollback or permit replay.
//! Unwinding panics return [`ARIAD_ERROR_INTERNAL`]. Destroy an affected engine;
//! normal operations reject a failed or poisoned engine. Aborts and invalid caller
//! memory are outside this panic boundary. No callbacks are registered.
//! Keep the library loaded until engines, calls, and deferred runtime cleanup end.
//! Version, capability, target, and status queries need no engine and do no I/O.

use std::collections::HashMap;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, OnceLock, TryLockError};
use std::thread::JoinHandle;
use std::time::Duration;

use ariad_core::{
    CapabilitySet, Credential, DatagramOutcome, DeliveryMode, Destination, EngineError,
    TargetClass, target_class, wire_compatible,
};
use ariad_engine::{
    AssociationControl, AssociationRecvHalf, AssociationSendHalf, CloseMode, CloseOutcome,
    DatagramRequirements, Deadline, EndpointPolicy, Engine, ReadOutcome, Session, StreamControl,
    StreamOptions, StreamReadHalf, StreamWriteHalf,
};
use tokio::runtime::{Builder, Handle};
use tokio::sync::{Notify, watch};

include!("abi.rs");

const MAX_ENGINES: usize = 32;
const MAX_HANDLES: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Engine,
    Session,
    Stream,
    Association,
}

#[derive(Clone, Copy)]
struct HandleRecord {
    engine_handle: AriadHandle,
    parent: AriadHandle,
    kind: HandleKind,
}

struct OwnedStream {
    session_handle: AriadHandle,
    read: Mutex<StreamReadHalf>,
    write: Mutex<StreamWriteHalf>,
    control: StreamControl,
}

impl Drop for OwnedStream {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

struct OwnedAssociation {
    session_handle: AriadHandle,
    send: Mutex<AssociationSendHalf>,
    recv: Mutex<AssociationRecvHalf>,
    control: AssociationControl,
    delivery_mode: DeliveryMode,
    max_payload: usize,
}

impl Drop for OwnedAssociation {
    fn drop(&mut self) {
        let _ = self.control.cancel();
    }
}

struct OwnedEngine {
    handle: AriadHandle,
    runtime: Option<Arc<RuntimeDriver>>,
    engine: Option<Arc<Engine>>,
    policy: Arc<EndpointPolicy>,
    interrupt: watch::Sender<Option<i32>>,
    sessions: HashMap<AriadHandle, Session>,
    streams: HashMap<AriadHandle, Arc<OwnedStream>>,
    associations: HashMap<AriadHandle, Arc<OwnedAssociation>>,
    shutdown_started: bool,
    destroyed: bool,
}

impl OwnedEngine {
    fn validate(&self) -> Result<(), i32> {
        if self.destroyed {
            return Err(ARIAD_ERROR_INVALID_HANDLE);
        }
        if *self.interrupt.borrow() == Some(ARIAD_ERROR_INTERNAL) {
            return Err(ARIAD_ERROR_INTERNAL);
        }
        Ok(())
    }
}

impl Drop for OwnedEngine {
    fn drop(&mut self) {
        self.streams.clear();
        self.associations.clear();
        for session in self.sessions.values() {
            session.cancel();
        }
        self.sessions.clear();
        let _ = self.engine.take();
        if let Some(runtime) = self.runtime.take() {
            runtime.request_stop();
        }
    }
}

#[derive(Default)]
struct DriverState {
    // Keep admission until runtime cleanup, including after forced destruction.
    admission: Option<EngineAdmission>,
    active_calls: usize,
    stop_requested: bool,
    finished: bool,
    failed: bool,
}

struct DriverControl {
    state: Mutex<DriverState>,
    activity: Notify,
    finished: Condvar,
}

impl DriverControl {
    async fn wait_for_stop(&self) {
        loop {
            let notified = self.activity.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                // The runtime must outlive all calling-thread futures.
                if state.stop_requested && state.active_calls == 0 {
                    return;
                }
            }
            notified.await;
        }
    }

    fn request_stop(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stop_requested = true;
        self.activity.notify_one();
    }

    fn wait_for_calls(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while state.active_calls != 0 {
            state = self
                .finished
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

struct RuntimeDriver {
    handle: Handle,
    control: Arc<DriverControl>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl RuntimeDriver {
    fn start(
        interrupt: watch::Sender<Option<i32>>,
        admission: EngineAdmission,
    ) -> Result<Arc<Self>, i32> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
        let handle = runtime.handle().clone();
        let control = Arc::new(DriverControl {
            state: Mutex::new(DriverState {
                admission: Some(admission),
                ..DriverState::default()
            }),
            activity: Notify::new(),
            finished: Condvar::new(),
        });
        let worker_control = Arc::clone(&control);
        let thread = std::thread::Builder::new()
            .name("ariad-ffi-driver".into())
            .spawn(move || {
                let running = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(worker_control.wait_for_stop());
                }));
                let mut failed = running.is_err();
                if let Err(payload) = running {
                    worker_control
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .failed = true;
                    signal_interrupt(&interrupt, ARIAD_ERROR_INTERNAL);
                    discard_panic(payload);
                    worker_control.wait_for_calls();
                }
                let shutdown = catch_unwind(AssertUnwindSafe(|| {
                    runtime.shutdown_timeout(Duration::ZERO);
                }));
                if let Err(payload) = shutdown {
                    failed = true;
                    signal_interrupt(&interrupt, ARIAD_ERROR_INTERNAL);
                    discard_panic(payload);
                }
                let mut state = worker_control
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                drop(state.admission.take());
                state.failed = failed;
                state.finished = true;
                worker_control.finished.notify_all();
            })
            .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
        Ok(Arc::new(Self {
            handle,
            control,
            thread: Mutex::new(Some(thread)),
        }))
    }

    fn acquire(&self) -> Result<(), i32> {
        let mut state = self
            .control
            .state
            .lock()
            .map_err(|_| ARIAD_ERROR_INTERNAL)?;
        if state.failed || state.finished {
            return Err(ARIAD_ERROR_INTERNAL);
        }
        if state.stop_requested {
            return Err(ARIAD_ERROR_INVALID_HANDLE);
        }
        state.active_calls = state
            .active_calls
            .checked_add(1)
            .ok_or(ARIAD_ERROR_RESOURCE_LIMIT)?;
        Ok(())
    }

    fn release(&self) {
        let mut state = self
            .control
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.active_calls -= 1;
        drop(state);
        self.control.activity.notify_one();
        self.control.finished.notify_all();
    }

    fn request_stop(&self) {
        self.control.request_stop();
    }

    fn wait_finished(&self, deadline: Deadline) -> Result<bool, i32> {
        let mut state = self
            .control
            .state
            .lock()
            .map_err(|_| ARIAD_ERROR_INTERNAL)?;
        while !state.finished {
            let Ok(remaining) = deadline.remaining() else {
                return Ok(false);
            };
            let (next, _) = self
                .control
                .finished
                .wait_timeout(state, remaining)
                .map_err(|_| ARIAD_ERROR_INTERNAL)?;
            state = next;
        }
        if state.failed {
            Err(ARIAD_ERROR_INTERNAL)
        } else {
            Ok(true)
        }
    }
}

impl Drop for RuntimeDriver {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(thread) = self
            .thread
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            && thread.thread().id() != std::thread::current().id()
            && thread.is_finished()
            && let Err(payload) = thread.join()
        {
            discard_panic(payload);
        }
    }
}

struct OperationLease {
    owner: Arc<Mutex<OwnedEngine>>,
    engine_handle: AriadHandle,
    runtime: Arc<RuntimeDriver>,
    interrupt: watch::Sender<Option<i32>>,
}

impl OperationLease {
    fn run<T>(&self, operation: impl Future<Output = Result<T, EngineError>>) -> Result<T, i32> {
        // Borrowed futures stay on this calling thread and are dropped before return.
        self.runtime.handle.block_on(async {
            tokio::select! {
                biased;
                error = wait_interrupt(self.interrupt.subscribe()) => Err(error),
                result = operation => result.map_err(error_status),
            }
        })
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        if std::thread::panicking() {
            signal_interrupt(&self.interrupt, ARIAD_ERROR_INTERNAL);
        }
        self.runtime.release();
    }
}

fn signal_interrupt(interrupt: &watch::Sender<Option<i32>>, error: i32) {
    // Shutdown cancellation must not hide an internal failure.
    interrupt.send_modify(|current| {
        if *current != Some(ARIAD_ERROR_INTERNAL) {
            *current = Some(error);
        }
    });
}

async fn wait_interrupt(mut interrupt: watch::Receiver<Option<i32>>) -> i32 {
    loop {
        if let Some(error) = *interrupt.borrow_and_update() {
            return error;
        }
        if interrupt.changed().await.is_err() {
            return ARIAD_ERROR_INTERNAL;
        }
    }
}

async fn wait_failure(mut interrupt: watch::Receiver<Option<i32>>) -> i32 {
    loop {
        let failed = *interrupt.borrow_and_update() == Some(ARIAD_ERROR_INTERNAL);
        if failed || interrupt.changed().await.is_err() {
            return ARIAD_ERROR_INTERNAL;
        }
    }
}

struct Registry {
    next_handle: AriadHandle,
    records: HashMap<AriadHandle, HandleRecord>,
    engines: HashMap<AriadHandle, Arc<Mutex<OwnedEngine>>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next_handle: 1,
            records: HashMap::new(),
            engines: HashMap::new(),
        }
    }

    fn allocate(&mut self, record: HandleRecord) -> Result<AriadHandle, i32> {
        if self.records.len() >= MAX_HANDLES {
            return Err(ARIAD_ERROR_RESOURCE_LIMIT);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
        let handle = self.next_handle;
        self.next_handle = handle.checked_add(1).ok_or(ARIAD_ERROR_RESOURCE_LIMIT)?;
        self.records.insert(handle, record);
        Ok(handle)
    }
}

struct EngineAdmission {
    count: Arc<Mutex<usize>>,
}

impl EngineAdmission {
    fn reserve() -> Result<Self, i32> {
        static COUNT: OnceLock<Arc<Mutex<usize>>> = OnceLock::new();
        Self::reserve_from(Arc::clone(COUNT.get_or_init(|| Arc::new(Mutex::new(0)))))
    }

    fn reserve_from(count: Arc<Mutex<usize>>) -> Result<Self, i32> {
        let mut reserved = count.lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
        if *reserved >= MAX_ENGINES {
            return Err(ARIAD_ERROR_RESOURCE_LIMIT);
        }
        *reserved += 1;
        drop(reserved);
        Ok(Self { count })
    }
}

impl Drop for EngineAdmission {
    fn drop(&mut self) {
        let mut reserved = self.count.lock().unwrap_or_else(|error| error.into_inner());
        *reserved -= 1;
    }
}

fn install_engine(mut owned: OwnedEngine) -> Result<AriadHandle, i32> {
    let mut registry = registry().lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
    registry
        .engines
        .try_reserve(1)
        .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
    let handle = registry.allocate(HandleRecord {
        engine_handle: 0,
        parent: 0,
        kind: HandleKind::Engine,
    })?;
    registry.records.insert(
        handle,
        HandleRecord {
            engine_handle: handle,
            parent: handle,
            kind: HandleKind::Engine,
        },
    );
    owned.handle = handle;
    registry.engines.insert(handle, Arc::new(Mutex::new(owned)));
    Ok(handle)
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::new()))
}

fn boundary(operation: impl FnOnce() -> Result<i32, i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(status)) | Ok(Err(status)) => status,
        Err(payload) => {
            discard_panic(payload);
            ARIAD_ERROR_INTERNAL
        }
    }
}

fn discard_panic(payload: Box<dyn std::any::Any + Send>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        // A second panic must not unwind across the C boundary.
        std::mem::forget(payload);
    }
}

fn error_status(error: EngineError) -> i32 {
    match error {
        EngineError::InvalidConfig => ARIAD_ERROR_INVALID_CONFIG,
        EngineError::UnsupportedCapability => ARIAD_ERROR_UNSUPPORTED,
        EngineError::EndpointResolutionFailed => ARIAD_ERROR_ENDPOINT_RESOLUTION,
        EngineError::PeerIdentityFailed => ARIAD_ERROR_PEER_IDENTITY,
        EngineError::AuthenticationDenied => ARIAD_ERROR_AUTHENTICATION,
        EngineError::AuthorizationUnavailable => ARIAD_ERROR_AUTHORIZATION_UNAVAILABLE,
        EngineError::EgressDenied => ARIAD_ERROR_EGRESS,
        EngineError::TargetResolutionFailed => ARIAD_ERROR_TARGET_RESOLUTION,
        EngineError::TargetConnectFailed => ARIAD_ERROR_TARGET_CONNECT,
        EngineError::TransportUnavailable => ARIAD_ERROR_TRANSPORT,
        EngineError::TransferStalled => ARIAD_ERROR_TRANSFER_STALLED,
        EngineError::ResourceLimitExceeded => ARIAD_ERROR_RESOURCE_LIMIT,
        EngineError::MessageTooLarge => ARIAD_ERROR_MESSAGE_TOO_LARGE,
        EngineError::Cancelled => ARIAD_ERROR_CANCELLED,
        EngineError::DeadlineExceeded => ARIAD_ERROR_DEADLINE,
        EngineError::RemoteReset => ARIAD_ERROR_REMOTE_RESET,
        EngineError::ProtocolViolation => ARIAD_ERROR_PROTOCOL,
        EngineError::TruncatedStream => ARIAD_ERROR_TRUNCATED,
        EngineError::NoReachableTrustedPath => ARIAD_ERROR_NO_TRUSTED_PATH,
        _ => ARIAD_ERROR_INTERNAL,
    }
}

fn deadline(timeout_ms: u32) -> Result<Deadline, i32> {
    if timeout_ms == 0 || timeout_ms > ARIAD_MAX_TIMEOUT_MS {
        return Err(ARIAD_ERROR_INVALID_ARGUMENT);
    }
    Deadline::after(Duration::from_millis(u64::from(timeout_ms))).map_err(error_status)
}

fn owner(handle: AriadHandle, kind: HandleKind) -> Result<Arc<Mutex<OwnedEngine>>, i32> {
    let registry = registry().lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
    let record = registry
        .records
        .get(&handle)
        .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
    if record.kind != kind {
        return Err(ARIAD_ERROR_INVALID_HANDLE);
    }
    registry
        .engines
        .get(&record.engine_handle)
        .cloned()
        .ok_or(ARIAD_ERROR_INVALID_HANDLE)
}

fn with_owner<T>(
    handle: AriadHandle,
    kind: HandleKind,
    operation: impl FnOnce(&mut OwnedEngine) -> Result<T, i32>,
) -> Result<T, i32> {
    let owner = owner(handle, kind)?;
    let mut engine = try_lock(&owner)?;
    engine.validate()?;
    operation(&mut engine)
}

fn start_operation<T>(
    handle: AriadHandle,
    kind: HandleKind,
    prepare: impl FnOnce(&mut OwnedEngine) -> Result<T, i32>,
) -> Result<(OperationLease, T), i32> {
    let owner = owner(handle, kind)?;
    let mut owned = try_lock(&owner)?;
    owned.validate()?;
    let runtime = Arc::clone(owned.runtime.as_ref().ok_or(ARIAD_ERROR_INVALID_HANDLE)?);
    runtime.acquire()?;
    let lease = OperationLease {
        owner: Arc::clone(&owner),
        engine_handle: owned.handle,
        runtime,
        interrupt: owned.interrupt.clone(),
    };
    let prepared = prepare(&mut owned)?;
    drop(owned);
    Ok((lease, prepared))
}

fn stream_operation(stream: AriadHandle) -> Result<(OperationLease, Arc<OwnedStream>), i32> {
    start_operation(stream, HandleKind::Stream, |owned| {
        owned
            .streams
            .get(&stream)
            .cloned()
            .ok_or(ARIAD_ERROR_INVALID_HANDLE)
    })
}

fn association_operation(
    association: AriadHandle,
) -> Result<(OperationLease, Arc<OwnedAssociation>), i32> {
    start_operation(association, HandleKind::Association, |owned| {
        owned
            .associations
            .get(&association)
            .cloned()
            .ok_or(ARIAD_ERROR_INVALID_HANDLE)
    })
}

fn try_lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, i32> {
    match mutex.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(ARIAD_ERROR_BUSY),
        Err(TryLockError::Poisoned(_)) => Err(ARIAD_ERROR_INTERNAL),
    }
}

fn publish_child<T>(
    lease: &OperationLease,
    parent: AriadHandle,
    kind: HandleKind,
    publish: impl FnOnce(&mut OwnedEngine, AriadHandle) -> Result<T, i32>,
) -> Result<T, i32> {
    // Publication and teardown must use the same owner lock.
    let mut owned = lease.owner.lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
    owned.validate()?;
    if owned.shutdown_started {
        return Err(ARIAD_ERROR_CANCELLED);
    }
    if kind != HandleKind::Session {
        let session = owned
            .sessions
            .get(&parent)
            .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
        if session.phase() != ariad_core::SessionPhase::Ready {
            return Err(ARIAD_ERROR_CANCELLED);
        }
    }
    match kind {
        HandleKind::Session => owned.sessions.try_reserve(1),
        HandleKind::Stream => owned.streams.try_reserve(1),
        HandleKind::Association => owned.associations.try_reserve(1),
        HandleKind::Engine => return Err(ARIAD_ERROR_INTERNAL),
    }
    .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
    let handle = insert_child(lease.engine_handle, parent, kind)?;
    match publish(&mut owned, handle) {
        Ok(value) => Ok(value),
        Err(error) => {
            remove_handle(handle)?;
            Err(error)
        }
    }
}

fn insert_child(
    engine_handle: AriadHandle,
    parent: AriadHandle,
    kind: HandleKind,
) -> Result<AriadHandle, i32> {
    let mut registry = registry().lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
    if !registry.engines.contains_key(&engine_handle) || !registry.records.contains_key(&parent) {
        return Err(ARIAD_ERROR_INVALID_HANDLE);
    }
    registry.allocate(HandleRecord {
        engine_handle,
        parent,
        kind,
    })
}

fn remove_handle(handle: AriadHandle) -> Result<(), i32> {
    registry()
        .lock()
        .map_err(|_| ARIAD_ERROR_INTERNAL)?
        .records
        .remove(&handle);
    Ok(())
}

fn remove_flow_handles(parent: AriadHandle) -> Result<(), i32> {
    registry()
        .lock()
        .map_err(|_| ARIAD_ERROR_INTERNAL)?
        .records
        .retain(|_, record| {
            record.parent != parent
                || !matches!(record.kind, HandleKind::Stream | HandleKind::Association)
        });
    Ok(())
}

/// # Safety
/// If non-null, `output` must provide exclusive, aligned write access to one `T`
/// for this call. The storage need not be initialized.
unsafe fn initialize_output<T>(output: *mut T, initial: T) -> Result<(), i32> {
    if output.is_null() {
        return Err(ARIAD_ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: output is non-null. The caller grants aligned, exclusive write access.
    unsafe { output.write(initial) };
    Ok(())
}

/// # Safety
/// For accepted lengths, `pointer` must refer to `length` initialized, readable
/// bytes in one live allocation. The range must stay unmodified for the call,
/// and `length` must fit `isize::MAX`. The returned vector owns a copy.
unsafe fn copy_input(pointer: *const u8, length: usize, maximum: usize) -> Result<Vec<u8>, i32> {
    // SAFETY: The caller keeps the accepted input range valid and unchanged for this copy.
    let input = unsafe { borrow_input(pointer, length, maximum) }?;
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(length)
        .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
    copied.extend_from_slice(input);
    Ok(copied)
}

/// # Safety
/// For accepted lengths, `pointer` must refer to `length` initialized, readable
/// bytes in one live allocation for `'a`. The range must stay unmodified for
/// that lifetime, and `length` must fit `isize::MAX`.
unsafe fn borrow_input<'a>(
    pointer: *const u8,
    length: usize,
    maximum: usize,
) -> Result<&'a [u8], i32> {
    if length == 0 || pointer.is_null() {
        return Err(ARIAD_ERROR_INVALID_ARGUMENT);
    }
    if length > maximum {
        return Err(ARIAD_ERROR_MESSAGE_TOO_LARGE);
    }
    // SAFETY: The caller guarantees the accepted range and its lifetime.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

/// # Safety
/// The accepted input range must meet the allocation, initialization, lifetime,
/// and no-mutation requirements of `copy_input`.
unsafe fn copy_text(pointer: *const u8, length: usize) -> Result<String, i32> {
    // SAFETY: The caller supplies the input range required by copy_input.
    let copied = unsafe { copy_input(pointer, length, ARIAD_MAX_TEXT) }?;
    String::from_utf8(copied).map_err(|_| ARIAD_ERROR_INVALID_ARGUMENT)
}

/// Returns the C ABI version, independent of the protocol and H2 binding versions.
/// Compatible additions keep this version. Dynamic loaders must also check that
/// each entry point they use is present.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_abi_version() -> u32 {
    ARIAD_ABI_VERSION
}

/// Returns the constant name for an operation status as a borrowed ASCII C string.
///
/// Unknown values return `ARIAD_STATUS_UNKNOWN`. The pointer is always non-null
/// and stays valid until the library is unloaded. Do not modify or free it.
/// This query needs no engine, allocates no memory, and is safe across threads.
/// Feature and target query results are classifications, not operation statuses.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_status_name(status: i32) -> *const std::ffi::c_char {
    abi_status_name(status)
}

/// Creates an H2 engine for one fixed address, TLS identity, and DER trust root.
///
/// Endpoint and identity are UTF-8 strings of 1..=[`ARIAD_MAX_TEXT`] bytes, without a trailing
/// NUL. Endpoint must parse as an IP socket address. Identity must meet ASCII
/// hostname syntax and the 253-byte limit, independently of the address.
/// Trust material is one nonempty DER certificate of at most [`ARIAD_MAX_TRUST_ROOT_DER_BYTES`] bytes.
/// Malformed or larger certificates return
/// `ARIAD_ERROR_INVALID_CONFIG`. The earlier copy limit rejects inputs above
/// [`ARIAD_MAX_COPY`] with `ARIAD_ERROR_MESSAGE_TOO_LARGE`, and empty or null
/// DER input with `ARIAD_ERROR_INVALID_ARGUMENT`.
///
/// Success writes a new handle to `out_engine`. Creation performs no network I/O.
/// Later connections use TLS 1.3 with ALPN h2. Default sockets have no host
/// routing-loop protection; hosts needing that hook must use Rust `HostServices`.
///
/// # Safety
/// Input ranges must meet the crate-level pointer requirements for their stated
/// lengths. `out_engine` must provide exclusive, aligned write access to one
/// `AriadHandle` for the complete call and must not overlap any input range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_engine_create(
    endpoint: *const u8,
    endpoint_len: usize,
    identity: *const u8,
    identity_len: usize,
    trust_root_der: *const u8,
    trust_root_len: usize,
    out_engine: *mut AriadHandle,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_engine.
        unsafe { initialize_output(out_engine, 0) }?;
        let admission = EngineAdmission::reserve()?;
        // SAFETY: The caller supplies the endpoint input range for this call.
        let address = unsafe { copy_text(endpoint, endpoint_len) }?
            .parse()
            .map_err(|_| ARIAD_ERROR_INVALID_ARGUMENT)?;
        // SAFETY: The caller supplies the identity input range for this call.
        let identity = unsafe { copy_text(identity, identity_len) }?;
        // SAFETY: The caller supplies the DER input range for this call.
        let trust_root = unsafe { copy_input(trust_root_der, trust_root_len, ARIAD_MAX_COPY) }?;
        let (engine, policy) =
            ariad_embed::pinned_h2_engine(address, identity, trust_root).map_err(error_status)?;
        let (interrupt, _) = watch::channel(None);
        let runtime = RuntimeDriver::start(interrupt.clone(), admission)?;
        let owned = OwnedEngine {
            handle: 0,
            runtime: Some(runtime),
            engine: Some(Arc::new(engine)),
            policy: Arc::new(policy),
            interrupt,
            sessions: HashMap::new(),
            streams: HashMap::new(),
            associations: HashMap::new(),
            shutdown_started: false,
            destroyed: false,
        };
        let handle = install_engine(owned)?;
        // SAFETY: The caller keeps out_engine exclusively writable and aligned until return.
        unsafe { out_engine.write(handle) };
        Ok(ARIAD_OK)
    })
}

/// Connects the engine's fixed endpoint and stores a copied credential.
///
/// The credential contains [`Credential::BYTE_LEN`] bytes.
/// Success writes a session handle after TLS identity and H2 setup succeed.
/// Authentication and destination authorization occur on each subsequent open.
/// A shut-down engine rejects this call with `ARIAD_ERROR_CANCELLED`.
///
/// # Safety
/// For `credential_len == Credential::BYTE_LEN`, the range must meet the crate-level
/// input requirements. `out_session` must provide exclusive, aligned write
/// access to one `AriadHandle` for the call and must not overlap the credential.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_engine_connect(
    engine: AriadHandle,
    credential: *const u8,
    credential_len: usize,
    timeout_ms: u32,
    out_session: *mut AriadHandle,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_session.
        unsafe { initialize_output(out_session, 0) }?;
        if credential_len != Credential::BYTE_LEN {
            return Err(ARIAD_ERROR_INVALID_ARGUMENT);
        }
        let deadline = deadline(timeout_ms)?;
        let mut bytes = [0u8; Credential::BYTE_LEN];
        if credential.is_null() {
            return Err(ARIAD_ERROR_INVALID_ARGUMENT);
        }
        // SAFETY: The caller supplies Credential::BYTE_LEN initialized, readable bytes.
        // The local array is writable and disjoint. Both pointers have alignment 1.
        unsafe { std::ptr::copy_nonoverlapping(credential, bytes.as_mut_ptr(), bytes.len()) };
        let credential = Credential::from_bytes(bytes);
        bytes.fill(0);
        let (lease, (engine_api, policy)) = start_operation(engine, HandleKind::Engine, |owned| {
            if owned.shutdown_started {
                return Err(ARIAD_ERROR_CANCELLED);
            }
            owned
                .sessions
                .try_reserve(1)
                .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
            Ok((
                Arc::clone(owned.engine.as_ref().ok_or(ARIAD_ERROR_INVALID_HANDLE)?),
                Arc::clone(&owned.policy),
            ))
        })?;
        let session = lease.run(engine_api.connect(&policy, credential, deadline))?;
        publish_child(&lease, engine, HandleKind::Session, |owned, handle| {
            owned.sessions.insert(handle, session);
            // SAFETY: The caller keeps out_session exclusively writable and aligned until return.
            unsafe { out_session.write(handle) };
            Ok(ARIAD_OK)
        })
    })
}

/// Opens a TCP CONNECT stream with the session credential and writes its handle to `out_stream`.
///
/// Destination is ASCII `host:port` or `[ipv6]:port`, without a NUL, in 1..=[`ARIAD_MAX_TEXT`]
/// bytes. Domains are limited to 253 bytes and ports to 1..=65535; full syntax
/// follows [`Destination::parse`]. Success requires an accepted CONNECT response.
/// Opening a stream does not send application payload.
///
/// # Safety
/// The destination range must meet the crate-level input requirements for
/// `destination_len` bytes. `out_stream` must provide exclusive, aligned write
/// access to one `AriadHandle` for the call and must not overlap that input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_session_open_stream(
    session: AriadHandle,
    destination: *const u8,
    destination_len: usize,
    timeout_ms: u32,
    out_stream: *mut AriadHandle,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_stream.
        unsafe { initialize_output(out_stream, 0) }?;
        let deadline = deadline(timeout_ms)?;
        // SAFETY: The caller supplies the destination input range for this call.
        let destination = Destination::parse(&unsafe { copy_text(destination, destination_len) }?)
            .map_err(error_status)?;
        let (lease, session_api) = start_operation(session, HandleKind::Session, |owned| {
            if owned.shutdown_started {
                return Err(ARIAD_ERROR_CANCELLED);
            }
            owned
                .streams
                .try_reserve(1)
                .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
            owned
                .sessions
                .get(&session)
                .cloned()
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)
        })?;
        let stream =
            lease.run(session_api.open_stream(&destination, StreamOptions::default(), deadline))?;
        let control = stream.control();
        let (read, write) = stream.into_split();
        let entry = Arc::new(OwnedStream {
            session_handle: session,
            read: Mutex::new(read),
            write: Mutex::new(write),
            control,
        });
        publish_child(&lease, session, HandleKind::Stream, |owned, handle| {
            owned.streams.insert(handle, entry);
            // SAFETY: The caller keeps out_stream exclusively writable and aligned until return.
            unsafe { out_stream.write(handle) };
            Ok(ARIAD_OK)
        })
    })
}

/// Borrows 1..=ARIAD_MAX_COPY input bytes and submits one stream prefix.
///
/// `ARIAD_OK` reports the accepted prefix in `out_written`; advance by that
/// count. Acceptance does not confirm remote delivery. Errors leave the count
/// zero but can retain transport effects, so the payload must not be replayed.
///
/// # Safety
/// The input range must meet the crate-level requirements for `input_len` bytes.
/// `out_written` must provide exclusive, aligned write access to one `usize`
/// for the call and must not overlap the input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_stream_write(
    stream: AriadHandle,
    input: *const u8,
    input_len: usize,
    timeout_ms: u32,
    out_written: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_written.
        unsafe { initialize_output(out_written, 0) }?;
        let deadline = deadline(timeout_ms)?;
        let (lease, entry) = stream_operation(stream)?;
        let mut writer = try_lock(&entry.write)?;
        // SAFETY: The caller keeps the range valid and unchanged until return.
        // The write future is polled and dropped on this calling thread.
        let input = unsafe { borrow_input(input, input_len, ARIAD_MAX_COPY) }?;
        let written = lease.run(writer.write(input, deadline))?;
        if written == 0 || written > input.len() {
            return Err(ARIAD_ERROR_PROTOCOL);
        }
        // SAFETY: The caller keeps out_written exclusively writable and aligned until return.
        unsafe { out_written.write(written) };
        Ok(ARIAD_OK)
    })
}

/// Copies the next stream prefix into a buffer of 1..=ARIAD_MAX_COPY bytes.
///
/// `ARIAD_OK` reports a nonzero count in `out_read`. Clean EOF returns
/// `ARIAD_EOF` with count zero. Reset, cancellation, and truncation are errors.
/// Errors and EOF leave the output buffer unchanged.
///
/// # Safety
/// `output` must provide exclusive write access to `output_capacity` bytes for
/// the call. `out_read` must provide exclusive, aligned write access to one
/// `usize`. Both ranges must meet the crate-level requirements and be disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_stream_read(
    stream: AriadHandle,
    output: *mut u8,
    output_capacity: usize,
    timeout_ms: u32,
    out_read: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_read.
        unsafe { initialize_output(out_read, 0) }?;
        if output.is_null() || output_capacity == 0 {
            return Err(ARIAD_ERROR_INVALID_ARGUMENT);
        }
        if output_capacity > ARIAD_MAX_COPY {
            return Err(ARIAD_ERROR_MESSAGE_TOO_LARGE);
        }
        let deadline = deadline(timeout_ms)?;
        let (lease, entry) = stream_operation(stream)?;
        let mut reader = try_lock(&entry.read)?;
        let mut read_buffer = Vec::new();
        read_buffer
            .try_reserve_exact(output_capacity)
            .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)?;
        read_buffer.resize(output_capacity, 0);
        match lease.run(reader.read(&mut read_buffer, deadline))? {
            ReadOutcome::Data(count) if count > 0 && count <= output_capacity => {
                // SAFETY: count <= output_capacity == read_buffer.len(). The source
                // is initialized; the caller grants disjoint writable output storage.
                unsafe { std::ptr::copy_nonoverlapping(read_buffer.as_ptr(), output, count) };
                // SAFETY: The caller keeps out_read exclusively writable and aligned until return.
                unsafe { out_read.write(count) };
                Ok(ARIAD_OK)
            }
            ReadOutcome::Eof => Ok(ARIAD_EOF),
            ReadOutcome::Reset => Err(ARIAD_ERROR_REMOTE_RESET),
            ReadOutcome::Cancelled => Err(ARIAD_ERROR_CANCELLED),
            ReadOutcome::Truncated => Err(ARIAD_ERROR_TRUNCATED),
            ReadOutcome::Data(_) | ReadOutcome::Waiting => Err(ARIAD_ERROR_PROTOCOL),
        }
    })
}

/// Ends stream writes while retaining the handle and permitting further reads.
///
/// `ARIAD_OK` means the local end signal was accepted, not that the peer reached EOF.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_stream_end_write(stream: AriadHandle, timeout_ms: u32) -> i32 {
    boundary(|| {
        let deadline = deadline(timeout_ms)?;
        let (lease, entry) = stream_operation(stream)?;
        let mut writer = try_lock(&entry.write)?;
        lease.run(writer.end_write(deadline))?;
        Ok(ARIAD_OK)
    })
}

/// Requests stream cancellation. The handle remains valid until destroy.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_stream_cancel(stream: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, entry) = stream_operation(stream)?;
        entry.control.cancel();
        Ok(ARIAD_OK)
    })
}

/// Resets the stream. On success, further reads report `ARIAD_ERROR_REMOTE_RESET`.
/// The handle remains valid until destroy.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_stream_reset(stream: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, entry) = stream_operation(stream)?;
        entry.control.reset().map_err(error_status)?;
        Ok(ARIAD_OK)
    })
}

/// Cancels and releases the stream, invalidating its handle.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_stream_destroy(stream: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, removed) = start_operation(stream, HandleKind::Stream, |owned| {
            let removed = owned
                .streams
                .remove(&stream)
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
            remove_handle(stream)?;
            Ok(removed)
        })?;
        removed.control.cancel();
        Ok(ARIAD_OK)
    })
}

/// Opens a CONNECT-UDP association and writes its handle to `out_association`.
///
/// Destination uses the same text format as [`ariad_session_open_stream`].
/// `require_unreliable` is 0 or 1. H2 rejects 1 before reading the destination or
/// sending a request. The association getters report its negotiated delivery
/// mode and current maximum payload; feature metadata does not establish either.
///
/// # Safety
/// The destination range must meet the crate-level input requirements for
/// `destination_len` bytes. `out_association` must provide exclusive, aligned
/// write access to one `AriadHandle` for the call and must not overlap the input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_session_open_datagram(
    session: AriadHandle,
    destination: *const u8,
    destination_len: usize,
    require_unreliable: u32,
    timeout_ms: u32,
    out_association: *mut AriadHandle,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_association.
        unsafe { initialize_output(out_association, 0) }?;
        if require_unreliable > 1 {
            return Err(ARIAD_ERROR_INVALID_ARGUMENT);
        }
        let deadline = deadline(timeout_ms)?;
        let (lease, session_api) = start_operation(session, HandleKind::Session, |owned| {
            if owned.shutdown_started {
                return Err(ARIAD_ERROR_CANCELLED);
            }
            let session_api = owned
                .sessions
                .get(&session)
                .cloned()
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
            if require_unreliable != 0
                && session_api.capabilities().binding == ariad_core::BindingId::H2
            {
                return Err(ARIAD_ERROR_UNSUPPORTED);
            }
            Ok(session_api)
        })?;
        // SAFETY: The caller supplies the destination input range for this call.
        let destination = Destination::parse(&unsafe { copy_text(destination, destination_len) }?)
            .map_err(error_status)?;
        with_owner(session, HandleKind::Session, |owned| {
            owned
                .associations
                .try_reserve(1)
                .map_err(|_| ARIAD_ERROR_RESOURCE_LIMIT)
        })?;
        let association = lease.run(session_api.open_datagram_association(
            &destination,
            DatagramRequirements {
                require_unreliable: require_unreliable != 0,
            },
            deadline,
        ))?;
        let delivery_mode = association.delivery_mode();
        let max_payload = association.max_payload();
        let control = association.control();
        let (send, recv) = association.into_split();
        let entry = Arc::new(OwnedAssociation {
            session_handle: session,
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            control,
            delivery_mode,
            max_payload,
        });
        publish_child(&lease, session, HandleKind::Association, |owned, handle| {
            owned.associations.insert(handle, entry);
            // SAFETY: The caller keeps out_association exclusively writable and aligned until return.
            unsafe { out_association.write(handle) };
            Ok(ARIAD_OK)
        })
    })
}

/// Writes `ARIAD_DELIVERY_RELIABLE` or `ARIAD_DELIVERY_UNRELIABLE` for this association.
/// The getter remains available after association close, until handle destruction.
///
/// # Safety
/// `out_mode` must provide exclusive, aligned write access to one `u32` for the
/// call, as required by the crate-level pointer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_association_delivery_mode(
    association: AriadHandle,
    out_mode: *mut u32,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_mode.
        unsafe { initialize_output(out_mode, 0) }?;
        let (_lease, entry) = association_operation(association)?;
        let mode = match entry.delivery_mode {
            DeliveryMode::ReliableEncapsulation => ARIAD_DELIVERY_RELIABLE,
            DeliveryMode::UnreliableNative => ARIAD_DELIVERY_UNRELIABLE,
            DeliveryMode::Unsupported => return Err(ARIAD_ERROR_UNSUPPORTED),
        };
        // SAFETY: The caller keeps out_mode exclusively writable and aligned until return.
        unsafe { out_mode.write(mode) };
        Ok(ARIAD_OK)
    })
}

/// Writes the association's maximum whole-message size in bytes, capped by [`ARIAD_MAX_COPY`].
/// The getter remains available after association close, until handle destruction.
///
/// # Safety
/// `out_max_payload` must provide exclusive, aligned write access to one `usize`
/// for the call, as required by the crate-level pointer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_association_max_payload(
    association: AriadHandle,
    out_max_payload: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_max_payload.
        unsafe { initialize_output(out_max_payload, 0) }?;
        let (_lease, entry) = association_operation(association)?;
        // SAFETY: The caller keeps out_max_payload exclusively writable and aligned until return.
        unsafe { out_max_payload.write(entry.max_payload.min(ARIAD_MAX_COPY)) };
        Ok(ARIAD_OK)
    })
}

/// Sends one complete datagram. `ARIAD_DROPPED` reports a local admission drop.
///
/// Empty datagrams are accepted with a null input. Nonempty messages must fit
/// [`ariad_association_max_payload`]. `ARIAD_OK` means locally accepted, not
/// remotely delivered. Failed sends can have effects and must not be replayed.
///
/// # Safety
/// For a nonzero length, the input range must meet the crate-level requirements
/// for `input_len` bytes. A null input is permitted for an empty datagram.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_association_send(
    association: AriadHandle,
    input: *const u8,
    input_len: usize,
    timeout_ms: u32,
) -> i32 {
    boundary(|| {
        let deadline = deadline(timeout_ms)?;
        let (lease, entry) = association_operation(association)?;
        let mut sender = try_lock(&entry.send)?;
        let input_copy = if input_len == 0 {
            Vec::new()
        } else {
            // SAFETY: The caller supplies the complete input range for this call.
            unsafe { copy_input(input, input_len, entry.max_payload.min(ARIAD_MAX_COPY)) }?
        };
        match lease.run(sender.send(&input_copy, deadline))? {
            DatagramOutcome::Queued => Ok(ARIAD_OK),
            DatagramOutcome::Dropped => Ok(ARIAD_DROPPED),
        }
    })
}

/// # Safety
/// For a fitting nonempty message, `output` must provide exclusive write access
/// to `message.len()` bytes in live storage, disjoint from `message` and
/// `out_read`. `out_read` must provide exclusive, aligned write access to one
/// `usize`. Both ranges must stay valid for the call. An error leaves them unchanged.
unsafe fn copy_datagram_output(
    message: &[u8],
    output: *mut u8,
    capacity: usize,
    out_read: *mut usize,
) -> Result<i32, i32> {
    if message.len() > capacity {
        return Err(ARIAD_ERROR_MESSAGE_TOO_LARGE);
    }
    if !message.is_empty() {
        // SAFETY: message.len() <= capacity. The caller grants writable storage
        // disjoint from the initialized message and count; byte alignment is 1.
        unsafe { std::ptr::copy_nonoverlapping(message.as_ptr(), output, message.len()) };
    }
    // SAFETY: The caller grants aligned, exclusive write access to out_read.
    unsafe { out_read.write(message.len()) };
    Ok(ARIAD_OK)
}

/// Consumes one message. An oversized message is discarded without a prefix.
///
/// Capacity is 0..=ARIAD_MAX_COPY. `ARIAD_OK` copies the complete message and
/// reports its size in `out_read`; count zero is an empty datagram, not EOF.
/// A message exceeding capacity returns `ARIAD_ERROR_MESSAGE_TOO_LARGE` with
/// count zero and unchanged output. A capacity above the ABI limit is rejected
/// before receiving a message.
///
/// # Safety
/// `output` must provide exclusive write access to `output_capacity` bytes for
/// the call; it may be null when capacity is zero. `out_read` must provide
/// exclusive, aligned write access to one `usize`. The ranges must meet the
/// crate-level pointer requirements and must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ariad_association_recv(
    association: AriadHandle,
    output: *mut u8,
    output_capacity: usize,
    timeout_ms: u32,
    out_read: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller grants aligned, exclusive write access to out_read.
        unsafe { initialize_output(out_read, 0) }?;
        if output_capacity > ARIAD_MAX_COPY {
            return Err(ARIAD_ERROR_MESSAGE_TOO_LARGE);
        }
        if output_capacity != 0 && output.is_null() {
            return Err(ARIAD_ERROR_INVALID_ARGUMENT);
        }
        let deadline = deadline(timeout_ms)?;
        let (lease, entry) = association_operation(association)?;
        let mut receiver = try_lock(&entry.recv)?;
        let message = lease.run(receiver.recv(deadline))?;
        let bytes: &[u8] = message.as_ref();
        // SAFETY: The caller supplies disjoint output and count storage for
        // the full call. The owned message stays initialized through the copy.
        unsafe { copy_datagram_output(bytes, output, output_capacity, out_read) }
    })
}

/// Closes the association and discards buffered messages. Its handle and getters remain valid.
/// H2 closure resets the transport; send and receive calls cannot continue afterward.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_association_close(association: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, entry) = association_operation(association)?;
        entry.control.close().map_err(error_status)?;
        Ok(ARIAD_OK)
    })
}

/// Cancels and releases the association, invalidating its handle.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_association_destroy(association: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, removed) = start_operation(association, HandleKind::Association, |owned| {
            let removed = owned
                .associations
                .remove(&association)
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
            remove_handle(association)?;
            Ok(removed)
        })?;
        let _ = removed.control.cancel();
        Ok(ARIAD_OK)
    })
}

/// Closes a session using `ARIAD_CLOSE_GRACEFUL` or `ARIAD_CLOSE_IMMEDIATE`.
///
/// Once the close operation returns, the session is cancelled and its stream
/// and association handles are invalidated, including on transport errors.
/// `ARIAD_OK` reports graceful closure; `ARIAD_FORCED` reports forced cleanup
/// or an expired closure deadline.
/// The session handle remains valid until destroy. Argument and lock failures
/// occur before closure; a caught panic can interrupt cleanup.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_session_close(session: AriadHandle, mode: u32, timeout_ms: u32) -> i32 {
    boundary(|| {
        let deadline = deadline(timeout_ms)?;
        let mode = match mode {
            ARIAD_CLOSE_GRACEFUL => CloseMode::Graceful,
            ARIAD_CLOSE_IMMEDIATE => CloseMode::Immediate,
            _ => return Err(ARIAD_ERROR_INVALID_ARGUMENT),
        };
        let (lease, session_api) = start_operation(session, HandleKind::Session, |owned| {
            owned
                .sessions
                .get(&session)
                .cloned()
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)
        })?;
        let result = lease.run(deadline.run(session_api.close(mode, deadline)));
        session_api.cancel();
        let mut owned = lease.owner.lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
        remove_session_flows(&mut owned, session)?;
        match result {
            Ok(CloseOutcome::Graceful) => Ok(ARIAD_OK),
            Ok(CloseOutcome::Forced) | Err(ARIAD_ERROR_DEADLINE) => Ok(ARIAD_FORCED),
            Err(error) => Err(error),
        }
    })
}

/// Cancels and releases a session and all its stream and association handles.
/// This call performs no graceful network drain.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_session_destroy(session: AriadHandle) -> i32 {
    boundary(|| {
        let (_lease, removed) = start_operation(session, HandleKind::Session, |owned| {
            let removed = owned
                .sessions
                .remove(&session)
                .ok_or(ARIAD_ERROR_INVALID_HANDLE)?;
            remove_session_flows(owned, session)?;
            remove_handle(session)?;
            Ok(removed)
        })?;
        removed.cancel();
        Ok(ARIAD_OK)
    })
}

fn remove_session_flows(owned: &mut OwnedEngine, session: AriadHandle) -> Result<(), i32> {
    owned
        .streams
        .retain(|_, stream| stream.session_handle != session);
    owned
        .associations
        .retain(|_, association| association.session_handle != session);
    remove_flow_handles(session)
}

struct ShutdownChildren {
    sessions: HashMap<AriadHandle, Session>,
    streams: HashMap<AriadHandle, Arc<OwnedStream>>,
    associations: HashMap<AriadHandle, Arc<OwnedAssociation>>,
}

impl ShutdownChildren {
    fn take(owned: &mut OwnedEngine) -> Self {
        Self {
            sessions: std::mem::take(&mut owned.sessions),
            streams: std::mem::take(&mut owned.streams),
            associations: std::mem::take(&mut owned.associations),
        }
    }

    fn cancel_flows(&mut self) {
        for stream in self.streams.values() {
            stream.control.cancel();
        }
        for association in self.associations.values() {
            let _ = association.control.cancel();
        }
        self.streams.clear();
        self.associations.clear();
    }
}

impl Drop for ShutdownChildren {
    fn drop(&mut self) {
        self.cancel_flows();
        for session in self.sessions.values() {
            session.cancel();
        }
    }
}

fn begin_shutdown(owned: &mut OwnedEngine) -> Result<(Arc<Engine>, ShutdownChildren), i32> {
    owned.shutdown_started = true;
    signal_interrupt(&owned.interrupt, ARIAD_ERROR_CANCELLED);
    let engine_api = Arc::clone(owned.engine.as_ref().ok_or(ARIAD_ERROR_INVALID_HANDLE)?);
    let children = ShutdownChildren::take(owned);
    registry()
        .lock()
        .map_err(|_| ARIAD_ERROR_INTERNAL)?
        .records
        .retain(|handle, record| record.engine_handle != owned.handle || *handle == owned.handle);
    Ok((engine_api, children))
}

fn shutdown_result(
    runtime: &RuntimeDriver,
    engine: &Engine,
    interrupt: &watch::Sender<Option<i32>>,
    deadline: Deadline,
) -> Result<i32, i32> {
    let report = match runtime.handle.block_on(async {
        tokio::select! {
            biased;
            error = wait_failure(interrupt.subscribe()) => Err(error),
            result = deadline.run(async { Ok(engine.shutdown_with_deadline(deadline).await) }) => {
                result.map_err(error_status)
            },
        }
    }) {
        Ok(report) => report,
        Err(ARIAD_ERROR_DEADLINE) => return Ok(ARIAD_FORCED),
        Err(error) => return Err(error),
    };
    if report.failed_sessions != 0 {
        Err(ARIAD_ERROR_TRANSPORT)
    } else if report.forced_sessions != 0 || report.pending_connects != 0 {
        Ok(ARIAD_FORCED)
    } else {
        Ok(ARIAD_OK)
    }
}

/// Stops new opens and shuts down sessions under one deadline.
///
/// Shutdown invalidates child handles before network waits, including when it
/// returns `ARIAD_ERROR_TRANSPORT`. `ARIAD_FORCED` reports forced sessions,
/// pending connects, or an expired shutdown deadline. The engine handle and
/// runtime remain until destroy. Argument and lock failures occur before
/// shutdown; a caught panic can interrupt cleanup.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_engine_shutdown(engine: AriadHandle, timeout_ms: u32) -> i32 {
    boundary(|| {
        let deadline = deadline(timeout_ms)?;
        let (lease, (engine_api, mut children)) =
            start_operation(engine, HandleKind::Engine, begin_shutdown)?;
        children.cancel_flows();
        shutdown_result(&lease.runtime, &engine_api, &lease.interrupt, deadline)
    })
}

/// Invalidates the engine and child handles, then stops its runtime.
///
/// Handles are invalidated before network waits, including on shutdown
/// `ARIAD_ERROR_TRANSPORT`. Cancellation wakes admitted calls without taking
/// their direction locks. `ARIAD_FORCED` can report an expired wait for those
/// calls; runtime cleanup continues after they return and retains admission.
/// A failed or poisoned owner is torn down with `ARIAD_ERROR_INTERNAL`.
/// `ARIAD_ERROR_BUSY`, argument errors, and invalid
/// handles leave ownership unchanged. Other internal errors or caught panics
/// can occur before teardown or interrupt it; they do not establish handle reuse.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_engine_destroy(engine: AriadHandle, timeout_ms: u32) -> i32 {
    boundary(|| {
        let deadline = deadline(timeout_ms)?;
        let owner = owner(engine, HandleKind::Engine)?;
        let (runtime, engine_api, mut children, poisoned, teardown_lease) = {
            let (mut owned, lock_poisoned) = match owner.try_lock() {
                Ok(owned) => (owned, false),
                Err(TryLockError::WouldBlock) => return Err(ARIAD_ERROR_BUSY),
                // An unwind may leave partial state. Recover the lock only to
                // invalidate handles and release resources; normal calls reject it.
                Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
            };
            if owned.destroyed {
                return Err(ARIAD_ERROR_INVALID_HANDLE);
            }
            let mut poisoned =
                lock_poisoned || *owned.interrupt.borrow() == Some(ARIAD_ERROR_INTERNAL);
            let teardown_lease = if let Some(runtime) = owned.runtime.as_ref() {
                match runtime.acquire() {
                    Ok(()) => Some(OperationLease {
                        owner: Arc::clone(&owner),
                        engine_handle: owned.handle,
                        runtime: Arc::clone(runtime),
                        interrupt: owned.interrupt.clone(),
                    }),
                    Err(_) => {
                        poisoned = true;
                        None
                    }
                }
            } else {
                None
            };
            owned.shutdown_started = true;
            owned.destroyed = true;
            signal_interrupt(
                &owned.interrupt,
                if poisoned {
                    ARIAD_ERROR_INTERNAL
                } else {
                    ARIAD_ERROR_CANCELLED
                },
            );
            let children = ShutdownChildren::take(&mut owned);
            let runtime = owned.runtime.take();
            let engine_api = owned.engine.take();
            let mut registry = registry().lock().map_err(|_| ARIAD_ERROR_INTERNAL)?;
            registry
                .records
                .retain(|_, record| record.engine_handle != engine);
            registry.engines.remove(&engine);
            (runtime, engine_api, children, poisoned, teardown_lease)
        };
        children.cancel_flows();
        let result = if poisoned {
            Err(ARIAD_ERROR_INTERNAL)
        } else if let (Some(runtime), Some(engine_api), Some(lease)) =
            (&runtime, &engine_api, &teardown_lease)
        {
            shutdown_result(runtime, engine_api, &lease.interrupt, deadline)
        } else {
            Err(ARIAD_ERROR_INTERNAL)
        };
        drop(children);
        drop(engine_api);
        // This call cannot stay counted while waiting for the driver to stop.
        drop(teardown_lease);
        let Some(runtime) = runtime else {
            return Err(ARIAD_ERROR_INTERNAL);
        };
        runtime.request_stop();
        let finished = runtime.wait_finished(deadline);
        match (result, finished) {
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(status), Ok(true)) => Ok(status),
            (Ok(_), Ok(false)) => Ok(ARIAD_FORCED),
        }
    })
}

/// Returns the experimental protocol version supported by this library.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_protocol_version() -> u16 {
    ariad_core::PROTOCOL_VERSION.0
}

/// Returns the experimental H2 binding version supported by this library.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_h2_binding_version() -> u16 {
    ariad_core::H2_BINDING_VERSION.0
}

/// Returns local H2 ABI feature metadata: 1 for supported, 0 for unsupported,
/// and -1 for an unknown feature identifier. This does not describe a peer.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_supported(feature: u32) -> i32 {
    let caps = CapabilitySet::v0_h2_only();
    match feature {
        ARIAD_FEATURE_H2 => i32::from(caps.h2_streams),
        ARIAD_FEATURE_H3 => i32::from(caps.h3),
        ARIAD_FEATURE_UDP_UNRELIABLE => i32::from(caps.unreliable_datagram),
        ARIAD_FEATURE_ECH => i32::from(caps.ech),
        _ => -1,
    }
}

/// Returns 1 when both versions match this library, or 0 otherwise.
/// This compares supplied values without performing wire negotiation.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_wire_compatible(protocol: u16, h2_binding: u16) -> i32 {
    i32::from(wire_compatible(protocol, h2_binding))
}

/// Returns declared target metadata using the `ARIAD_TARGET_CLASS_*` constants.
/// Unknown target identifiers return -1.
/// The result classifies the named target; it does not inspect the current host.
#[unsafe(no_mangle)]
pub extern "C" fn ariad_target(target: u32) -> i32 {
    let class = match target {
        ARIAD_TARGET_WINDOWS_MSVC => target_class("x86_64-pc-windows-msvc"),
        ARIAD_TARGET_LINUX_GNU => target_class("x86_64-unknown-linux-gnu"),
        ARIAD_TARGET_IOS => target_class("aarch64-apple-ios"),
        ARIAD_TARGET_ANDROID => target_class("aarch64-linux-android"),
        _ => return -1,
    };
    match class {
        TargetClass::TestedLocal => ARIAD_TARGET_CLASS_TESTED_LOCAL,
        TargetClass::DeclaredCi => ARIAD_TARGET_CLASS_DECLARED_CI,
        TargetClass::Unsupported => ARIAD_TARGET_CLASS_UNSUPPORTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_engine() -> AriadHandle {
        registered_engine_with_admission(EngineAdmission::reserve().unwrap())
    }

    fn registered_engine_with_admission(admission: EngineAdmission) -> AriadHandle {
        let descriptor = ariad_core::EndpointDescriptor {
            id: 1,
            generation: 1,
            identity_hostname: "localhost".into(),
            trust_group: 1,
            bindings: vec![ariad_core::BindingId::H2],
            ech_required: false,
        };
        let policy = EndpointPolicy::single(
            descriptor,
            "127.0.0.1:443".parse().unwrap(),
            ariad_core::NetworkEpoch::start(),
        )
        .unwrap();
        let (interrupt, _) = watch::channel(None);
        let owned = OwnedEngine {
            handle: 0,
            runtime: Some(RuntimeDriver::start(interrupt.clone(), admission).unwrap()),
            engine: Some(Arc::new(
                Engine::new(ariad_engine::EngineConfig {
                    limits: ariad_core::BudgetLimits::lab_small(),
                })
                .unwrap(),
            )),
            policy: Arc::new(policy),
            interrupt,
            sessions: HashMap::new(),
            streams: HashMap::new(),
            associations: HashMap::new(),
            shutdown_started: false,
            destroyed: false,
        };
        install_engine(owned).unwrap()
    }

    #[test]
    fn drivers_progress_between_native_calls() {
        let engine = registered_engine();
        let runtime = with_owner(engine, HandleKind::Engine, |owned| {
            Ok(Arc::clone(owned.runtime.as_ref().unwrap()))
        })
        .unwrap();
        let (finished, completion) = std::sync::mpsc::channel();
        let task = runtime.handle.spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            finished.send(()).unwrap();
        });
        completion.recv_timeout(Duration::from_secs(2)).unwrap();
        runtime.handle.block_on(task).unwrap();
        assert_eq!(ariad_engine_destroy(engine, 1000), ARIAD_OK);
    }

    #[test]
    fn pending_operations_allow_progress_and_destroy_wakes_them() {
        let engine = registered_engine();
        let (entered, entry) = std::sync::mpsc::channel();
        let pending = std::thread::spawn(move || {
            let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
            lease.run(async {
                entered.send(()).unwrap();
                std::future::pending::<Result<(), EngineError>>().await
            })
        });
        entry.recv_timeout(Duration::from_secs(2)).unwrap();
        {
            let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
            assert_eq!(lease.run(async { Ok(17) }), Ok(17));
        }
        assert_eq!(ariad_engine_destroy(engine, 1000), ARIAD_OK);
        assert_eq!(pending.join().unwrap(), Err(ARIAD_ERROR_CANCELLED));
        assert_eq!(
            ariad_engine_destroy(engine, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
    }

    #[test]
    fn destroy_expires_without_stopping_a_live_call_driver() {
        let engine = registered_engine();
        let runtime = with_owner(engine, HandleKind::Engine, |owned| {
            Ok(Arc::clone(owned.runtime.as_ref().unwrap()))
        })
        .unwrap();
        let (entered, entry) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let pending = std::thread::spawn(move || {
            let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(2)).unwrap();
            lease.run(async { Ok(()) })
        });
        entry.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(ariad_engine_destroy(engine, 20), ARIAD_FORCED);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            ariad_engine_destroy(engine, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
        release.send(()).unwrap();
        assert_eq!(pending.join().unwrap(), Err(ARIAD_ERROR_CANCELLED));
        assert_eq!(
            runtime.wait_finished(Deadline::after(Duration::from_secs(2)).unwrap()),
            Ok(true)
        );
    }

    #[test]
    fn an_open_cannot_publish_a_child_after_destroy() {
        let engine = registered_engine();
        let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
        let runtime = Arc::clone(&lease.runtime);
        assert_eq!(ariad_engine_destroy(engine, 10), ARIAD_FORCED);
        let mut published = false;
        assert_eq!(
            publish_child(&lease, engine, HandleKind::Session, |_, _| {
                published = true;
                Ok(())
            }),
            Err(ARIAD_ERROR_INVALID_HANDLE)
        );
        assert!(!published);
        drop(lease);
        assert_eq!(
            runtime.wait_finished(Deadline::after(Duration::from_secs(2)).unwrap()),
            Ok(true)
        );
    }

    #[test]
    fn deferred_drivers_hold_admission_until_runtime_cleanup() {
        let count = Arc::new(Mutex::new(0));
        let other_admissions: Vec<_> = (0..MAX_ENGINES - 1)
            .map(|_| EngineAdmission::reserve_from(Arc::clone(&count)).unwrap())
            .collect();
        let engine = registered_engine_with_admission(
            EngineAdmission::reserve_from(Arc::clone(&count)).unwrap(),
        );
        let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
        let runtime = Arc::clone(&lease.runtime);
        assert_eq!(ariad_engine_destroy(engine, 10), ARIAD_FORCED);
        assert!(matches!(
            EngineAdmission::reserve_from(Arc::clone(&count)),
            Err(ARIAD_ERROR_RESOURCE_LIMIT)
        ));
        drop(lease);
        assert_eq!(
            runtime.wait_finished(Deadline::after(Duration::from_secs(2)).unwrap()),
            Ok(true)
        );
        let replacement = registered_engine_with_admission(
            EngineAdmission::reserve_from(Arc::clone(&count)).unwrap(),
        );
        assert_eq!(ariad_engine_destroy(replacement, 1000), ARIAD_OK);
        drop(other_admissions);
        assert_eq!(*count.lock().unwrap(), 0);
    }

    #[test]
    fn an_operation_panic_disables_the_owner_without_a_held_owner_lock() {
        let engine = registered_engine();
        assert_eq!(
            boundary(|| {
                let (lease, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
                lease.run::<i32>(async {
                    panic!("synthetic concurrent FFI operation panic");
                })
            }),
            ARIAD_ERROR_INTERNAL
        );
        assert_eq!(ariad_engine_shutdown(engine, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(ariad_engine_destroy(engine, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(
            ariad_engine_destroy(engine, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
    }

    #[test]
    fn shutdown_keeps_a_failure_reported_after_owner_validation() {
        let engine = registered_engine();
        let (failing_call, ()) = start_operation(engine, HandleKind::Engine, |_| Ok(())).unwrap();
        let (release, failure_allowed) = std::sync::mpsc::channel();
        let (finished, failure_reported) = std::sync::mpsc::channel();
        let failing_worker = std::thread::spawn(move || {
            failure_allowed
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            let status = boundary(|| {
                let _lease = failing_call;
                panic!("synthetic FFI operation panic during shutdown admission");
            });
            finished.send(status).unwrap();
        });
        let (lease, (engine_api, mut children)) =
            start_operation(engine, HandleKind::Engine, |owned| {
                release.send(()).unwrap();
                assert_eq!(
                    failure_reported
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap(),
                    ARIAD_ERROR_INTERNAL
                );
                begin_shutdown(owned)
            })
            .unwrap();
        children.cancel_flows();
        assert_eq!(
            shutdown_result(
                &lease.runtime,
                &engine_api,
                &lease.interrupt,
                Deadline::after(Duration::from_secs(2)).unwrap(),
            ),
            Err(ARIAD_ERROR_INTERNAL)
        );
        drop(children);
        drop(engine_api);
        drop(lease);
        failing_worker.join().unwrap();
        assert_eq!(ariad_engine_shutdown(engine, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(ariad_engine_destroy(engine, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(
            ariad_engine_destroy(engine, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
    }

    #[test]
    fn engine_handles_reject_wrong_types_busy_calls_and_reuse() {
        let first = registered_engine();
        let owned = owner(first, HandleKind::Engine).unwrap();
        let guard = owned.lock().unwrap();
        assert_eq!(ariad_session_destroy(first), ARIAD_ERROR_INVALID_HANDLE);
        assert_eq!(ariad_stream_destroy(first), ARIAD_ERROR_INVALID_HANDLE);
        assert_eq!(ariad_association_destroy(first), ARIAD_ERROR_INVALID_HANDLE);
        assert_eq!(ariad_engine_shutdown(first, 10), ARIAD_ERROR_BUSY);
        assert_eq!(ariad_engine_destroy(first, 10), ARIAD_ERROR_BUSY);
        drop(guard);
        assert_eq!(ariad_engine_destroy(first, 1000), ARIAD_OK);
        assert_eq!(
            ariad_engine_destroy(first, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
        let second = registered_engine();
        assert!(second > first);
        assert_eq!(ariad_engine_shutdown(first, 10), ARIAD_ERROR_INVALID_HANDLE);
        assert_eq!(ariad_engine_destroy(second, 1000), ARIAD_OK);
    }

    #[test]
    fn a_caught_panic_can_only_reuse_the_owner_for_teardown() {
        let handle = registered_engine();
        let owned = owner(handle, HandleKind::Engine).unwrap();
        let status = boundary(|| {
            let _guard = owned.lock().unwrap();
            panic!("synthetic FFI operation panic");
        });
        assert_eq!(status, ARIAD_ERROR_INTERNAL);
        assert_eq!(ariad_engine_shutdown(handle, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(ariad_engine_destroy(handle, 1000), ARIAD_ERROR_INTERNAL);
        assert_eq!(
            ariad_engine_destroy(handle, 1000),
            ARIAD_ERROR_INVALID_HANDLE
        );
        let state = owned.lock().unwrap_or_else(|error| error.into_inner());
        assert!(state.destroyed);
        assert!(state.runtime.is_none());
        assert!(state.engine.is_none());
        assert!(state.sessions.is_empty());
        assert!(state.streams.is_empty());
        assert!(state.associations.is_empty());
    }

    #[test]
    fn invalid_memory_arguments_return_without_access_or_output_data() {
        let mut engine = 123;
        assert_eq!(
            // SAFETY: Null inputs are rejected before access. The output is a valid local handle.
            unsafe {
                ariad_engine_create(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    &mut engine,
                )
            },
            ARIAD_ERROR_INVALID_ARGUMENT
        );
        assert_eq!(engine, 0);
        let mut output = [0x7e; 8];
        let mut count = 123;
        assert_eq!(
            // SAFETY: Output and count are valid disjoint local objects for this call.
            unsafe { ariad_stream_read(0, output.as_mut_ptr(), output.len(), 10, &mut count) },
            ARIAD_ERROR_INVALID_HANDLE
        );
        assert_eq!(count, 0);
        assert_eq!(output, [0x7e; 8]);
        let oversized = vec![0u8; ARIAD_MAX_COPY + 1];
        assert_eq!(
            // SAFETY: The vector supplies the complete readable range; the size is rejected before access.
            unsafe { copy_input(oversized.as_ptr(), oversized.len(), ARIAD_MAX_COPY) },
            Err(ARIAD_ERROR_MESSAGE_TOO_LARGE)
        );
        assert_eq!(ariad_engine_destroy(0, 0), ARIAD_ERROR_INVALID_ARGUMENT);
        assert_eq!(
            ariad_engine_destroy(0, ARIAD_MAX_TIMEOUT_MS + 1),
            ARIAD_ERROR_INVALID_ARGUMENT
        );
    }

    #[test]
    fn handle_exhaustion_does_not_reuse_a_number() {
        let mut registry = Registry::new();
        registry.next_handle = u64::MAX;
        assert_eq!(
            registry.allocate(HandleRecord {
                engine_handle: 1,
                parent: 1,
                kind: HandleKind::Engine,
            }),
            Err(ARIAD_ERROR_RESOURCE_LIMIT)
        );
        assert!(registry.records.is_empty());
    }

    #[test]
    fn datagram_output_preserves_empty_messages_and_never_returns_a_prefix() {
        let mut output = [0x7e; 2];
        let mut count = 0;
        assert_eq!(
            // SAFETY: An empty message does not access the null output. Count is a valid local object.
            unsafe { copy_datagram_output(&[], std::ptr::null_mut(), 0, &mut count) },
            Ok(ARIAD_OK)
        );
        assert_eq!(count, 0);
        assert_eq!(
            // SAFETY: Output and count are valid disjoint local objects. The complete message cannot fit.
            unsafe {
                copy_datagram_output(b"larger", output.as_mut_ptr(), output.len(), &mut count)
            },
            Err(ARIAD_ERROR_MESSAGE_TOO_LARGE)
        );
        assert_eq!(output, [0x7e; 2]);
        assert_eq!(count, 0);
        assert_eq!(
            // SAFETY: The source, output, and count are valid disjoint ranges for this call.
            unsafe { copy_datagram_output(b"ok", output.as_mut_ptr(), output.len(), &mut count) },
            Ok(ARIAD_OK)
        );
        assert_eq!(output, *b"ok");
        assert_eq!(count, 2);
    }

    #[test]
    fn datagram_arguments_clear_outputs_and_reject_invalid_requirements() {
        let mut mode = 123;
        assert_eq!(
            // SAFETY: Mode is a valid aligned local output.
            unsafe { ariad_association_delivery_mode(0, &mut mode) },
            ARIAD_ERROR_INVALID_HANDLE
        );
        assert_eq!(mode, 0);
        let mut association = 123;
        let destination = b"1.1.1.1:53";
        assert_eq!(
            // SAFETY: The destination and output are valid disjoint local ranges.
            unsafe {
                ariad_session_open_datagram(
                    0,
                    destination.as_ptr(),
                    destination.len(),
                    2,
                    10,
                    &mut association,
                )
            },
            ARIAD_ERROR_INVALID_ARGUMENT
        );
        assert_eq!(association, 0);
        let mut count = 123;
        assert_eq!(
            // SAFETY: Empty output does not access the null pointer. Count is a valid local output.
            unsafe { ariad_association_recv(0, std::ptr::null_mut(), 0, 10, &mut count) },
            ARIAD_ERROR_INVALID_HANDLE
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn a_panic_payload_destructor_cannot_unwind_over_the_boundary() {
        struct PanickingDrop;

        impl Drop for PanickingDrop {
            fn drop(&mut self) {
                panic!("synthetic panic payload destructor");
            }
        }

        assert_eq!(
            boundary(|| std::panic::panic_any(PanickingDrop)),
            ARIAD_ERROR_INTERNAL
        );
    }

    #[test]
    fn status_names_match_every_public_operation_status() {
        let header = include_str!("../include/ariad.h");
        let mut statuses = 0;
        for line in header.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("#define") {
                continue;
            }
            let Some(name) = fields.next() else {
                continue;
            };
            if !name.starts_with("ARIAD_ERROR_")
                && !matches!(
                    name,
                    "ARIAD_OK" | "ARIAD_EOF" | "ARIAD_FORCED" | "ARIAD_DROPPED"
                )
            {
                continue;
            }
            let value = fields.next().unwrap();
            let value = value
                .strip_prefix('(')
                .and_then(|value| value.strip_suffix(')'))
                .unwrap_or(value);
            let status = value.parse::<i32>().unwrap();
            let pointer = ariad_status_name(status);
            assert!(!pointer.is_null(), "{name}");
            // SAFETY: The query returns a non-null, static, NUL-terminated string.
            let actual = unsafe { std::ffi::CStr::from_ptr(pointer) };
            assert_eq!(actual.to_str().unwrap(), name);
            assert_eq!(ariad_status_name(status), pointer);
            statuses += 1;
        }
        assert_eq!(statuses, 27);
    }

    #[test]
    fn unknown_status_names_have_a_static_fallback() {
        let fallback = ariad_status_name(i32::MIN);
        assert!(!fallback.is_null());
        for status in [i32::MIN, -29, -9, -5, 4, i32::MAX] {
            let pointer = ariad_status_name(status);
            assert_eq!(pointer, fallback);
            // SAFETY: The query returns a non-null, static, NUL-terminated string.
            let actual = unsafe { std::ffi::CStr::from_ptr(pointer) };
            assert_eq!(actual, c"ARIAD_STATUS_UNKNOWN");
        }
    }

    #[test]
    fn c_abi_reports_only_the_implemented_contract() {
        assert_eq!(ariad_abi_version(), ARIAD_ABI_VERSION);
        assert_eq!(ariad_protocol_version(), 0);
        assert_eq!(ariad_h2_binding_version(), 0);
        assert_eq!(ariad_supported(ARIAD_FEATURE_H2), 1);
        assert_eq!(ariad_supported(ARIAD_FEATURE_H3), 0);
        assert_eq!(ariad_supported(ARIAD_FEATURE_UDP_UNRELIABLE), 0);
        assert_eq!(ariad_supported(ARIAD_FEATURE_ECH), 0);
        assert_eq!(ariad_supported(99), -1);
        assert_eq!(ariad_wire_compatible(0, 0), 1);
        assert_eq!(ariad_wire_compatible(1, 0), 0);
        assert_eq!(ariad_target(ARIAD_TARGET_WINDOWS_MSVC), 1);
        assert_eq!(ariad_target(ARIAD_TARGET_LINUX_GNU), 2);
        assert_eq!(ariad_target(ARIAD_TARGET_IOS), 0);
        assert_eq!(ariad_target(ARIAD_TARGET_ANDROID), 0);
        assert_eq!(ariad_target(0), -1);
    }

    #[test]
    fn header_names_the_same_functions() {
        let header = include_str!("../include/ariad.h");
        for name in [
            "ariad_abi_version",
            "ariad_status_name",
            "ariad_engine_create",
            "ariad_engine_connect",
            "ariad_engine_shutdown",
            "ariad_engine_destroy",
            "ariad_session_open_stream",
            "ariad_session_close",
            "ariad_session_destroy",
            "ariad_stream_write",
            "ariad_stream_read",
            "ariad_stream_end_write",
            "ariad_stream_cancel",
            "ariad_stream_reset",
            "ariad_stream_destroy",
            "ariad_session_open_datagram",
            "ariad_association_delivery_mode",
            "ariad_association_max_payload",
            "ariad_association_send",
            "ariad_association_recv",
            "ariad_association_close",
            "ariad_association_destroy",
            "ariad_protocol_version",
            "ariad_h2_binding_version",
            "ariad_supported",
            "ariad_wire_compatible",
            "ariad_target",
        ] {
            assert!(header.contains(name), "{name}");
        }
    }
}
