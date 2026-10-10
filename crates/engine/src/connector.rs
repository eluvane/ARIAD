#![forbid(unsafe_code)]

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use ariad_core::{
    BindingId, BudgetLimits, Candidate, CandidateContext, CooldownTable, DeadlineKind,
    EndpointAddressHints, EndpointDescriptor, EngineError, MAX_CANDIDATE_ATTEMPTS,
    MAX_PARALLEL_CANDIDATES, NetworkEpoch, RetryPolicy, RetryQuota, RetryQuotaPolicy,
    SelectRequest, backoff_delay_ms, candidate_cooled_in_epoch, connect_failure_class, lab_cap,
    may_retry_other_endpoint, preferred_connect_error, scoped_cooldown_key,
    select_attempts_for_epoch,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch};
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::Deadline;
use crate::h2_tunnel::{H2Config, H2Session};
#[cfg(feature = "h3")]
use crate::h3_tunnel::{H3Config, H3Session};
use crate::host::HostServices;
#[cfg(feature = "tls-boring")]
use crate::native_tls::NativeVerifiedTlsChannel;
use crate::resolver::validate_address;
#[cfg(feature = "tls-rustls")]
use crate::tls::VerifiedTlsChannel;
use crate::trust::EchState;

/// Maximum number of endpoint, address and binding combinations in one policy.
pub const MAX_DIAL_CANDIDATES: usize = 64;
/// Default delay between launches while an earlier attempt remains pending.
pub const CANDIDATE_RACE_DELAY: Duration = Duration::from_millis(250);
const CANDIDATE_COOLDOWN_MS: u64 = 1_000;

/// One endpoint, transport address and binding choice for a network epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialCandidate {
    pub endpoint: EndpointDescriptor,
    /// Routing address. TLS verifies `endpoint.identity_hostname`.
    pub address: SocketAddr,
    pub binding: BindingId,
    /// Groups candidates for selection and failure-domain cooldowns.
    pub failure_domain: u64,
    /// Host network generation under which this route address was selected.
    pub network_epoch: NetworkEpoch,
    pub rtt_hint_ms: u32,
}

impl DialCandidate {
    fn selection(&self, eligible: bool) -> Candidate {
        Candidate {
            endpoint_id: self.endpoint.id,
            binding: self.binding,
            failure_domain: self.failure_domain,
            rtt_hint_ms: self.rtt_hint_ms,
            supports_unreliable: cfg!(feature = "h3") && self.binding == BindingId::H3,
            supports_ech: false,
            exhausted: false,
            binding_allowed: eligible && self.endpoint.permits_binding(self.binding),
        }
    }

    fn context(&self) -> CandidateContext {
        CandidateContext {
            endpoint_generation: self.endpoint.generation,
            address: self.address,
            network_epoch: self.network_epoch,
        }
    }
}

/// Candidate choices for credentials restricted to one trust group.
///
/// Addresses are a host-supplied snapshot. DNS resolution and network observation
/// belong to the host. After a network change, refresh the addresses and rebuild
/// candidates for the new epoch before connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPolicy {
    pub candidates: Vec<DialCandidate>,
    pub credential_trust_group: u64,
    pub require_ech: bool,
    pub require_unreliable: bool,
}

impl EndpointPolicy {
    /// Build an H2 policy containing one supplied transport address.
    pub fn single(
        endpoint: EndpointDescriptor,
        address: SocketAddr,
        network_epoch: NetworkEpoch,
    ) -> Result<Self, EngineError> {
        Self::single_binding(endpoint, address, network_epoch, BindingId::H2)
    }

    /// Build a policy containing one address and binding for the endpoint's trust group.
    pub fn single_binding(
        endpoint: EndpointDescriptor,
        address: SocketAddr,
        network_epoch: NetworkEpoch,
        binding: BindingId,
    ) -> Result<Self, EngineError> {
        let credential_trust_group = endpoint.trust_group;
        let failure_domain = endpoint.id;
        let policy = Self {
            candidates: vec![DialCandidate {
                endpoint,
                address,
                binding,
                failure_domain,
                network_epoch,
                rtt_hint_ms: 0,
            }],
            credential_trust_group,
            require_ech: false,
            require_unreliable: false,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate hints and expand their addresses and bindings into dial candidates.
    /// Hints outside the credential trust group are omitted; no DNS lookup runs here.
    /// The endpoint hostname remains the TLS identity for every address.
    pub fn from_address_hints(
        hints: &[EndpointAddressHints],
        credential_trust_group: u64,
        network_epoch: NetworkEpoch,
    ) -> Result<Self, EngineError> {
        if hints.len() > MAX_DIAL_CANDIDATES {
            return Err(EngineError::ResourceLimitExceeded);
        }
        let mut candidates = Vec::new();
        for hint in hints {
            hint.validate()?;
            if !hint
                .endpoint
                .permits_credential_group(credential_trust_group)
            {
                continue;
            }
            for address in &hint.addresses {
                for binding in &hint.endpoint.bindings {
                    if candidates.len() == MAX_DIAL_CANDIDATES {
                        return Err(EngineError::ResourceLimitExceeded);
                    }
                    candidates.push(DialCandidate {
                        endpoint: hint.endpoint.clone(),
                        address: *address,
                        binding: *binding,
                        failure_domain: hint.endpoint.id,
                        network_epoch,
                        rtt_hint_ms: 0,
                    });
                }
            }
        }
        let policy = Self {
            candidates,
            credential_trust_group,
            require_ech: false,
            require_unreliable: false,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Check candidate bounds, endpoint descriptors, route addresses and descriptor consistency.
    ///
    /// Zero ports return `InvalidConfig`. Unspecified, multicast and IPv4 broadcast
    /// targets return `EndpointResolutionFailed`, including IPv4-mapped IPv6 values.
    /// Validation runs before an attempt spends retry quota.
    /// Binding support and credential-group eligibility are checked when connecting.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.candidates.len() > MAX_DIAL_CANDIDATES {
            return Err(EngineError::ResourceLimitExceeded);
        }
        if self.candidates.is_empty() {
            return Err(EngineError::NoReachableTrustedPath);
        }
        for (index, candidate) in self.candidates.iter().enumerate() {
            candidate.endpoint.validate()?;
            if candidate.address.port() == 0 {
                return Err(EngineError::InvalidConfig);
            }
            validate_address(candidate.address)?;
            if self.candidates[..index].iter().any(|previous| {
                previous.endpoint.id == candidate.endpoint.id
                    && previous.endpoint.generation == candidate.endpoint.generation
                    && previous.endpoint != candidate.endpoint
            }) {
                return Err(EngineError::InvalidConfig);
            }
        }
        Ok(())
    }
}

/// One candidate race's deadline and expected network epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Absolute deadline for selection, dialing and retiring completed losing channels.
    pub deadline: Deadline,
    pub network_epoch: NetworkEpoch,
}

impl ConnectRequest {
    pub fn lab_small(network_epoch: NetworkEpoch) -> Result<Self, EngineError> {
        Ok(Self {
            deadline: Deadline::after(lab_cap(DeadlineKind::ConnectTotal))?,
            network_epoch,
        })
    }
}

/// A peer-verified transport whose binding startup handshake completed.
pub enum SelectedTransport {
    #[cfg(feature = "tls-rustls")]
    RustlsH2(ReadyH2Channel),
    #[cfg(feature = "tls-boring")]
    BoringH2(ReadyH2Channel),
    #[cfg(feature = "h3")]
    H3(H3Session),
}

/// Peer identity and the H2 control handshake are verified before this value exists.
pub struct ReadyH2Channel {
    session: H2Session,
    endpoint: EndpointDescriptor,
    address: SocketAddr,
    ech: EchState,
}

impl ReadyH2Channel {
    #[cfg(feature = "tls-rustls")]
    async fn from_rustls(
        channel: VerifiedTlsChannel,
        config: &H2Config,
        deadline: Deadline,
    ) -> Result<Self, EngineError> {
        let endpoint = channel.endpoint().clone();
        let address = channel.address();
        let ech = channel.ech();
        let session =
            H2Session::handshake_with_deadline(channel.into_io(), true, config.clone(), deadline)
                .await?;
        Ok(Self {
            session,
            endpoint,
            address,
            ech,
        })
    }

    #[cfg(feature = "tls-boring")]
    async fn from_boring(
        channel: NativeVerifiedTlsChannel,
        config: &H2Config,
        deadline: Deadline,
    ) -> Result<Self, EngineError> {
        let endpoint = channel.endpoint().clone();
        let address = channel.address();
        let ech = channel.ech();
        let session =
            H2Session::handshake_with_deadline(channel.into_io(), true, config.clone(), deadline)
                .await?;
        Ok(Self {
            session,
            endpoint,
            address,
            ech,
        })
    }

    pub fn endpoint(&self) -> &EndpointDescriptor {
        &self.endpoint
    }
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
    pub const fn binding(&self) -> BindingId {
        BindingId::H2
    }
    pub const fn ech(&self) -> EchState {
        self.ech
    }
    pub fn into_session(self) -> H2Session {
        self.session
    }
}

impl SelectedTransport {
    pub fn endpoint(&self) -> &EndpointDescriptor {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(channel) => channel.endpoint(),
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(channel) => channel.endpoint(),
            #[cfg(feature = "h3")]
            Self::H3(channel) => channel.endpoint(),
        }
    }

    pub fn address(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(channel) => channel.address(),
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(channel) => channel.address(),
            #[cfg(feature = "h3")]
            Self::H3(channel) => channel.address(),
        }
    }

    pub fn binding(&self) -> BindingId {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(channel) => channel.binding(),
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(channel) => channel.binding(),
            #[cfg(feature = "h3")]
            Self::H3(channel) => channel.binding(),
        }
    }

    pub fn ech(&self) -> EchState {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(channel) => channel.ech(),
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(channel) => channel.ech(),
            #[cfg(feature = "h3")]
            Self::H3(channel) => channel.ech(),
        }
    }

    pub fn native_datagrams_enabled(&self) -> bool {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(_) => false,
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(_) => false,
            #[cfg(feature = "h3")]
            Self::H3(channel) => channel.native_datagram_enabled(),
        }
    }
}

/// The winning transport and candidate metadata returned by an endpoint connector.
pub struct SelectedChannel {
    pub endpoint: EndpointDescriptor,
    pub binding: BindingId,
    pub channel: SelectedTransport,
    pub network_epoch: NetworkEpoch,
}

/// Races candidates with shared dial slots, retry quota, cooldowns and backoff.
/// Concurrent connection calls on this connector share these limits.
pub struct EndpointConnector {
    host: Arc<HostServices>,
    race: RaceController,
    #[cfg(feature = "h3")]
    limits: BudgetLimits,
}

impl EndpointConnector {
    /// Create a connector with the lab dial limits and retry quota.
    pub fn new(host: Arc<HostServices>) -> Self {
        Self {
            host,
            race: RaceController::new(),
            #[cfg(feature = "h3")]
            limits: BudgetLimits::lab_small(),
        }
    }

    pub fn with_limits(host: Arc<HostServices>, limits: BudgetLimits) -> Result<Self, EngineError> {
        limits.validate()?;
        Ok(Self {
            host,
            race: RaceController::with_limits(
                limits.parallel_candidate_dials,
                limits.candidate_attempts,
            )?,
            #[cfg(feature = "h3")]
            limits,
        })
    }

    pub fn with_retry_quota(
        host: Arc<HostServices>,
        policy: RetryQuotaPolicy,
    ) -> Result<Self, EngineError> {
        let quota = RetryQuota::new(policy)?;
        let mut connector = Self::new(host);
        connector
            .race
            .state
            .get_mut()
            .map_err(|_| EngineError::ResourceLimitExceeded)?
            .quota = quota;
        Ok(connector)
    }

    /// Accept a newer network epoch and cancel races from older epochs.
    /// Repeating the current epoch keeps races running. Retry quota and backoff persist.
    /// Use `Engine::on_network_change` to coordinate this with session draining.
    /// Refresh host route addresses and rebuild policy candidates for the new epoch.
    pub fn on_network_change(&self, epoch: NetworkEpoch) -> Result<(), EngineError> {
        self.race.on_network_change(epoch)
    }

    /// Select and prepare a transport using the default H2 configuration.
    /// See [`Self::connect_with_config`] for deadline and cancellation behavior.
    pub async fn connect(
        &self,
        policy: &EndpointPolicy,
        request: ConnectRequest,
    ) -> Result<SelectedChannel, EngineError> {
        self.connect_with_config(policy, request, &H2Config::default())
            .await
    }

    /// Verify a candidate's peer and complete binding startup within the request deadline.
    ///
    /// Each dial attempt uses the lab [`DeadlineKind::TransportHandshake`] cap
    /// within the same total deadline. See [`lab_cap`] for the current limit.
    /// A peer identity failure rejects the race even if another channel is ready.
    /// Success includes retiring completed losers; pending attempts are dropped.
    /// Spent retry quota remains charged after cancellation.
    pub async fn connect_with_config(
        &self,
        policy: &EndpointPolicy,
        request: ConnectRequest,
        config: &H2Config,
    ) -> Result<SelectedChannel, EngineError> {
        request.deadline.remaining()?;
        policy.validate()?;
        config.validate()?;
        if policy.require_ech {
            return Err(EngineError::UnsupportedCapability);
        }
        #[cfg(not(feature = "h3"))]
        if policy.require_unreliable {
            return Err(EngineError::UnsupportedCapability);
        }
        let mut eligibility = Vec::with_capacity(policy.candidates.len());
        let mut eligibility_error = None;
        for candidate in &policy.candidates {
            if candidate.network_epoch != request.network_epoch
                || !candidate
                    .endpoint
                    .permits_credential_group(policy.credential_trust_group)
                || (policy.require_unreliable && candidate.binding != BindingId::H3)
            {
                eligibility.push(false);
                continue;
            }
            match self
                .host
                .supports_binding(&candidate.endpoint, candidate.binding)
            {
                Ok(()) => eligibility.push(true),
                Err(error) => {
                    eligibility.push(false);
                    eligibility_error = Some(
                        eligibility_error
                            .map_or(error, |previous| preferred_connect_error(previous, error)),
                    );
                    if error == EngineError::PeerIdentityFailed {
                        return Err(error);
                    }
                }
            }
        }
        if !eligibility.iter().any(|eligible| *eligible) {
            return Err(eligibility_error.unwrap_or(EngineError::NoReachableTrustedPath));
        }
        let (candidate_index, channel) = self
            .race
            .race(
                &policy.candidates,
                &eligibility,
                request,
                |candidate, deadline| async move {
                    let channel = self.dial(candidate, deadline, config).await?;
                    if channel.endpoint() != &candidate.endpoint
                        || channel.binding() != candidate.binding
                        || channel.address() != candidate.address
                    {
                        return Err(EngineError::PeerIdentityFailed);
                    }
                    if policy.require_unreliable && !channel.native_datagrams_enabled() {
                        return Err(EngineError::UnsupportedCapability);
                    }
                    Ok(channel)
                },
            )
            .await?;
        let candidate = &policy.candidates[candidate_index];
        Ok(SelectedChannel {
            endpoint: candidate.endpoint.clone(),
            binding: candidate.binding,
            channel,
            network_epoch: request.network_epoch,
        })
    }

    async fn dial(
        &self,
        candidate: &DialCandidate,
        deadline: Deadline,
        config: &H2Config,
    ) -> Result<SelectedTransport, EngineError> {
        match candidate.binding {
            BindingId::H2 => {
                // Select the TLS backend before dialing. Identity failures never switch backends.
                #[cfg(feature = "tls-boring")]
                if self
                    .host
                    .supports_boring_endpoint(&candidate.endpoint)
                    .is_ok()
                {
                    let channel = self
                        .host
                        .connect_boring_verified(&candidate.endpoint, candidate.address, deadline)
                        .await?;
                    return ReadyH2Channel::from_boring(channel, config, deadline)
                        .await
                        .map(SelectedTransport::BoringH2);
                }
                #[cfg(feature = "tls-rustls")]
                {
                    let channel = self
                        .host
                        .connect_verified(&candidate.endpoint, candidate.address, deadline)
                        .await?;
                    ReadyH2Channel::from_rustls(channel, config, deadline)
                        .await
                        .map(SelectedTransport::RustlsH2)
                }
                #[cfg(not(feature = "tls-rustls"))]
                {
                    Err(EngineError::UnsupportedCapability)
                }
            }
            BindingId::H3 => {
                #[cfg(feature = "h3")]
                {
                    let mut h3_config = H3Config::from_h2_config(config)?;
                    h3_config.limits = self.limits;
                    h3_config.validate()?;
                    self.host
                        .connect_h3_verified(
                            &candidate.endpoint,
                            candidate.address,
                            h3_config,
                            deadline,
                        )
                        .await
                        .map(SelectedTransport::H3)
                }
                #[cfg(not(feature = "h3"))]
                {
                    let _ = config;
                    Err(EngineError::UnsupportedCapability)
                }
            }
        }
    }
}

/// A completed dial result with cleanup for a losing race outcome.
trait RaceChannel: Send {
    /// Consume the result and retire its driver. Failure can replace the race result.
    fn retire(self, deadline: Deadline) -> impl Future<Output = Result<(), EngineError>> + Send;
}

impl RaceChannel for SelectedTransport {
    async fn retire(self, deadline: Deadline) -> Result<(), EngineError> {
        match self {
            #[cfg(feature = "tls-rustls")]
            Self::RustlsH2(channel) => retire_h2(channel.into_session(), deadline).await,
            #[cfg(feature = "tls-boring")]
            Self::BoringH2(channel) => retire_h2(channel.into_session(), deadline).await,
            #[cfg(feature = "h3")]
            Self::H3(session) => {
                session.cancel();
                match deadline.run(session.wait_closed()).await {
                    Err(EngineError::DeadlineExceeded) => Err(EngineError::DeadlineExceeded),
                    _ => Ok(()),
                }
            }
        }
    }
}

async fn retire_h2(session: H2Session, deadline: Deadline) -> Result<(), EngineError> {
    session.cancel();
    match deadline.run(session.wait_closed()).await {
        Err(EngineError::DeadlineExceeded) => Err(EngineError::DeadlineExceeded),
        _ => Ok(()),
    }
}

struct RaceState {
    epoch: NetworkEpoch,
    cooldowns: CooldownTable,
    quota: RetryQuota,
    failed_races: u32,
    next_race_at: Instant,
}

struct RaceController {
    state: Mutex<RaceState>,
    epoch_changes: watch::Sender<NetworkEpoch>,
    dial_slots: Arc<Semaphore>,
    clock_origin: Instant,
    launch_delay: Duration,
    max_parallel: usize,
    max_attempts: usize,
}

impl RaceController {
    fn new() -> Self {
        Self::configured(MAX_PARALLEL_CANDIDATES, MAX_CANDIDATE_ATTEMPTS)
    }

    fn with_limits(max_parallel: usize, max_attempts: usize) -> Result<Self, EngineError> {
        if max_parallel == 0
            || max_parallel > MAX_PARALLEL_CANDIDATES
            || max_attempts == 0
            || max_attempts > MAX_CANDIDATE_ATTEMPTS
            || max_parallel > max_attempts
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self::configured(max_parallel, max_attempts))
    }

    fn configured(max_parallel: usize, max_attempts: usize) -> Self {
        let epoch = NetworkEpoch::start();
        let clock_origin = Instant::now();
        let (epoch_changes, _) = watch::channel(epoch);
        Self {
            state: Mutex::new(RaceState {
                epoch,
                cooldowns: CooldownTable::new(),
                quota: RetryQuota::lab_small(),
                failed_races: 0,
                next_race_at: clock_origin,
            }),
            epoch_changes,
            dial_slots: Arc::new(Semaphore::new(max_parallel)),
            clock_origin,
            launch_delay: CANDIDATE_RACE_DELAY,
            max_parallel,
            max_attempts,
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, RaceState>, EngineError> {
        self.state
            .lock()
            .map_err(|_| EngineError::ResourceLimitExceeded)
    }

    fn elapsed_ms(&self) -> Result<u64, EngineError> {
        u64::try_from(self.clock_origin.elapsed().as_millis())
            .map_err(|_| EngineError::ResourceLimitExceeded)
    }

    fn on_network_change(&self, epoch: NetworkEpoch) -> Result<(), EngineError> {
        let mut state = self.lock_state()?;
        state.epoch.observe(epoch)?;
        if state.epoch != epoch {
            state.epoch = epoch;
            state.cooldowns.retain_epoch(epoch);
            self.epoch_changes.send_replace(epoch);
        }
        // Reachability is local to the network. Retry quota covers all network epochs.
        Ok(())
    }

    fn verify_epoch(&self, epoch: NetworkEpoch) -> Result<(), EngineError> {
        if self.lock_state()?.epoch != epoch {
            Err(EngineError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn record_failure(
        &self,
        candidate: &DialCandidate,
        error: EngineError,
    ) -> Result<(), EngineError> {
        let Some(class) = connect_failure_class(error) else {
            return Ok(());
        };
        let Some(key) = scoped_cooldown_key(&candidate.selection(true), candidate.context(), class)
        else {
            return Ok(());
        };
        let mut state = self.lock_state()?;
        if state.epoch != candidate.network_epoch {
            return Err(EngineError::Cancelled);
        }
        state
            .cooldowns
            .record_scoped(key, self.elapsed_ms()?, CANDIDATE_COOLDOWN_MS)
    }

    fn finish_failed_race<T>(
        &self,
        error: EngineError,
        launched_attempts: usize,
    ) -> Result<T, EngineError> {
        if launched_attempts != 0 && error != EngineError::Cancelled {
            let mut state = self.lock_state()?;
            let policy = RetryPolicy {
                max_attempts_per_operation: u32::MAX,
                ..RetryPolicy::lab_small()
            };
            let jitter_ppm = u32::try_from(
                self.clock_origin.elapsed().as_nanos()
                    % (u128::from(RetryPolicy::JITTER_PPM_SCALE) + 1),
            )
            .map_err(|_| EngineError::ResourceLimitExceeded)?;
            let backoff_ms = backoff_delay_ms(policy, state.failed_races, jitter_ppm)?;
            state.failed_races = state.failed_races.saturating_add(1);
            state.next_race_at = Instant::now()
                .checked_add(Duration::from_millis(backoff_ms))
                .ok_or(EngineError::ResourceLimitExceeded)?;
        }
        Err(error)
    }

    async fn race<'a, T, D, F>(
        &'a self,
        candidates: &'a [DialCandidate],
        eligibility: &[bool],
        request: ConnectRequest,
        dial: D,
    ) -> Result<(usize, T), EngineError>
    where
        T: RaceChannel + 'a,
        D: Fn(&'a DialCandidate, Deadline) -> F,
        F: Future<Output = Result<T, EngineError>> + Send + 'a,
    {
        request.deadline.remaining()?;
        if candidates.len() != eligibility.len() || candidates.len() > MAX_DIAL_CANDIDATES {
            return Err(EngineError::InvalidConfig);
        }
        let mut epoch_changes = self.epoch_changes.subscribe();
        self.verify_epoch(request.network_epoch)?;
        let (candidate_order, mut launch_at) = {
            let state = self.lock_state()?;
            let now_ms = self.elapsed_ms()?;
            let selection_candidates: Vec<_> = candidates
                .iter()
                .zip(eligibility)
                .map(|(candidate, eligible)| candidate.selection(*eligible))
                .collect();
            let candidate_epochs: Vec<_> = candidates
                .iter()
                .map(|candidate| candidate.network_epoch.get())
                .collect();
            let candidate_cooled: Vec<_> = candidates
                .iter()
                .map(|candidate| {
                    candidate_cooled_in_epoch(
                        &candidate.selection(true),
                        candidate.context(),
                        &state.cooldowns,
                        now_ms,
                    )
                })
                .collect();
            let candidate_order = select_attempts_for_epoch(
                &selection_candidates,
                &candidate_epochs,
                &candidate_cooled,
                request.network_epoch,
                SelectRequest {
                    require_unreliable: false,
                    require_ech: false,
                    max_parallel: self.max_parallel,
                    max_attempts: self.max_attempts,
                },
            )?;
            (candidate_order, state.next_race_at)
        };
        if candidate_order.is_empty() {
            return Err(EngineError::NoReachableTrustedPath);
        }
        let mut attempts = AttemptSet::new();
        let mut order_position = 0;
        let mut launched_attempts = 0;
        let mut preferred_error = EngineError::NoReachableTrustedPath;
        let mut reserved_dial_slot = None;
        let mut quota_exhausted = false;
        loop {
            if let Err(error) = request
                .deadline
                .remaining()
                .and_then(|_| self.verify_epoch(request.network_epoch))
            {
                return self.finish_failed_race(error, launched_attempts);
            }
            let may_launch_more = !quota_exhausted
                && order_position < candidate_order.len()
                && launched_attempts < self.max_attempts;
            let should_launch = may_launch_more
                && attempts.len() < self.max_parallel
                && Instant::now() >= launch_at;
            if should_launch {
                let dial_slot = match reserved_dial_slot.take() {
                    Some(dial_slot) => Some(dial_slot),
                    None => match Arc::clone(&self.dial_slots).try_acquire_owned() {
                        Ok(dial_slot) => Some(dial_slot),
                        Err(TryAcquireError::NoPermits) => None,
                        Err(TryAcquireError::Closed) => {
                            return self
                                .finish_failed_race(EngineError::Cancelled, launched_attempts);
                        }
                    },
                };
                if let Some(dial_slot) = dial_slot {
                    let candidate_index = candidate_order[order_position];
                    order_position += 1;
                    let candidate = &candidates[candidate_index];
                    let mut state = self.lock_state()?;
                    if state.epoch != request.network_epoch {
                        return Err(EngineError::Cancelled);
                    }
                    let now_ms = self.elapsed_ms()?;
                    if candidate_cooled_in_epoch(
                        &candidate.selection(true),
                        candidate.context(),
                        &state.cooldowns,
                        now_ms,
                    ) {
                        continue;
                    }
                    // Charge before creating the dial future. Cancellation does not restore quota.
                    match state.quota.reserve(now_ms) {
                        Ok(()) => {}
                        Err(error) => {
                            quota_exhausted = true;
                            preferred_error = preferred_connect_error(preferred_error, error);
                            continue;
                        }
                    }
                    drop(state);
                    let attempt_deadline = request
                        .deadline
                        .cap(lab_cap(DeadlineKind::TransportHandshake))?;
                    let dial_future = dial(candidate, attempt_deadline);
                    attempts.push(
                        candidate_index,
                        async move {
                            timeout_at(attempt_deadline.expires_at(), dial_future)
                                .await
                                .map_err(|_| EngineError::DeadlineExceeded)?
                        },
                        dial_slot,
                    );
                    launched_attempts += 1;
                    launch_at = Instant::now()
                        .checked_add(self.launch_delay)
                        .ok_or(EngineError::ResourceLimitExceeded)?;
                    continue;
                }
            }
            if attempts.is_empty() && !may_launch_more {
                return self.finish_failed_race(preferred_error, launched_attempts);
            }
            let wait_for_dial_slot = should_launch && reserved_dial_slot.is_none();
            tokio::select! {
                biased;
                _ = sleep_until(request.deadline.expires_at()) => return self.finish_failed_race(EngineError::DeadlineExceeded, launched_attempts),
                change = epoch_changes.changed() => {
                    let _ = change;
                    return Err(EngineError::Cancelled);
                }
                completed_attempts = poll_fn(|cx| attempts.poll_ready(cx)), if !attempts.is_empty() => {
                    let mut winner = None;
                    let mut ready_losers = Vec::new();
                    let mut terminal_error = None;
                    for (candidate_index, result) in completed_attempts {
                        match result {
                            Ok(channel) => {
                                if winner.is_none() { winner = Some((candidate_index, channel)); }
                                else { ready_losers.push(channel); }
                            }
                            Err(error) => {
                                self.record_failure(&candidates[candidate_index], error)?;
                                preferred_error = preferred_connect_error(preferred_error, error);
                                let retryable = error == EngineError::UnsupportedCapability
                                    || connect_failure_class(error).is_some_and(may_retry_other_endpoint);
                                if !retryable {
                                    terminal_error = Some(terminal_error.map_or(error, |previous| preferred_connect_error(previous, error)));
                                }
                            }
                        }
                    }
                    // A ready channel must not hide a peer identity failure in this batch.
                    let outcome = match (terminal_error, winner) {
                        (Some(error), winner) => {
                            if let Some((_, channel)) = winner { ready_losers.push(channel); }
                            Err(error)
                        }
                        (None, Some(winner)) => Ok(winner),
                        (None, None) => {
                            if attempts.is_empty() { launch_at = Instant::now(); }
                            continue;
                        }
                    };
                    // Pending dials stop on drop. Completed losers need driver retirement.
                    drop(attempts);
                    for loser in ready_losers {
                        if let Err(error) = loser.retire(request.deadline).await { return self.finish_failed_race(error, launched_attempts); }
                    }
                    let winner = match outcome {
                        Ok(winner) => winner,
                        Err(error) => return self.finish_failed_race(error, launched_attempts),
                    };
                    if let Err(error) = request.deadline.remaining() { return self.finish_failed_race(error, launched_attempts); }
                    let mut state = self.lock_state()?;
                    if state.epoch != request.network_epoch { return Err(EngineError::Cancelled); }
                    state.quota.record_progress();
                    state.failed_races = 0;
                    state.next_race_at = Instant::now();
                    drop(state);
                    return Ok(winner);
                }
                dial_slot = Arc::clone(&self.dial_slots).acquire_owned(), if wait_for_dial_slot => {
                    reserved_dial_slot = Some(dial_slot.map_err(|_| EngineError::Cancelled)?);
                }
                _ = sleep_until(launch_at), if may_launch_more && attempts.len() < self.max_parallel && !should_launch => {}
            }
        }
    }
}

struct Attempt<'a, T> {
    candidate_index: usize,
    future: Pin<Box<dyn Future<Output = Result<T, EngineError>> + Send + 'a>>,
    // Hold the shared dial slot until the future completes or is dropped.
    _dial_slot: OwnedSemaphorePermit,
}

struct AttemptSet<'a, T> {
    attempts: Vec<Attempt<'a, T>>,
}

impl<'a, T> AttemptSet<'a, T> {
    fn new() -> Self {
        Self {
            attempts: Vec::with_capacity(MAX_PARALLEL_CANDIDATES),
        }
    }

    fn len(&self) -> usize {
        self.attempts.len()
    }
    fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }

    fn push<F>(&mut self, candidate_index: usize, future: F, dial_slot: OwnedSemaphorePermit)
    where
        F: Future<Output = Result<T, EngineError>> + Send + 'a,
    {
        self.attempts.push(Attempt {
            candidate_index,
            future: Box::pin(future),
            _dial_slot: dial_slot,
        });
    }

    /// Poll each attempt once. The race checks the whole ready batch for terminal failures.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Vec<(usize, Result<T, EngineError>)>> {
        let mut completed = Vec::new();
        let mut position = 0;
        while position < self.attempts.len() {
            match self.attempts[position].future.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let attempt = self.attempts.remove(position);
                    completed.push((attempt.candidate_index, result));
                }
                Poll::Pending => position += 1,
            }
        }
        if completed.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(completed)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct ActiveAttempt {
        active: Arc<AtomicUsize>,
    }

    impl ActiveAttempt {
        fn new(active: Arc<AtomicUsize>, peak_active: Arc<AtomicUsize>) -> Self {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak_active.fetch_max(count, Ordering::SeqCst);
            Self { active }
        }
    }

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct DropTrackedChannel(Arc<AtomicUsize>);

    struct RetirementFailure;

    impl RaceChannel for RetirementFailure {
        async fn retire(self, _deadline: Deadline) -> Result<(), EngineError> {
            Err(EngineError::DeadlineExceeded)
        }
    }

    struct RetirementTrackedChannel {
        id: u64,
        retired: Arc<AtomicUsize>,
    }

    impl RaceChannel for RetirementTrackedChannel {
        async fn retire(self, _deadline: Deadline) -> Result<(), EngineError> {
            tokio::task::yield_now().await;
            self.retired.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl Drop for DropTrackedChannel {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RaceChannel for DropTrackedChannel {
        async fn retire(self, _deadline: Deadline) -> Result<(), EngineError> {
            drop(self);
            Ok(())
        }
    }

    impl RaceChannel for () {
        async fn retire(self, _deadline: Deadline) -> Result<(), EngineError> {
            Ok(())
        }
    }

    fn candidates(count: usize, epoch: NetworkEpoch) -> Vec<DialCandidate> {
        (0..count)
            .map(|index| {
                let id = u64::try_from(index).unwrap() + 1;
                DialCandidate {
                    endpoint: EndpointDescriptor {
                        id,
                        generation: 1,
                        identity_hostname: "endpoint.test".to_string(),
                        trust_group: 7,
                        bindings: vec![BindingId::H2],
                        ech_required: false,
                    },
                    address: "127.0.0.1:443".parse().unwrap(),
                    binding: BindingId::H2,
                    failure_domain: id,
                    network_epoch: epoch,
                    rtt_hint_ms: 0,
                }
            })
            .collect()
    }

    fn immediate_race() -> RaceController {
        let mut race = RaceController::new();
        race.launch_delay = Duration::ZERO;
        race
    }

    fn request(epoch: NetworkEpoch, duration: Duration) -> ConnectRequest {
        ConnectRequest {
            deadline: Deadline::after(duration).unwrap(),
            network_epoch: epoch,
        }
    }

    #[tokio::test]
    async fn winner_drops_the_pending_loser_before_returning() {
        let race = immediate_race();
        let candidates = candidates(3, NetworkEpoch::start());
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let result = race
            .race(
                &candidates,
                &[true; 3],
                request(NetworkEpoch::start(), Duration::from_secs(1)),
                |candidate, _| {
                    let active = Arc::clone(&active);
                    let peak_active = Arc::clone(&peak_active);
                    let dropped = Arc::clone(&dropped);
                    async move {
                        let _active = ActiveAttempt::new(active, peak_active);
                        if candidate.endpoint.id == 1 {
                            pending::<()>().await;
                        }
                        Ok(DropTrackedChannel(dropped))
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(result.0, 1);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak_active.load(Ordering::SeqCst), 2);
        assert_eq!(race.dial_slots.available_permits(), MAX_PARALLEL_CANDIDATES);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(result);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn winner_waits_for_ready_loser_retirement() {
        let race = immediate_race();
        let candidates = candidates(2, NetworkEpoch::start());
        let retired = Arc::new(AtomicUsize::new(0));
        let result = race
            .race(
                &candidates,
                &[true; 2],
                request(NetworkEpoch::start(), Duration::from_secs(1)),
                |candidate, _| {
                    let retired = Arc::clone(&retired);
                    async move {
                        Ok(RetirementTrackedChannel {
                            id: candidate.endpoint.id,
                            retired,
                        })
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(result.1.id, 1);
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert_eq!(race.dial_slots.available_permits(), MAX_PARALLEL_CANDIDATES);
    }

    #[tokio::test]
    async fn retirement_failure_overrides_success_and_terminal_failure() {
        for dial_error in [None, Some(EngineError::PeerIdentityFailed)] {
            let race = immediate_race();
            let candidates = candidates(2, NetworkEpoch::start());
            let result = race
                .race(
                    &candidates,
                    &[true; 2],
                    request(NetworkEpoch::start(), Duration::from_secs(1)),
                    |candidate, _| async move {
                        if candidate.endpoint.id == 2
                            && let Some(error) = dial_error
                        {
                            return Err(error);
                        }
                        Ok(RetirementFailure)
                    },
                )
                .await;
            assert_eq!(result.err(), Some(EngineError::DeadlineExceeded));
            assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
            assert_eq!(race.dial_slots.available_permits(), MAX_PARALLEL_CANDIDATES);
        }
    }

    #[tokio::test]
    async fn dropping_connect_cancels_attempts_and_keeps_spent_quota() {
        let race = immediate_race();
        let candidates = candidates(3, NetworkEpoch::start());
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let allowed = [true; 3];
        let mut operation = Box::pin(race.race(
            &candidates,
            &allowed,
            request(NetworkEpoch::start(), Duration::from_secs(1)),
            |_, _| {
                let active = Arc::clone(&active);
                let peak_active = Arc::clone(&peak_active);
                async move {
                    let _active = ActiveAttempt::new(active, peak_active);
                    pending::<Result<(), EngineError>>().await
                }
            },
        ));
        tokio::select! {
            result = &mut operation => panic!("unexpected completion: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(active.load(Ordering::SeqCst), 2);
        drop(operation);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(race.dial_slots.available_permits(), MAX_PARALLEL_CANDIDATES);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
    }

    #[tokio::test]
    async fn total_deadline_stops_pending_attempts() {
        let race = immediate_race();
        let candidates = candidates(8, NetworkEpoch::start());
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let request = request(NetworkEpoch::start(), Duration::from_millis(10));
        let result = race
            .race(&candidates, &[true; 8], request, |_, child| {
                assert!(child.expires_at() <= request.deadline.expires_at());
                let active = Arc::clone(&active);
                let peak_active = Arc::clone(&peak_active);
                async move {
                    let _active = ActiveAttempt::new(active, peak_active);
                    pending::<Result<(), EngineError>>().await
                }
            })
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak_active.load(Ordering::SeqCst), 2);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
    }

    #[tokio::test]
    async fn failures_stop_at_four_total_attempts() {
        let race = immediate_race();
        let candidates = candidates(8, NetworkEpoch::start());
        let started = AtomicUsize::new(0);
        let result = race
            .race(
                &candidates,
                &[true; 8],
                request(NetworkEpoch::start(), Duration::from_secs(1)),
                |_, _| async {
                    started.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(EngineError::TransportUnavailable)
                },
            )
            .await;
        assert_eq!(result, Err(EngineError::TransportUnavailable));
        assert_eq!(started.load(Ordering::SeqCst), MAX_CANDIDATE_ATTEMPTS);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 4);
        assert!(race.lock_state().unwrap().next_race_at > Instant::now());
    }

    #[tokio::test]
    async fn identity_failure_wins_over_a_simultaneously_ready_channel() {
        let race = immediate_race();
        let candidates = candidates(2, NetworkEpoch::start());
        let dropped = Arc::new(AtomicUsize::new(0));
        let result = race
            .race(
                &candidates,
                &[true; 2],
                request(NetworkEpoch::start(), Duration::from_secs(1)),
                |candidate, _| {
                    let dropped = Arc::clone(&dropped);
                    async move {
                        if candidate.endpoint.id == 2 {
                            return Err(EngineError::PeerIdentityFailed);
                        }
                        Ok(DropTrackedChannel(dropped))
                    }
                },
            )
            .await;
        assert!(matches!(result, Err(EngineError::PeerIdentityFailed)));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_change_cancels_the_race_without_resetting_quota() {
        let race = immediate_race();
        race.lock_state().unwrap().quota = RetryQuota::new(RetryQuotaPolicy {
            window_ms: 60_000,
            max_attempts_per_window: 2,
            max_attempts_without_progress: 2,
        })
        .unwrap();
        let epoch = NetworkEpoch::start();
        let candidates = candidates(2, epoch);
        let allowed = [true; 2];
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let mut operation = Box::pin(race.race(
            &candidates,
            &allowed,
            request(epoch, Duration::from_secs(1)),
            |_, _| {
                let active = Arc::clone(&active);
                let peak_active = Arc::clone(&peak_active);
                async move {
                    let _active = ActiveAttempt::new(active, peak_active);
                    pending::<Result<(), EngineError>>().await
                }
            },
        ));
        tokio::select! {
            result = &mut operation => panic!("unexpected completion: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        let next = epoch.advance().unwrap();
        race.on_network_change(next).unwrap();
        assert_eq!(operation.await, Err(EngineError::Cancelled));
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let candidates = self::candidates(1, next);
        let started = AtomicUsize::new(0);
        let result = race
            .race(
                &candidates,
                &[true],
                request(next, Duration::from_secs(1)),
                |_, _| async {
                    started.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
        assert_eq!(result, Err(EngineError::ResourceLimitExceeded));
        assert_eq!(started.load(Ordering::SeqCst), 0);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
    }

    #[test]
    fn address_policy_filters_credential_groups_without_changing_identity() {
        let epoch = NetworkEpoch::start().advance().unwrap();
        let descriptor = candidates(1, epoch).remove(0).endpoint;
        let addresses: Vec<SocketAddr> = [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "[::1]:443",
            "[fd00::1]:443",
            "[::ffff:127.0.0.1]:443",
            "[::ffff:10.0.0.1]:443",
            "[fe80::1%7]:443",
        ]
        .into_iter()
        .map(|address| address.parse().unwrap())
        .collect();
        let allowed = descriptor
            .clone()
            .with_addresses(addresses.clone())
            .unwrap();
        let mut foreign = allowed.clone();
        foreign.endpoint.id = 9;
        foreign.endpoint.trust_group = 9;
        let policy = EndpointPolicy::from_address_hints(&[foreign, allowed], 7, epoch).unwrap();
        assert!(policy.candidates.iter().all(|candidate| {
            candidate.endpoint == descriptor && candidate.network_epoch == epoch
        }));
        assert_eq!(
            policy
                .candidates
                .iter()
                .map(|candidate| candidate.address)
                .collect::<Vec<_>>(),
            addresses
        );
    }

    #[test]
    fn policy_constructors_reject_unusable_route_addresses() {
        let epoch = NetworkEpoch::start();
        let descriptor = candidates(1, epoch).remove(0).endpoint;
        let mut manual = EndpointPolicy {
            candidates: candidates(1, epoch),
            credential_trust_group: descriptor.trust_group,
            require_ech: false,
            require_unreliable: false,
        };
        for address in [
            "0.0.0.0:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[::]:443",
            "[ff02::1]:443",
            "[::ffff:0.0.0.0]:443",
            "[::ffff:224.0.0.1]:443",
            "[::ffff:255.255.255.255]:443",
        ] {
            let address = address.parse().unwrap();
            assert_eq!(
                EndpointPolicy::single(descriptor.clone(), address, epoch),
                Err(EngineError::EndpointResolutionFailed)
            );
            assert_eq!(
                EndpointPolicy::single_binding(descriptor.clone(), address, epoch, BindingId::H3),
                Err(EngineError::EndpointResolutionFailed)
            );
            let hints = descriptor.clone().with_addresses(vec![address]).unwrap();
            assert_eq!(
                EndpointPolicy::from_address_hints(&[hints], descriptor.trust_group, epoch),
                Err(EngineError::EndpointResolutionFailed)
            );
            manual.candidates[0].address = address;
            assert_eq!(
                manual.validate(),
                Err(EngineError::EndpointResolutionFailed)
            );
        }
        for address in [
            "127.0.0.1:0",
            "[::ffff:0.0.0.0]:0",
            "[::ffff:224.0.0.1]:0",
            "[::ffff:255.255.255.255]:0",
        ] {
            let address = address.parse().unwrap();
            assert_eq!(
                EndpointPolicy::single(descriptor.clone(), address, epoch),
                Err(EngineError::InvalidConfig)
            );
            assert_eq!(
                EndpointPolicy::single_binding(descriptor.clone(), address, epoch, BindingId::H3),
                Err(EngineError::InvalidConfig)
            );
            let hints = EndpointAddressHints {
                endpoint: descriptor.clone(),
                addresses: vec![address],
            };
            assert_eq!(
                EndpointPolicy::from_address_hints(&[hints], descriptor.trust_group, epoch),
                Err(EngineError::InvalidConfig)
            );
            manual.candidates[0].address = address;
            assert_eq!(manual.validate(), Err(EngineError::InvalidConfig));
        }
    }

    #[test]
    fn single_policy_keeps_mapped_unicast_and_scoped_routes() {
        let epoch = NetworkEpoch::start();
        let descriptor = candidates(1, epoch).remove(0).endpoint;
        for ip in ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "fe80::1"] {
            let address =
                SocketAddr::V6(std::net::SocketAddrV6::new(ip.parse().unwrap(), 443, 17, 7));
            let policy = EndpointPolicy::single(descriptor.clone(), address, epoch).unwrap();
            assert_eq!(policy.candidates[0].address, address);
            assert_eq!(policy.candidates[0].endpoint, descriptor);
        }
    }

    #[cfg(feature = "tls-rustls")]
    #[tokio::test]
    async fn mapped_invalid_routes_do_not_create_sockets_or_spend_quota() {
        struct CountingSocketFactory(Arc<AtomicUsize>);

        impl crate::SocketFactory for CountingSocketFactory {
            fn create_tcp(
                &self,
                _address: SocketAddr,
            ) -> Result<tokio::net::TcpSocket, EngineError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(EngineError::TransportUnavailable)
            }
        }

        let socket_calls = Arc::new(AtomicUsize::new(0));
        let certificate = rcgen::generate_simple_self_signed(vec!["endpoint.test".into()]).unwrap();
        let trust =
            crate::TrustPolicy::from_der_roots(7, vec![certificate.cert.der().to_vec()]).unwrap();
        let host = HostServices::new(
            Arc::new(crate::SystemBootstrapResolver),
            Arc::new(CountingSocketFactory(Arc::clone(&socket_calls))),
            vec![trust],
            1,
        )
        .unwrap();
        let connector = EndpointConnector::new(Arc::new(host));
        let epoch = NetworkEpoch::start();
        let mut policy = EndpointPolicy {
            candidates: candidates(1, epoch),
            credential_trust_group: 7,
            require_ech: false,
            require_unreliable: false,
        };
        for address in [
            "[::ffff:0.0.0.0]:443",
            "[::ffff:224.0.0.1]:443",
            "[::ffff:255.255.255.255]:443",
        ] {
            policy.candidates[0].address = address.parse().unwrap();
            let result = connector
                .connect(&policy, request(epoch, Duration::from_secs(1)))
                .await;
            assert!(matches!(result, Err(EngineError::EndpointResolutionFailed)));
            assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                connector.race.lock_state().unwrap().quota.attempts_used(),
                0
            );
            assert_eq!(
                connector.race.dial_slots.available_permits(),
                MAX_PARALLEL_CANDIDATES
            );
        }
    }

    #[tokio::test]
    async fn expired_parent_does_not_reserve_or_poll_a_candidate() {
        let race = immediate_race();
        let candidates = candidates(1, NetworkEpoch::start());
        let started = AtomicUsize::new(0);
        let result = race
            .race(
                &candidates,
                &[true],
                ConnectRequest {
                    deadline: Deadline::at(Instant::now()),
                    network_epoch: NetworkEpoch::start(),
                },
                |_, _| async {
                    started.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        assert_eq!(started.load(Ordering::SeqCst), 0);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 0);
    }

    #[tokio::test]
    async fn concurrent_operations_share_the_two_dial_limit() {
        let race = immediate_race();
        let candidates = candidates(2, NetworkEpoch::start());
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let started = AtomicUsize::new(0);
        let allowed = [true; 2];
        let mut first = Box::pin(race.race(
            &candidates,
            &allowed,
            request(NetworkEpoch::start(), Duration::from_secs(1)),
            |_, _| {
                let active = Arc::clone(&active);
                let peak_active = Arc::clone(&peak_active);
                async move {
                    let _active = ActiveAttempt::new(active, peak_active);
                    pending::<Result<(), EngineError>>().await
                }
            },
        ));
        let mut second = Box::pin(race.race(
            &candidates,
            &allowed,
            request(NetworkEpoch::start(), Duration::from_secs(1)),
            |_, _| {
                let active = Arc::clone(&active);
                let peak_active = Arc::clone(&peak_active);
                let started = &started;
                async move {
                    let _active = ActiveAttempt::new(active, peak_active);
                    started.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        tokio::select! {
            biased;
            result = &mut first => panic!("unexpected completion: {result:?}"),
            result = &mut second => panic!("unexpected completion: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(active.load(Ordering::SeqCst), 2);
        assert_eq!(started.load(Ordering::SeqCst), 0);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 2);
        drop(first);
        assert!(second.await.is_ok());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak_active.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn configured_one_attempt_and_one_parallel_dial_are_enforced() {
        let mut race = RaceController::with_limits(1, 1).unwrap();
        race.launch_delay = Duration::ZERO;
        let candidates = candidates(4, NetworkEpoch::start());
        let started = AtomicUsize::new(0);
        let result = race
            .race(
                &candidates,
                &[true; 4],
                request(NetworkEpoch::start(), Duration::from_secs(1)),
                |_, _| async {
                    started.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(EngineError::TransportUnavailable)
                },
            )
            .await;
        assert_eq!(result, Err(EngineError::TransportUnavailable));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(race.dial_slots.available_permits(), 1);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 1);
        assert!(RaceController::with_limits(3, 4).is_err());
        assert!(RaceController::with_limits(2, 5).is_err());
        assert!(RaceController::with_limits(2, 1).is_err());
    }

    #[tokio::test]
    async fn configured_parallel_one_waits_for_the_pending_first_dial() {
        let mut race = RaceController::with_limits(1, 4).unwrap();
        race.launch_delay = Duration::ZERO;
        let candidates = candidates(4, NetworkEpoch::start());
        let active = Arc::new(AtomicUsize::new(0));
        let peak_active = Arc::new(AtomicUsize::new(0));
        let result = race
            .race(
                &candidates,
                &[true; 4],
                request(NetworkEpoch::start(), Duration::from_millis(10)),
                |_, _| {
                    let active = Arc::clone(&active);
                    let peak_active = Arc::clone(&peak_active);
                    async move {
                        let _active = ActiveAttempt::new(active, peak_active);
                        pending::<Result<(), EngineError>>().await
                    }
                },
            )
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        assert_eq!(peak_active.load(Ordering::SeqCst), 1);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(race.lock_state().unwrap().quota.attempts_used(), 1);
    }
}
