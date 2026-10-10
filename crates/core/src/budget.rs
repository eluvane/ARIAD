use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::EngineError;
use crate::path_select::{MAX_CANDIDATE_ATTEMPTS, MAX_PARALLEL_CANDIDATES};

/// Shared quota for caller-reported retained allocation bytes.
///
/// Clones share usage and the limit. Callers charge allocation capacity before
/// allocation and keep the guard until that storage is released. This does not
/// measure process RSS.
#[derive(Debug, Clone)]
pub struct MemoryBudget {
    state: Arc<MemoryBudgetState>,
}

#[derive(Debug)]
struct MemoryBudgetState {
    limit_bytes: usize,
    // Admission does not publish or synchronize access to retained data.
    reserved_bytes: AtomicUsize,
}

/// Releases its remaining byte charge when dropped.
#[derive(Debug)]
#[must_use = "hold the reservation while the retained allocation is alive"]
pub struct MemoryReservation {
    budget: MemoryBudget,
    reserved_bytes: usize,
}

/// Holds one allocation's charge in the selected quotas until drop.
#[derive(Debug)]
#[must_use = "hold the reservation while the retained allocation is alive"]
pub struct ScopedMemoryReservation {
    process: MemoryReservation,
    // When present, session keeps the same charge as process between calls.
    session: Option<MemoryReservation>,
}

impl MemoryBudget {
    /// Creates an unused quota with a byte limit. Zero returns `InvalidConfig`.
    pub fn new(limit: usize) -> Result<Self, EngineError> {
        if limit == 0 {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self {
            state: Arc::new(MemoryBudgetState {
                limit_bytes: limit,
                reserved_bytes: AtomicUsize::new(0),
            }),
        })
    }

    /// Reserves bytes without allocating payload storage. Zero bytes are allowed.
    /// Exceeding the limit or overflowing usage returns `ResourceLimitExceeded`
    /// without changing usage.
    pub fn try_acquire(&self, bytes: usize) -> Result<MemoryReservation, EngineError> {
        if bytes != 0 {
            self.state
                .reserved_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved_bytes| {
                    reserved_bytes
                        .checked_add(bytes)
                        .filter(|total_bytes| *total_bytes <= self.state.limit_bytes)
                })
                .map_err(|_| EngineError::ResourceLimitExceeded)?;
        }
        Ok(MemoryReservation {
            budget: self.clone(),
            reserved_bytes: bytes,
        })
    }

    /// Returns only after both quotas admit the allocation. A second-quota
    /// failure releases the first reservation. Shared aliases are charged once.
    pub fn try_acquire_scoped(
        &self,
        session: &Self,
        bytes: usize,
    ) -> Result<ScopedMemoryReservation, EngineError> {
        let process = self.try_acquire(bytes)?;
        let session = if Arc::ptr_eq(&self.state, &session.state) {
            None
        } else {
            Some(session.try_acquire(bytes)?)
        };
        Ok(ScopedMemoryReservation { process, session })
    }

    /// Returns a snapshot of reserved bytes across all clones.
    pub fn used(&self) -> usize {
        self.state.reserved_bytes.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> usize {
        self.state.limit_bytes
    }
}

impl MemoryReservation {
    pub const fn bytes(&self) -> usize {
        self.reserved_bytes
    }

    /// Use only after retained allocation capacity is reduced. Consuming bytes
    /// from a buffer does not release its backing allocation.
    /// Increasing the charge returns `InvalidConfig` without changing usage.
    pub fn shrink_to(&mut self, bytes: usize) -> Result<(), EngineError> {
        let released_bytes = self
            .reserved_bytes
            .checked_sub(bytes)
            .ok_or(EngineError::InvalidConfig)?;
        self.reserved_bytes = bytes;
        self.release_bytes(released_bytes);
        Ok(())
    }

    /// Releases the charge. The caller remains responsible for the allocation.
    pub fn release(self) {
        drop(self);
    }

    fn release_bytes(&self, bytes: usize) {
        if bytes != 0 {
            let _ = self
                .budget
                .state
                .reserved_bytes
                .fetch_sub(bytes, Ordering::Relaxed);
        }
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        self.release_bytes(self.reserved_bytes);
    }
}

impl ScopedMemoryReservation {
    /// Returns the allocation's charge, rather than the sum across both quotas.
    pub const fn bytes(&self) -> usize {
        self.process.bytes()
    }

    /// Shrinks both quota charges under [`MemoryReservation::shrink_to`]'s constraints.
    /// Increasing the charge returns `InvalidConfig` without changing either quota.
    pub fn shrink_to(&mut self, bytes: usize) -> Result<(), EngineError> {
        if let Some(session) = &mut self.session {
            session.shrink_to(bytes)?;
        }
        self.process.shrink_to(bytes)
    }

    pub fn release(self) {
        drop(self);
    }
}

/// Application byte and object limits. Validation does not reserve resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits {
    /// Maximum bytes in one control message.
    pub control_message_max: usize,
    pub decoded_header_bytes: usize,
    pub decoded_header_fields: usize,
    /// Maximum queued stream bytes in each direction.
    pub stream_queue_per_direction: usize,
    /// Retained application byte limit for one session.
    pub session_application_budget: usize,
    /// Control-work byte allowance within the application budgets.
    pub control_reserve: usize,
    pub active_flows_per_session: usize,
    pub udp_queue_bytes: usize,
    pub udp_queue_datagrams: usize,
    /// Application datagram byte ceiling, bounded by [`Self::UDP_PAYLOAD_ABSOLUTE_CEILING`].
    /// Binding overhead and negotiated limits can reduce the accepted payload; see
    /// [`UdpAssociation::max_payload`](crate::UdpAssociation::max_payload).
    pub udp_payload_absolute_max: usize,
    pub pending_egress_opens: usize,
    pub pending_handshakes: usize,
    pub active_sessions: usize,
    /// Retained application byte limit shared across sessions.
    pub global_application_budget: usize,
    pub parallel_candidate_dials: usize,
    pub candidate_attempts: usize,
}

impl BudgetLimits {
    /// Conservative API UDP payload ceiling in bytes. Path and binding limits may be lower.
    pub const UDP_PAYLOAD_ABSOLUTE_CEILING: usize = 65_507;

    pub const fn lab_small() -> Self {
        Self {
            control_message_max: 16 * 1024,
            decoded_header_bytes: 32 * 1024,
            decoded_header_fields: 64,
            stream_queue_per_direction: 128 * 1024,
            session_application_budget: 4 * 1024 * 1024,
            control_reserve: 64 * 1024,
            active_flows_per_session: 64,
            udp_queue_bytes: 64 * 1024,
            udp_queue_datagrams: 64,
            udp_payload_absolute_max: Self::UDP_PAYLOAD_ABSOLUTE_CEILING,
            pending_egress_opens: 8,
            pending_handshakes: 64,
            active_sessions: 64,
            global_application_budget: 256 * 1024 * 1024,
            parallel_candidate_dials: MAX_PARALLEL_CANDIDATES,
            candidate_attempts: MAX_CANDIDATE_ATTEMPTS,
        }
    }

    /// Checks nonzero limits, local budget relationships, the UDP ceiling, and
    /// overflow of combined session limits. Session ceilings need not fit in
    /// the global budget at once.
    pub fn validate(self) -> Result<(), EngineError> {
        if self.has_zero_cap()
            || self.control_reserve > self.session_application_budget
            || self.control_message_max > self.session_application_budget
            || self.stream_queue_per_direction > self.session_application_budget
            || self.udp_queue_bytes > self.session_application_budget
            || self.control_reserve > self.global_application_budget
            || self.udp_payload_absolute_max > Self::UDP_PAYLOAD_ABSOLUTE_CEILING
            || self.parallel_candidate_dials > self.candidate_attempts
            || self
                .active_sessions
                .checked_mul(self.session_application_budget)
                .is_none()
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }

    fn has_zero_cap(self) -> bool {
        self.control_message_max == 0
            || self.decoded_header_bytes == 0
            || self.decoded_header_fields == 0
            || self.stream_queue_per_direction == 0
            || self.session_application_budget == 0
            || self.control_reserve == 0
            || self.active_flows_per_session == 0
            || self.udp_queue_bytes == 0
            || self.udp_queue_datagrams == 0
            || self.udp_payload_absolute_max == 0
            || self.pending_egress_opens == 0
            || self.pending_handshakes == 0
            || self.active_sessions == 0
            || self.global_application_budget == 0
            || self.parallel_candidate_dials == 0
            || self.candidate_attempts == 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;

    use super::*;

    #[test]
    fn zero_memory_limit_is_rejected() {
        assert_eq!(
            MemoryBudget::new(0).unwrap_err(),
            EngineError::InvalidConfig
        );
    }

    #[test]
    fn memory_reservations_release_only_their_remaining_bytes() {
        let budget = MemoryBudget::new(8).unwrap();
        let mut first = budget.try_acquire(6).unwrap();
        assert_eq!(first.bytes(), 6);
        assert_eq!(budget.used(), 6);
        assert_eq!(budget.limit(), 8);
        assert_eq!(
            budget.try_acquire(3).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(budget.used(), 6);

        let second = budget.try_acquire(2).unwrap();
        first.shrink_to(4).unwrap();
        assert_eq!(first.bytes(), 4);
        assert_eq!(budget.used(), 6);
        first.shrink_to(4).unwrap();
        assert_eq!(first.shrink_to(5), Err(EngineError::InvalidConfig));
        assert_eq!(budget.used(), 6);
        second.release();
        assert_eq!(budget.used(), 4);
        drop(first);
        assert_eq!(budget.used(), 0);
        let mut full = budget.try_acquire(8).unwrap();
        full.shrink_to(0).unwrap();
        assert_eq!(budget.used(), 0);
        let replacement = budget.try_acquire(8).unwrap();
        full.release();
        assert_eq!(budget.used(), 8);
        drop(replacement);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn checked_admission_rejects_integer_overflow() {
        let budget = MemoryBudget::new(usize::MAX).unwrap();
        let mut full = budget.try_acquire(usize::MAX).unwrap();
        assert_eq!(
            budget.try_acquire(1).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(budget.used(), usize::MAX);
        full.shrink_to(usize::MAX - 1).unwrap();
        let last = budget.try_acquire(1).unwrap();
        assert_eq!(budget.used(), usize::MAX);
        drop(last);
        assert_eq!(budget.used(), usize::MAX - 1);
        drop(full);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn zero_byte_reservation_is_valid_at_capacity() {
        let budget = MemoryBudget::new(1).unwrap();
        let full = budget.try_acquire(1).unwrap();
        let empty = budget.try_acquire(0).unwrap();
        assert_eq!(empty.bytes(), 0);
        empty.release();
        assert_eq!(budget.used(), 1);
        full.release();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn cloned_budget_shares_usage_and_survives_original_owner() {
        let budget = MemoryBudget::new(4).unwrap();
        let observer = budget.clone();
        let permit = budget.try_acquire(4).unwrap();
        drop(budget);
        assert_eq!(observer.used(), 4);
        assert_eq!(
            observer.try_acquire(1).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        drop(permit);
        assert_eq!(observer.used(), 0);
    }

    #[test]
    fn scoped_session_denial_rolls_back_process_admission() {
        let process = MemoryBudget::new(16).unwrap();
        let session = MemoryBudget::new(4).unwrap();
        let retained = session.try_acquire(3).unwrap();
        assert_eq!(
            process.try_acquire_scoped(&session, 2).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 3);
        drop(retained);
        let process_full = process.try_acquire(16).unwrap();
        assert_eq!(
            process.try_acquire_scoped(&session, 1).unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        assert_eq!(process.used(), 16);
        assert_eq!(session.used(), 0);
        drop(process_full);
        assert_eq!(process.used(), 0);
    }

    #[test]
    fn scoped_shrink_and_drop_preserve_other_reservations() {
        let process = MemoryBudget::new(16).unwrap();
        let session = MemoryBudget::new(8).unwrap();
        let process_only = process.try_acquire(2).unwrap();
        let session_only = session.try_acquire(1).unwrap();
        let mut scoped = process.try_acquire_scoped(&session, 6).unwrap();
        assert_eq!(scoped.bytes(), 6);
        assert_eq!(process.used(), 8);
        assert_eq!(session.used(), 7);
        scoped.shrink_to(3).unwrap();
        assert_eq!(process.used(), 5);
        assert_eq!(session.used(), 4);
        assert_eq!(scoped.shrink_to(4), Err(EngineError::InvalidConfig));
        assert_eq!(process.used(), 5);
        assert_eq!(session.used(), 4);
        scoped.release();
        assert_eq!(process.used(), 2);
        assert_eq!(session.used(), 1);
        drop(process_only);
        drop(session_only);
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[test]
    fn scoped_aliases_charge_the_shared_budget_once() {
        let process = MemoryBudget::new(4).unwrap();
        let session = process.clone();
        let mut scoped = process.try_acquire_scoped(&session, 4).unwrap();
        assert_eq!(process.used(), 4);
        assert_eq!(session.used(), 4);
        scoped.shrink_to(2).unwrap();
        assert_eq!(process.used(), 2);
        assert_eq!(scoped.shrink_to(3), Err(EngineError::InvalidConfig));
        assert_eq!(scoped.bytes(), 2);
        assert_eq!(process.used(), 2);
        scoped.release();
        assert_eq!(process.used(), 0);
        assert_eq!(session.used(), 0);
    }

    #[test]
    fn concurrent_admission_never_exceeds_the_byte_limit() {
        const WORKER_COUNT: usize = 8;
        const LIMIT_BYTES: usize = 3;
        let budget = MemoryBudget::new(LIMIT_BYTES).unwrap();
        let start = Barrier::new(WORKER_COUNT + 1);
        let held = Barrier::new(WORKER_COUNT + 1);
        let release = Barrier::new(WORKER_COUNT + 1);
        let admitted_count = AtomicUsize::new(0);
        let (observed_bytes, observed_count) = std::thread::scope(|scope| {
            for _ in 0..WORKER_COUNT {
                scope.spawn(|| {
                    start.wait();
                    let reservation = budget.try_acquire(1);
                    if reservation.is_ok() {
                        let _ = admitted_count.fetch_add(1, Ordering::Relaxed);
                    }
                    held.wait();
                    release.wait();
                    drop(reservation);
                });
            }
            start.wait();
            held.wait();
            let observed = (budget.used(), admitted_count.load(Ordering::Relaxed));
            release.wait();
            observed
        });
        assert_eq!(observed_bytes, LIMIT_BYTES);
        assert_eq!(observed_count, LIMIT_BYTES);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn lab_small_is_valid_when_session_ceilings_fill_the_global_budget() {
        let limits = BudgetLimits::lab_small();
        let combined_session_bytes = limits
            .active_sessions
            .checked_mul(limits.session_application_budget)
            .unwrap();
        assert_eq!(combined_session_bytes, limits.global_application_budget);
        limits.validate().unwrap();
    }

    #[test]
    fn zeroed_limits_are_rejected() {
        let limits = BudgetLimits {
            control_message_max: 0,
            decoded_header_bytes: 0,
            decoded_header_fields: 0,
            stream_queue_per_direction: 0,
            session_application_budget: 0,
            control_reserve: 0,
            active_flows_per_session: 0,
            udp_queue_bytes: 0,
            udp_queue_datagrams: 0,
            udp_payload_absolute_max: 0,
            pending_egress_opens: 0,
            pending_handshakes: 0,
            active_sessions: 0,
            global_application_budget: 0,
            parallel_candidate_dials: 0,
            candidate_attempts: 0,
        };
        assert_eq!(limits.validate().unwrap_err(), EngineError::InvalidConfig);
    }
}
