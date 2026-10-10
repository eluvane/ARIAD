use crate::error::EngineError;

/// Exponential delay and attempt limit for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Base delay in milliseconds for attempt zero, before jitter scaling.
    pub initial_ms: u64,
    /// Maximum delay in milliseconds, applied before and after jitter scaling.
    pub cap_ms: u64,
    pub max_attempts_per_operation: u32,
}

impl RetryPolicy {
    /// Jitter input that preserves the full backoff delay.
    pub const JITTER_PPM_SCALE: u32 = 1_000_000;

    pub const fn lab_small() -> Self {
        Self {
            initial_ms: 1000,
            cap_ms: 60_000,
            max_attempts_per_operation: 4,
        }
    }

    pub fn validate(self) -> Result<(), EngineError> {
        if self.initial_ms == 0
            || self.cap_ms < self.initial_ms
            || self.max_attempts_per_operation == 0
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }
}

/// Attempt limits for each observation window and for runs without progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryQuotaPolicy {
    pub window_ms: u64,
    pub max_attempts_per_window: u32,
    pub max_attempts_without_progress: u32,
}

impl RetryQuotaPolicy {
    pub const fn lab_small() -> Self {
        Self {
            window_ms: 60_000,
            max_attempts_per_window: 16,
            max_attempts_without_progress: 8,
        }
    }

    pub fn validate(self) -> Result<(), EngineError> {
        if self.window_ms == 0
            || self.max_attempts_per_window == 0
            || self.max_attempts_without_progress == 0
            || self.max_attempts_without_progress > self.max_attempts_per_window
        {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }
}

/// Counts admitted attempts in windows observed by `reserve` calls.
/// The first call starts a window. A later call at or past its duration starts
/// a new window and clears both counters; queries do not advance the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryQuota {
    policy: RetryQuotaPolicy,
    window_started_ms: Option<u64>,
    last_observed_ms: u64,
    window_attempts: u32,
    attempts_without_progress: u32,
}

impl RetryQuota {
    pub const fn lab_small() -> Self {
        Self {
            policy: RetryQuotaPolicy::lab_small(),
            window_started_ms: None,
            last_observed_ms: 0,
            window_attempts: 0,
            attempts_without_progress: 0,
        }
    }

    pub fn new(policy: RetryQuotaPolicy) -> Result<Self, EngineError> {
        policy.validate()?;
        Ok(Self {
            policy,
            ..Self::lab_small()
        })
    }

    /// Charges one attempt before it starts; its outcome does not refund the charge.
    /// `now_ms` must be nondecreasing milliseconds in one clock domain.
    /// Clock rollback returns `InvalidConfig` without changing state. Exhausted
    /// quotas return `ResourceLimitExceeded` without charging an attempt, but
    /// the time observation is retained.
    pub fn reserve(&mut self, now_ms: u64) -> Result<(), EngineError> {
        self.observe_time(now_ms)?;
        if self.window_attempts >= self.policy.max_attempts_per_window
            || self.attempts_without_progress >= self.policy.max_attempts_without_progress
        {
            return Err(EngineError::ResourceLimitExceeded);
        }
        self.window_attempts += 1;
        self.attempts_without_progress += 1;
        Ok(())
    }

    /// Clears attempts without progress while retaining the window's total charge.
    pub fn record_progress(&mut self) {
        self.attempts_without_progress = 0;
    }

    /// Attempts charged in the last observed window.
    pub const fn attempts_used(&self) -> u32 {
        self.window_attempts
    }

    pub const fn attempts_without_progress(&self) -> u32 {
        self.attempts_without_progress
    }

    fn observe_time(&mut self, now_ms: u64) -> Result<(), EngineError> {
        if now_ms < self.last_observed_ms {
            return Err(EngineError::InvalidConfig);
        }
        self.last_observed_ms = now_ms;
        match self.window_started_ms {
            Some(started_at_ms) if now_ms.saturating_sub(started_at_ms) < self.policy.window_ms => {
            }
            _ => {
                self.window_started_ms = Some(now_ms);
                self.window_attempts = 0;
                self.attempts_without_progress = 0;
            }
        }
        Ok(())
    }
}

impl Default for RetryQuota {
    fn default() -> Self {
        Self::lab_small()
    }
}

/// Computes a delay for a zero-based attempt. Overflow saturates the exponential
/// base before the policy cap is applied. `jitter_ppm` is clamped to
/// [`RetryPolicy::JITTER_PPM_SCALE`]
/// and maps to 50% through 100% of that base, with integer rounding down.
/// The caller supplies jitter; this function draws no random value.
/// Invalid policy returns `InvalidConfig`; an attempt at or beyond its limit
/// returns `ResourceLimitExceeded`.
pub fn backoff_delay_ms(
    policy: RetryPolicy,
    attempt: u32,
    jitter_ppm: u32,
) -> Result<u64, EngineError> {
    policy.validate()?;
    if attempt >= policy.max_attempts_per_operation {
        return Err(EngineError::ResourceLimitExceeded);
    }

    let exponential_ms = 1u64
        .checked_shl(attempt)
        .and_then(|factor| policy.initial_ms.checked_mul(factor))
        .unwrap_or(u64::MAX);
    let base_ms = policy.cap_ms.min(exponential_ms);
    let clamped_jitter_ppm = jitter_ppm.min(RetryPolicy::JITTER_PPM_SCALE);

    let delay_scale_ppm =
        u64::from(RetryPolicy::JITTER_PPM_SCALE / 2) + u64::from(clamped_jitter_ppm) / 2;

    let scaled_delay_ms = u128::from(base_ms) * u128::from(delay_scale_ppm)
        / u128::from(RetryPolicy::JITTER_PPM_SCALE);
    let jittered_delay_ms = u64::try_from(scaled_delay_ms).unwrap_or(u64::MAX);
    Ok(policy.cap_ms.min(jittered_delay_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_zero_maximum_jitter_keeps_initial_delay() {
        assert_eq!(
            backoff_delay_ms(RetryPolicy::lab_small(), 0, 1_000_000),
            Ok(1000)
        );
    }

    #[test]
    fn attempt_zero_zero_jitter_halves_initial_delay() {
        assert_eq!(backoff_delay_ms(RetryPolicy::lab_small(), 0, 0), Ok(500));
    }

    #[test]
    fn jitter_clamps_and_rounds_down() {
        let policy = RetryPolicy {
            initial_ms: 1_000_003,
            cap_ms: 1_000_003,
            max_attempts_per_operation: 1,
        };
        for (jitter_ppm, expected_ms) in [
            (1, 500_001),
            (3, 500_002),
            (1_000_001, 1_000_003),
            (u32::MAX, 1_000_003),
        ] {
            assert_eq!(backoff_delay_ms(policy, 0, jitter_ppm), Ok(expected_ms));
        }
    }

    #[test]
    fn high_attempt_stays_within_cap() {
        let policy = RetryPolicy {
            initial_ms: 1_000,
            cap_ms: 60_000,
            max_attempts_per_operation: 32,
        };
        let delay = backoff_delay_ms(policy, 20, 1_000_000).expect("attempt allowed");
        assert!(delay <= 60_000);
    }

    #[test]
    fn attempt_at_lab_budget_is_rejected() {
        assert_eq!(
            backoff_delay_ms(RetryPolicy::lab_small(), 4, 0),
            Err(EngineError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn rejects_impossible_policy() {
        assert_eq!(
            RetryPolicy {
                initial_ms: 0,
                cap_ms: 60_000,
                max_attempts_per_operation: 4,
            }
            .validate(),
            Err(EngineError::InvalidConfig)
        );
        assert_eq!(
            RetryPolicy {
                initial_ms: 2_000,
                cap_ms: 1_000,
                max_attempts_per_operation: 4,
            }
            .validate(),
            Err(EngineError::InvalidConfig)
        );
        assert_eq!(
            RetryPolicy {
                initial_ms: 1_000,
                cap_ms: 60_000,
                max_attempts_per_operation: 0,
            }
            .validate(),
            Err(EngineError::InvalidConfig)
        );
        assert_eq!(
            backoff_delay_ms(
                RetryPolicy {
                    initial_ms: 0,
                    cap_ms: 0,
                    max_attempts_per_operation: 0,
                },
                0,
                0,
            ),
            Err(EngineError::InvalidConfig)
        );
    }

    #[test]
    fn huge_base_maximum_jitter_keeps_the_base() {
        let initial_ms = u64::MAX / 2;
        let policy = RetryPolicy {
            initial_ms,
            cap_ms: u64::MAX,
            max_attempts_per_operation: 1,
        };
        assert_eq!(backoff_delay_ms(policy, 0, 1_000_000), Ok(initial_ms));
    }

    #[test]
    fn source_does_not_embed_a_published_observation_as_timeout() {
        let src = include_str!("retry.rs").as_bytes();

        #[allow(clippy::byte_char_slices)]
        let observation = [b'4', b'2', b'0'];
        assert!(
            !src.windows(observation.len())
                .any(|window| window == observation)
        );
    }

    #[test]
    fn progress_keeps_the_global_window_budget() {
        let mut quota = RetryQuota::new(RetryQuotaPolicy {
            window_ms: 100,
            max_attempts_per_window: 3,
            max_attempts_without_progress: 2,
        })
        .unwrap();
        quota.reserve(0).unwrap();
        quota.reserve(1).unwrap();
        assert_eq!(quota.reserve(2), Err(EngineError::ResourceLimitExceeded));
        quota.record_progress();
        quota.reserve(3).unwrap();
        assert_eq!(quota.reserve(4), Err(EngineError::ResourceLimitExceeded));
        assert_eq!(quota.attempts_used(), 3);
        quota.reserve(100).unwrap();
        assert_eq!(quota.attempts_used(), 1);
    }

    #[test]
    fn network_flapping_does_not_reset_retry_quota() {
        let mut quota = RetryQuota::new(RetryQuotaPolicy {
            window_ms: 100,
            max_attempts_per_window: 2,
            max_attempts_without_progress: 2,
        })
        .unwrap();
        let first = crate::epoch::NetworkEpoch::start();
        quota.reserve(0).unwrap();
        let second = first.advance().unwrap();
        quota.reserve(1).unwrap();
        assert_ne!(first, second);
        assert_eq!(quota.reserve(2), Err(EngineError::ResourceLimitExceeded));
    }

    #[test]
    fn clock_rollback_and_invalid_quota_fail_without_spending() {
        let mut quota = RetryQuota::lab_small();
        quota.reserve(10).unwrap();
        assert_eq!(quota.reserve(9), Err(EngineError::InvalidConfig));
        assert_eq!(quota.attempts_used(), 1);
        assert_eq!(
            RetryQuota::new(RetryQuotaPolicy {
                window_ms: 1,
                max_attempts_per_window: 1,
                max_attempts_without_progress: 2,
            }),
            Err(EngineError::InvalidConfig)
        );
    }
}
