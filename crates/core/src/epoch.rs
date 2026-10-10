#![forbid(unsafe_code)]

use crate::error::EngineError;

/// Network generation used to reject observations from a different network state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEpoch(u64);

impl NetworkEpoch {
    pub const fn start() -> Self {
        Self(1)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next generation without wrapping. Overflow returns
    /// `ResourceLimitExceeded`; this value remains usable.
    pub fn advance(self) -> Result<Self, EngineError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(EngineError::ResourceLimitExceeded),
        }
    }

    pub const fn accepts(self, observed: u64) -> bool {
        self.0 == observed
    }

    /// Returns `next` when it equals or follows this generation.
    /// Earlier generations return `InvalidConfig`; no stored value is changed.
    pub fn observe(self, next: Self) -> Result<Self, EngineError> {
        if next.0 < self.0 {
            return Err(EngineError::InvalidConfig);
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_epoch_is_not_current() {
        let epoch = NetworkEpoch::start();
        assert!(epoch.accepts(1));
        assert!(!epoch.accepts(0));
        let next = epoch.advance().unwrap();
        assert!(next.accepts(2));
        assert!(!next.accepts(1));
    }

    #[test]
    fn epoch_does_not_wrap() {
        let epoch = NetworkEpoch(u64::MAX);
        assert_eq!(epoch.advance(), Err(EngineError::ResourceLimitExceeded));
        assert!(epoch.accepts(u64::MAX));
    }

    #[test]
    fn observer_accepts_duplicate_and_new_epochs_but_rejects_rollback() {
        let first = NetworkEpoch::start();
        let next = first.advance().unwrap();
        assert_eq!(first.observe(first), Ok(first));
        assert_eq!(first.observe(next), Ok(next));
        assert_eq!(next.observe(first), Err(EngineError::InvalidConfig));
    }
}
