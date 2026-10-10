#![forbid(unsafe_code)]

use ariad_core::EngineError;

/// Counts bytes accepted locally, with no retained payload or delivery proof.
#[derive(Debug)]
pub struct SentCount {
    accepted: u64,
}

impl SentCount {
    pub const fn new() -> Self {
        Self { accepted: 0 }
    }

    pub const fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Adds accepted bytes. Zero leaves the count unchanged.
    /// Overflow returns `ResourceLimitExceeded` and preserves the count.
    pub fn record(&mut self, n: u64) -> Result<(), EngineError> {
        if n == 0 {
            return Ok(());
        }
        self.accepted = self
            .accepted
            .checked_add(n)
            .ok_or(EngineError::ResourceLimitExceeded)?;
        Ok(())
    }

    /// Always returns `ProtocolViolation`, including when no bytes were accepted.
    pub fn bytes_for_new_connection(&self) -> Result<&'static [u8], EngineError> {
        Err(EngineError::ProtocolViolation)
    }
}

impl Default for SentCount {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_adds() {
        let mut sent = SentCount::new();
        assert_eq!(sent.accepted(), 0);
        assert_eq!(sent.record(0), Ok(()));
        assert_eq!(sent.accepted(), 0);
        assert_eq!(sent.record(5), Ok(()));
        assert_eq!(sent.record(7), Ok(()));
        assert_eq!(sent.accepted(), 12);
        assert_eq!(sent.record(0), Ok(()));
        assert_eq!(sent.accepted(), 12);
        assert_eq!(SentCount::default().accepted(), 0);
    }

    #[test]
    fn record_overflow_leaves_max() {
        let mut sent = SentCount::new();
        assert_eq!(sent.record(u64::MAX), Ok(()));
        assert_eq!(sent.record(1), Err(EngineError::ResourceLimitExceeded));
        assert_eq!(sent.accepted(), u64::MAX);
    }

    #[test]
    fn bytes_for_new_connection_is_protocol_violation() {
        let local = [7u8, 8, 9];
        let mut sent = SentCount::new();
        assert_eq!(
            sent.bytes_for_new_connection(),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(sent.record(local.len() as u64), Ok(()));
        assert_eq!(
            sent.bytes_for_new_connection(),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(local, [7, 8, 9]);
    }
}
