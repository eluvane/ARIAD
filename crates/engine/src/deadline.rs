use std::future::Future;
use std::time::Duration;

use ariad_core::EngineError;
use tokio::time::Instant;

/// An absolute expiration on Tokio's monotonic clock.
///
/// Copies keep the same expiration. Capped deadlines cannot extend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    expires_at: Instant,
}

impl Deadline {
    /// Sets the expiration to the current instant plus `duration`.
    ///
    /// Zero creates an expired deadline. Returns `InvalidConfig` if the clock
    /// cannot represent the requested expiration.
    pub fn after(duration: Duration) -> Result<Self, EngineError> {
        let expires_at = Instant::now()
            .checked_add(duration)
            .ok_or(EngineError::InvalidConfig)?;
        Ok(Self::at(expires_at))
    }

    /// Uses the supplied instant, including an expiration in the past.
    pub const fn at(expires_at: Instant) -> Self {
        Self { expires_at }
    }

    pub const fn expires_at(self) -> Instant {
        self.expires_at
    }

    /// Returns time left, or `DeadlineExceeded` at or after expiration.
    pub fn remaining(self) -> Result<Duration, EngineError> {
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(EngineError::DeadlineExceeded)
        } else {
            Ok(remaining)
        }
    }

    /// Uses the earlier of this expiration and the current instant plus `duration`.
    ///
    /// Returns `DeadlineExceeded` if this deadline is already expired, or
    /// `InvalidConfig` if the requested child expiration cannot be represented.
    pub fn cap(self, duration: Duration) -> Result<Self, EngineError> {
        self.remaining()?;
        let child = Self::after(duration)?;
        Ok(Self::at(self.expires_at.min(child.expires_at)))
    }

    /// Waits for an operation within this deadline.
    ///
    /// An expired deadline rejects the operation without polling it. Timeout or
    /// dropping this future drops the operation; effects from earlier polls remain.
    /// A poll that does not yield can run past expiration. Success is checked again
    /// after it finishes, while operation errors are returned unchanged.
    pub async fn run<T, F>(self, operation: F) -> Result<T, EngineError>
    where
        F: Future<Output = Result<T, EngineError>>,
    {
        self.remaining()?;
        let result = tokio::time::timeout_at(self.expires_at, operation)
            .await
            .map_err(|_| EngineError::DeadlineExceeded)?;
        match result {
            Ok(value) => {
                // A synchronous poll can complete after the timer expires.
                self.remaining()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn child_deadline_cannot_extend_parent() {
        let parent = Deadline::after(Duration::from_secs(3)).unwrap();
        let child = parent.cap(Duration::from_secs(10)).unwrap();
        assert_eq!(child.expires_at(), parent.expires_at());
        assert!(parent.cap(Duration::from_millis(10)).unwrap().expires_at() < parent.expires_at());
    }

    #[tokio::test]
    async fn expired_deadline_does_not_poll_operation() {
        let mut polled = false;
        let deadline = Deadline::at(Instant::now());
        let result = deadline
            .run(async {
                polled = true;
                Ok(())
            })
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
        assert!(!polled);
    }

    #[tokio::test]
    async fn ready_operation_cannot_return_success_after_deadline() {
        let deadline = Deadline::after(Duration::from_millis(20)).unwrap();
        let result = deadline
            .run(async {
                std::thread::sleep(Duration::from_millis(40));
                Ok(())
            })
            .await;
        assert_eq!(result, Err(EngineError::DeadlineExceeded));
    }
}
