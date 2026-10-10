#![forbid(unsafe_code)]

use ariad_core::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitDecision {
    Accepted,
    Draining,
    AtCapacity,
}

/// Counts admitted work without owning it. Pair each accepted `begin` with `finish`.
pub struct Admission {
    accepting: bool,
    inflight: usize,
    cap: usize,
}

impl Admission {
    /// Creates an accepting counter. A zero capacity is invalid.
    pub fn new(cap: usize) -> Result<Self, EngineError> {
        if cap == 0 {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self {
            accepting: true,
            inflight: 0,
            cap,
        })
    }

    pub fn begin(&mut self) -> AdmitDecision {
        if !self.accepting {
            return AdmitDecision::Draining;
        }
        if self.inflight >= self.cap {
            return AdmitDecision::AtCapacity;
        }
        self.inflight += 1;
        AdmitDecision::Accepted
    }

    /// Releases one slot. Calling this at zero leaves the count unchanged.
    pub fn finish(&mut self) {
        if self.inflight > 0 {
            self.inflight -= 1;
        }
    }

    /// Permanently refuses admissions without changing work already counted.
    pub fn drain(&mut self) {
        self.accepting = false;
    }

    #[cfg(test)]
    pub fn inflight(&self) -> usize {
        self.inflight
    }

    pub fn is_draining(&self) -> bool {
        !self.accepting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_cap_is_invalid_config() {
        assert!(matches!(Admission::new(0), Err(EngineError::InvalidConfig)));
    }

    #[test]
    fn begin_accepts_until_cap_then_at_capacity() {
        let mut admission = Admission::new(2).expect("cap");
        assert_eq!(admission.begin(), AdmitDecision::Accepted);
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.begin(), AdmitDecision::Accepted);
        assert_eq!(admission.inflight(), 2);
        assert_eq!(admission.begin(), AdmitDecision::AtCapacity);
        assert_eq!(admission.inflight(), 2);
    }

    #[test]
    fn drain_then_begin_is_draining_and_inflight_unchanged() {
        let mut admission = Admission::new(2).expect("cap");
        assert_eq!(admission.begin(), AdmitDecision::Accepted);
        admission.drain();
        assert!(admission.is_draining());
        assert_eq!(admission.inflight(), 1);
        assert_eq!(admission.begin(), AdmitDecision::Draining);
        assert_eq!(admission.inflight(), 1);
    }

    #[test]
    fn finish_after_drain_decrements() {
        let mut admission = Admission::new(2).expect("cap");
        assert_eq!(admission.begin(), AdmitDecision::Accepted);
        assert_eq!(admission.begin(), AdmitDecision::Accepted);
        admission.drain();
        admission.finish();
        assert_eq!(admission.inflight(), 1);
        assert!(admission.is_draining());
        admission.finish();
        assert_eq!(admission.inflight(), 0);
    }

    #[test]
    fn finish_at_zero_stays_zero() {
        let mut admission = Admission::new(1).expect("cap");
        admission.finish();
        assert_eq!(admission.inflight(), 0);
        admission.finish();
        assert_eq!(admission.inflight(), 0);
    }
}
