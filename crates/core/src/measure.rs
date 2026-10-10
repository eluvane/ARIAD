#![forbid(unsafe_code)]

use std::collections::VecDeque;

use crate::error::EngineError;
use crate::failure::FailureClass;
use crate::version::PROTOCOL_VERSION;

pub const MEASURE_CAP: usize = 32;
/// Fixed local sample date encoded as `YYYYMMDD`.
pub const OBSERVED_ON: u32 = 20261007;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    LocalhostH2,
    EchRequiredUnavailable,
    CooldownSkip,
    StaleEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureOutcome {
    Reached,
    Unsupported,
    Cooled,
    StaleEpoch,
}

/// Caller-reported scenario outcome and security flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub scenario: Scenario,
    pub protocol_version: u16,
    /// Reported observation date encoded as `YYYYMMDD`.
    pub observed_on: u32,
    pub outcome: MeasureOutcome,
    pub failure: Option<FailureClass>,
    /// Whether the caller reports successful peer TLS verification.
    pub tls_verified: bool,
    /// Whether the caller reports replay of application data.
    pub replayed: bool,
}

impl Sample {
    /// Use the fixed local version and date for a caller-supplied result.
    ///
    /// Flags default to verified TLS and no replay. The caller owns the evidence
    /// for those claims.
    pub const fn local(
        scenario: Scenario,
        outcome: MeasureOutcome,
        failure: Option<FailureClass>,
    ) -> Self {
        Self {
            scenario,
            protocol_version: PROTOCOL_VERSION.0,
            observed_on: OBSERVED_ON,
            outcome,
            failure,
            tls_verified: true,
            replayed: false,
        }
    }
}

/// In-memory FIFO history of at most 32 reported samples.
pub struct MeasureLog {
    samples: VecDeque<Sample>,
}

impl MeasureLog {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MEASURE_CAP),
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Append a reported sample, replacing the oldest entry when full.
    ///
    /// Unverified or replayed reports return [`EngineError::ProtocolViolation`]
    /// without changing the history. Other fields are stored as supplied.
    pub fn record(&mut self, sample: Sample) -> Result<(), EngineError> {
        if !sample.tls_verified || sample.replayed {
            return Err(EngineError::ProtocolViolation);
        }
        if self.samples.len() == MEASURE_CAP {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        Ok(())
    }

    /// Iterate over copied samples from oldest to newest.
    pub fn samples(&self) -> impl Iterator<Item = Sample> + '_ {
        self.samples.iter().copied()
    }
}

impl Default for MeasureLog {
    fn default() -> Self {
        Self::new()
    }
}

pub const FIELD_OBSERVATIONS: &[Sample] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unverified_or_replayed_samples() {
        let mut log = MeasureLog::new();
        let mut sample = Sample::local(Scenario::LocalhostH2, MeasureOutcome::Reached, None);
        sample.tls_verified = false;
        assert_eq!(log.record(sample), Err(EngineError::ProtocolViolation));
        sample.tls_verified = true;
        sample.replayed = true;
        assert_eq!(log.record(sample), Err(EngineError::ProtocolViolation));
        assert!(log.is_empty());
    }

    #[test]
    fn field_dataset_is_empty_and_the_log_is_bounded() {
        assert!(FIELD_OBSERVATIONS.is_empty());
        let mut log = MeasureLog::new();
        for _ in 0..MEASURE_CAP + 4 {
            log.record(Sample::local(
                Scenario::LocalhostH2,
                MeasureOutcome::Reached,
                None,
            ))
            .unwrap();
        }
        assert_eq!(log.len(), MEASURE_CAP);
        assert!(
            log.samples()
                .all(|sample| sample.observed_on == OBSERVED_ON)
        );
        assert!(log.samples().all(|sample| sample.protocol_version == 0));
    }
}
