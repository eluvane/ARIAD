use std::collections::VecDeque;

use ariad_core::EngineError;

use crate::admission::{Admission, AdmitDecision};

pub const EVENT_CAP: usize = 32;
pub const CONTROL_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEvent {
    Accepted,
    RefusedCapacity,
    RefusedDrain,
    ReloadKept,
    ReloadSwapped,
    Draining,
    TimedOut,
    ForcedClosed,
    ConnectionFailed,
}

impl LogEvent {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RefusedCapacity => "refused-capacity",
            Self::RefusedDrain => "refused-drain",
            Self::ReloadKept => "reload-kept",
            Self::ReloadSwapped => "reload-swapped",
            Self::Draining => "draining",
            Self::TimedOut => "timed-out",
            Self::ForcedClosed => "forced-closed",
            Self::ConnectionFailed => "connection-failed",
        }
    }
}

/// Saturating lifetime counters. Acceptance precedes TLS and authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    pub accepted: u64,
    pub refused: u64,
    pub timed_out: u64,
    pub reloads_ok: u64,
    pub reloads_failed: u64,
    pub forced_closed: u64,
    pub connections_failed: u64,
}

impl Metrics {
    fn saturating_inc(slot: &mut u64) {
        *slot = slot.saturating_add(1);
    }
}

/// Retains the most recent `EVENT_CAP` events in arrival order.
pub struct EventLog {
    items: VecDeque<LogEvent>,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            items: VecDeque::with_capacity(EVENT_CAP),
        }
    }

    pub fn push(&mut self, event: LogEvent) {
        if self.items.len() == EVENT_CAP {
            self.items.pop_front();
        }
        self.items.push_back(event);
    }

    pub fn snapshot(&self) -> Vec<&'static str> {
        self.items.iter().copied().map(LogEvent::name).collect()
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RuntimeLimits {
    admission: Admission,
    log: EventLog,
    metrics: Metrics,
}

impl RuntimeLimits {
    pub fn new(max_inflight: usize) -> Result<Self, EngineError> {
        Ok(Self {
            admission: Admission::new(max_inflight)?,
            log: EventLog::new(),
            metrics: Metrics::default(),
        })
    }

    pub fn try_accept(&mut self) -> AdmitDecision {
        let decision = self.admission.begin();
        let (counter, event) = match decision {
            AdmitDecision::Accepted => (&mut self.metrics.accepted, LogEvent::Accepted),
            AdmitDecision::AtCapacity => (&mut self.metrics.refused, LogEvent::RefusedCapacity),
            AdmitDecision::Draining => (&mut self.metrics.refused, LogEvent::RefusedDrain),
        };
        Metrics::saturating_inc(counter);
        self.log.push(event);
        decision
    }

    pub fn finish(&mut self) {
        self.admission.finish();
    }

    pub fn drain(&mut self) {
        self.admission.drain();
        self.log.push(LogEvent::Draining);
    }

    pub fn is_draining(&self) -> bool {
        self.admission.is_draining()
    }

    #[cfg(test)]
    pub fn inflight(&self) -> usize {
        self.admission.inflight()
    }

    pub fn note_timeout(&mut self) {
        Metrics::saturating_inc(&mut self.metrics.timed_out);
        self.log.push(LogEvent::TimedOut);
    }

    pub fn note_reload(&mut self, swapped: bool) {
        let (counter, event) = if swapped {
            (&mut self.metrics.reloads_ok, LogEvent::ReloadSwapped)
        } else {
            (&mut self.metrics.reloads_failed, LogEvent::ReloadKept)
        };
        Metrics::saturating_inc(counter);
        self.log.push(event);
    }

    pub fn note_forced_close(&mut self, count: usize) {
        self.metrics.forced_closed = self.metrics.forced_closed.saturating_add(count as u64);
        if count != 0 {
            self.log.push(LogEvent::ForcedClosed);
        }
    }

    pub fn note_connection_failed(&mut self) {
        Metrics::saturating_inc(&mut self.metrics.connections_failed);
        self.log.push(LogEvent::ConnectionFailed);
    }

    pub fn metrics(&self) -> Metrics {
        self.metrics
    }

    pub fn events(&self) -> Vec<&'static str> {
        self.log.snapshot()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Reload,
    Drain,
    Unknown,
    TooLarge,
}

/// Parses UTF-8 command bytes after trimming whitespace.
/// The `CONTROL_CAP` byte limit is checked before decoding or trimming.
/// This parser performs no command effect or peer authorization.
pub fn parse_control(bytes: &[u8]) -> Control {
    if bytes.len() > CONTROL_CAP {
        return Control::TooLarge;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Control::Unknown;
    };
    match text.trim() {
        "reload" => Control::Reload,
        "drain" => Control::Drain,
        _ => Control::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_and_drain_refuse_without_growing_the_log_forever() {
        let mut limits = RuntimeLimits::new(1).expect("cap");
        assert_eq!(limits.try_accept(), AdmitDecision::Accepted);
        assert_eq!(limits.try_accept(), AdmitDecision::AtCapacity);
        assert_eq!(limits.inflight(), 1);
        limits.drain();
        assert_eq!(limits.try_accept(), AdmitDecision::Draining);
        limits.finish();
        assert_eq!(limits.inflight(), 0);
        assert_eq!(limits.metrics().accepted, 1);
        assert_eq!(limits.metrics().refused, 2);
        for _ in 0..EVENT_CAP + 5 {
            limits.note_timeout();
        }
        assert_eq!(limits.events().len(), EVENT_CAP);
        assert!(limits.events().iter().all(|event| *event == "timed-out"));
    }

    #[test]
    fn zero_cap_is_invalid() {
        assert!(RuntimeLimits::new(0).is_err());
    }

    #[test]
    fn control_parser_drops_overlong_input() {
        assert_eq!(parse_control(b"reload\n"), Control::Reload);
        assert_eq!(parse_control(b"drain"), Control::Drain);
        assert_eq!(parse_control(b"x-forwarded-for: 1.1.1.1"), Control::Unknown);
        let mut secret = b"reload ".to_vec();
        secret.extend(std::iter::repeat_n(b'a', CONTROL_CAP));
        assert_eq!(parse_control(&secret), Control::TooLarge);
    }
}
