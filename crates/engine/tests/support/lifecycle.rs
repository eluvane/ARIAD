use ariad_core::EngineError;
use ariad_engine::{EngineResources, ShutdownReport};

pub fn assert_no_admission(resources: &EngineResources) {
    assert_eq!(resources.active_flows(), 0, "active flows");
    assert_eq!(resources.pending_opens(), 0, "pending opens");
    assert_eq!(resources.active_sessions(), 0, "active sessions");
    assert_eq!(resources.pending_handshakes(), 0, "pending handshakes");
}

pub fn assert_shutdown_complete(report: &ShutdownReport) {
    assert_eq!(report.pending_connects, 0);
    assert_eq!(report.failed_sessions, 0);
}

pub fn assert_tls_shutdown(result: Result<(), EngineError>, expected_error: Option<EngineError>) {
    // Driver shutdown can close TLS without close_notify after application EOF.
    assert!(
        matches!(result, Ok(()) | Err(EngineError::TransportUnavailable))
            || expected_error.is_some_and(|error| result == Err(error)),
        "{result:?}"
    );
}
