#![forbid(unsafe_code)]

use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    EndpointDns,
    CandidateTransport,
    PeerTrust,
    Authentication,
    TargetConnect,
    EgressPolicy,
    UnknownNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureScope {
    Candidate,
    Endpoint,
    FailureDomain,
    Target,
    Credential,
}

pub fn failure_scope(class: FailureClass) -> FailureScope {
    failure_policy(class).0
}

/// Allows endpoint retry for DNS, transport, and unknown-network failures.
/// Trust, credential, target, and policy failures stop endpoint retry.
pub fn may_retry_other_endpoint(class: FailureClass) -> bool {
    failure_policy(class).1
}

fn failure_policy(class: FailureClass) -> (FailureScope, bool) {
    match class {
        FailureClass::EndpointDns => (FailureScope::Endpoint, true),
        FailureClass::CandidateTransport => (FailureScope::Candidate, true),
        FailureClass::PeerTrust => (FailureScope::Endpoint, false),
        FailureClass::Authentication => (FailureScope::Credential, false),
        FailureClass::TargetConnect | FailureClass::EgressPolicy => (FailureScope::Target, false),
        FailureClass::UnknownNetwork => (FailureScope::FailureDomain, true),
    }
}

/// Maps connection errors to cooldown and retry categories.
/// Returns `None` for errors outside those categories, including cancellation.
pub fn connect_failure_class(error: EngineError) -> Option<FailureClass> {
    match error {
        EngineError::EndpointResolutionFailed => Some(FailureClass::EndpointDns),
        EngineError::TransportUnavailable | EngineError::DeadlineExceeded => {
            Some(FailureClass::CandidateTransport)
        }
        EngineError::PeerIdentityFailed => Some(FailureClass::PeerTrust),
        EngineError::AuthenticationDenied | EngineError::AuthorizationUnavailable => {
            Some(FailureClass::Authentication)
        }
        EngineError::TargetConnectFailed | EngineError::TargetResolutionFailed => {
            Some(FailureClass::TargetConnect)
        }
        EngineError::EgressDenied => Some(FailureClass::EgressPolicy),
        EngineError::NoReachableTrustedPath => Some(FailureClass::UnknownNetwork),
        _ => None,
    }
}

/// Selects by fixed category precedence, independent of race completion order.
/// Cancellation and deadline errors take precedence over the other categories.
pub fn preferred_connect_error(first: EngineError, second: EngineError) -> EngineError {
    if connect_error_priority(second) < connect_error_priority(first) {
        second
    } else {
        first
    }
}

fn connect_error_priority(error: EngineError) -> u8 {
    match error {
        EngineError::Cancelled => 0,
        EngineError::DeadlineExceeded => 1,
        EngineError::PeerIdentityFailed => 2,
        EngineError::AuthenticationDenied => 3,
        EngineError::AuthorizationUnavailable => 4,
        EngineError::InvalidConfig => 5,
        EngineError::ProtocolViolation => 6,
        EngineError::UnsupportedCapability => 7,
        EngineError::ResourceLimitExceeded => 8,
        EngineError::EndpointResolutionFailed => 9,
        EngineError::TransportUnavailable => 10,
        EngineError::TransferStalled => 11,
        EngineError::RemoteReset => 12,
        EngineError::TruncatedStream => 13,
        EngineError::MessageTooLarge => 14,
        EngineError::EgressDenied => 15,
        EngineError::TargetResolutionFailed => 16,
        EngineError::TargetConnectFailed => 17,
        EngineError::NoReachableTrustedPath => 18,
    }
}

#[cfg(test)]
mod tests {
    use super::{EngineError, FailureClass, FailureScope, failure_scope, may_retry_other_endpoint};

    const TABLE: &[(FailureClass, FailureScope, bool)] = &[
        (FailureClass::EndpointDns, FailureScope::Endpoint, true),
        (
            FailureClass::CandidateTransport,
            FailureScope::Candidate,
            true,
        ),
        (FailureClass::PeerTrust, FailureScope::Endpoint, false),
        (
            FailureClass::Authentication,
            FailureScope::Credential,
            false,
        ),
        (FailureClass::TargetConnect, FailureScope::Target, false),
        (FailureClass::EgressPolicy, FailureScope::Target, false),
        (
            FailureClass::UnknownNetwork,
            FailureScope::FailureDomain,
            true,
        ),
    ];

    #[test]
    fn table_covers_every_class_for_both_functions() {
        let mut seen = [false; 7];
        for &(class, scope, retry_other_endpoint) in TABLE {
            let index = class_index(class);
            assert!(!seen[index], "duplicate {class:?}");
            seen[index] = true;
            assert_eq!(failure_scope(class), scope, "{class:?}");
            assert_eq!(
                may_retry_other_endpoint(class),
                retry_other_endpoint,
                "{class:?}"
            );
        }
        assert!(seen.iter().all(|present| *present));
        assert_eq!(TABLE.len(), seen.len());
    }

    const fn class_index(class: FailureClass) -> usize {
        match class {
            FailureClass::EndpointDns => 0,
            FailureClass::CandidateTransport => 1,
            FailureClass::PeerTrust => 2,
            FailureClass::Authentication => 3,
            FailureClass::TargetConnect => 4,
            FailureClass::EgressPolicy => 5,
            FailureClass::UnknownNetwork => 6,
        }
    }

    #[test]
    fn connect_failure_precedence_is_independent_of_completion_order() {
        use super::{connect_failure_class, preferred_connect_error};
        assert_eq!(
            connect_failure_class(EngineError::PeerIdentityFailed),
            Some(FailureClass::PeerTrust)
        );
        assert_eq!(
            connect_failure_class(EngineError::TargetConnectFailed),
            Some(FailureClass::TargetConnect)
        );
        for errors in [
            [
                EngineError::TransportUnavailable,
                EngineError::PeerIdentityFailed,
            ],
            [
                EngineError::PeerIdentityFailed,
                EngineError::TransportUnavailable,
            ],
        ] {
            assert_eq!(
                preferred_connect_error(errors[0], errors[1]),
                EngineError::PeerIdentityFailed
            );
        }
        assert_eq!(
            preferred_connect_error(EngineError::PeerIdentityFailed, EngineError::Cancelled),
            EngineError::Cancelled
        );
        assert_eq!(
            preferred_connect_error(EngineError::TargetConnectFailed, EngineError::EgressDenied),
            EngineError::EgressDenied
        );
        assert_eq!(
            preferred_connect_error(EngineError::EgressDenied, EngineError::TargetConnectFailed),
            EngineError::EgressDenied
        );
    }
}
