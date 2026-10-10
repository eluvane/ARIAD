#![forbid(unsafe_code)]

use ariad_core::{
    BindingId, Candidate, EngineError, FailureClass, FailureScope, RetryPolicy, SelectRequest,
    backoff_delay_ms, failure_scope, may_retry_other_endpoint, select_candidates,
};

fn h2() -> Candidate {
    Candidate {
        endpoint_id: 1,
        binding: BindingId::H2,
        failure_domain: 1,
        rtt_hint_ms: 10,
        supports_unreliable: true,
        supports_ech: true,
        exhausted: false,
        binding_allowed: true,
    }
}

fn request(require_ech: bool, require_unreliable: bool) -> SelectRequest {
    SelectRequest {
        require_ech,
        require_unreliable,
        max_parallel: 2,
        max_attempts: 4,
    }
}

#[test]
fn ech_required_keeps_only_the_supporting_index() {
    let candidates = [
        Candidate {
            rtt_hint_ms: 1,
            supports_ech: false,
            ..h2()
        },
        Candidate {
            endpoint_id: 2,
            failure_domain: 2,
            rtt_hint_ms: 500,
            supports_ech: true,
            ..h2()
        },
    ];
    assert_eq!(
        select_candidates(&candidates, request(true, false)),
        vec![1]
    );
}

#[test]
fn unreliable_required_drops_a_candidate_without_support() {
    let candidates = [
        Candidate {
            rtt_hint_ms: 1,
            supports_unreliable: false,
            ..h2()
        },
        Candidate {
            endpoint_id: 2,
            failure_domain: 2,
            rtt_hint_ms: 500,
            supports_unreliable: true,
            ..h2()
        },
    ];
    assert_eq!(
        select_candidates(&candidates, request(false, true)),
        vec![1]
    );
}

#[test]
fn exhausted_candidate_is_dropped() {
    let candidates = [
        Candidate {
            rtt_hint_ms: 1,
            exhausted: true,
            ..h2()
        },
        Candidate {
            endpoint_id: 2,
            failure_domain: 2,
            rtt_hint_ms: 500,
            exhausted: false,
            ..h2()
        },
    ];
    assert_eq!(
        select_candidates(&candidates, request(false, false)),
        vec![1]
    );
}

#[test]
fn max_parallel_keeps_two_of_five_failure_domains() {
    let mut candidates = Vec::with_capacity(5);
    for domain in 1u64..=5 {
        candidates.push(Candidate {
            endpoint_id: domain,
            failure_domain: domain,
            rtt_hint_ms: 10 + u32::try_from(domain).expect("domain fits"),
            ..h2()
        });
    }
    let selected = select_candidates(&candidates, request(false, false));
    assert_eq!(selected, vec![0, 1]);
}

#[test]
fn same_failure_domain_chooses_the_lower_rtt_index() {
    let candidates = [
        Candidate {
            failure_domain: 6,
            rtt_hint_ms: 50,
            ..h2()
        },
        Candidate {
            endpoint_id: 2,
            failure_domain: 6,
            rtt_hint_ms: 10,
            ..h2()
        },
    ];
    let selected = select_candidates(&candidates, request(false, false));
    assert_eq!(selected, vec![1, 0]);
}

#[test]
fn later_candidates_improve_a_selected_domain_after_the_domain_cap_is_full() {
    let candidates = [
        Candidate {
            rtt_hint_ms: 100,
            ..h2()
        },
        Candidate {
            endpoint_id: 2,
            failure_domain: 2,
            rtt_hint_ms: 80,
            ..h2()
        },
        Candidate {
            endpoint_id: 3,
            failure_domain: 3,
            rtt_hint_ms: 1,
            ..h2()
        },
        Candidate {
            endpoint_id: 4,
            rtt_hint_ms: 10,
            ..h2()
        },
    ];
    assert_eq!(
        select_candidates(&candidates, request(false, false)),
        vec![3, 1]
    );
    assert_eq!(
        select_candidates(
            &candidates,
            SelectRequest {
                max_attempts: 1,
                ..request(false, false)
            },
        ),
        vec![3]
    );
}

#[test]
fn failure_scope_and_endpoint_retry() {
    assert_eq!(
        failure_scope(FailureClass::EndpointDns),
        FailureScope::Endpoint
    );
    assert!(may_retry_other_endpoint(FailureClass::EndpointDns));

    assert_eq!(
        failure_scope(FailureClass::PeerTrust),
        FailureScope::Endpoint
    );
    assert!(!may_retry_other_endpoint(FailureClass::PeerTrust));

    assert_eq!(
        failure_scope(FailureClass::Authentication),
        FailureScope::Credential
    );
    assert!(!may_retry_other_endpoint(FailureClass::Authentication));

    assert_eq!(
        failure_scope(FailureClass::TargetConnect),
        FailureScope::Target
    );
    assert!(!may_retry_other_endpoint(FailureClass::TargetConnect));

    assert_eq!(
        failure_scope(FailureClass::EgressPolicy),
        FailureScope::Target
    );
    assert!(!may_retry_other_endpoint(FailureClass::EgressPolicy));

    assert_eq!(
        failure_scope(FailureClass::UnknownNetwork),
        FailureScope::FailureDomain
    );
    assert!(may_retry_other_endpoint(FailureClass::UnknownNetwork));

    assert_eq!(
        failure_scope(FailureClass::CandidateTransport),
        FailureScope::Candidate
    );
    assert!(may_retry_other_endpoint(FailureClass::CandidateTransport));
}

#[test]
fn lab_small_maximum_jitter_on_attempt_zero_keeps_initial_delay() {
    assert_eq!(
        backoff_delay_ms(RetryPolicy::lab_small(), 0, 1_000_000),
        Ok(1000)
    );
}

#[test]
fn lab_small_zero_jitter_on_attempt_zero_halves_initial_delay() {
    assert_eq!(backoff_delay_ms(RetryPolicy::lab_small(), 0, 0), Ok(500));
}

#[test]
fn lab_small_attempt_four_is_rejected() {
    assert_eq!(
        backoff_delay_ms(RetryPolicy::lab_small(), 4, 0),
        Err(EngineError::ResourceLimitExceeded)
    );
}

#[test]
fn attempt_three_delay_stays_within_cap() {
    assert_eq!(
        backoff_delay_ms(RetryPolicy::lab_small(), 3, 1_000_000),
        Ok(8_000)
    );
}

#[test]
fn custom_backoff_keeps_growing_after_attempt_sixteen() {
    let policy = RetryPolicy {
        initial_ms: 1,
        cap_ms: 1_000_000,
        max_attempts_per_operation: 32,
    };
    for (attempt, expected) in [(16, 65_536), (17, 131_072), (19, 524_288), (20, 1_000_000)] {
        assert_eq!(backoff_delay_ms(policy, attempt, 1_000_000), Ok(expected));
    }
    assert_eq!(backoff_delay_ms(policy, 20, 0), Ok(500_000));
}

#[test]
fn exponential_backoff_saturates_when_shift_or_product_overflows() {
    let policy = RetryPolicy {
        initial_ms: 1,
        cap_ms: u64::MAX,
        max_attempts_per_operation: u32::MAX,
    };
    assert_eq!(backoff_delay_ms(policy, 63, 1_000_000), Ok(1u64 << 63));
    for attempt in [64, u32::MAX - 1] {
        assert_eq!(backoff_delay_ms(policy, attempt, 1_000_000), Ok(u64::MAX));
    }
    assert_eq!(
        backoff_delay_ms(
            RetryPolicy {
                initial_ms: u64::MAX / 2 + 1,
                ..policy
            },
            1,
            1_000_000,
        ),
        Ok(u64::MAX)
    );
}

#[test]
fn zero_initial_delay_is_rejected() {
    let policy = RetryPolicy {
        initial_ms: 0,
        cap_ms: 1000,
        max_attempts_per_operation: 1,
    };
    assert_eq!(policy.validate(), Err(EngineError::InvalidConfig));
}
