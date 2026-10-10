#![forbid(unsafe_code)]

use std::net::SocketAddr;

use crate::cooldown::{CooldownKey, CooldownTable, ScopedCooldownKey};
use crate::epoch::NetworkEpoch;
use crate::error::EngineError;
use crate::failure::{FailureClass, FailureScope, failure_scope};
use crate::path_select::{Candidate, SelectRequest, select_candidates};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateContext {
    pub endpoint_generation: u64,
    pub address: SocketAddr,
    pub network_epoch: NetworkEpoch,
}

/// Builds a key for candidate, endpoint, or failure-domain cooldowns.
/// Target and credential failures return `None` because this context does not
/// identify them. Candidate keys include the binding and dial address;
/// endpoint keys omit both, and domain keys use endpoint generation zero.
pub fn scoped_cooldown_key(
    candidate: &Candidate,
    context: CandidateContext,
    failure: FailureClass,
) -> Option<ScopedCooldownKey> {
    let scope = failure_scope(failure);
    let (id, endpoint_generation, binding, address) = match scope {
        FailureScope::Candidate => (
            candidate.endpoint_id,
            context.endpoint_generation,
            Some(candidate.binding),
            Some(context.address),
        ),
        FailureScope::Endpoint => (
            candidate.endpoint_id,
            context.endpoint_generation,
            None,
            None,
        ),
        FailureScope::FailureDomain => (candidate.failure_domain, 0, None, None),
        FailureScope::Target | FailureScope::Credential => return None,
    };
    Some(ScopedCooldownKey {
        scope,
        id,
        endpoint_generation,
        binding,
        address,
        failure,
        network_epoch: context.network_epoch,
    })
}

/// Checks scoped network and trust cooldowns in the supplied candidate context.
pub fn candidate_cooled_in_epoch(
    candidate: &Candidate,
    context: CandidateContext,
    table: &CooldownTable,
    now_ms: u64,
) -> bool {
    [
        FailureClass::EndpointDns,
        FailureClass::CandidateTransport,
        FailureClass::PeerTrust,
        FailureClass::UnknownNetwork,
    ]
    .into_iter()
    .filter_map(|failure| scoped_cooldown_key(candidate, context, failure))
    .any(|key| table.cooled_scoped(key, now_ms))
}

/// Returns attempt indices into `candidates` for the current epoch.
/// Uses the attempt limit, capped at `MAX_CANDIDATE_ATTEMPTS`, rather than the
/// parallel limit. Zero parallelism disables selection. Array length mismatches
/// return `InvalidConfig`.
pub fn select_attempts_for_epoch(
    candidates: &[Candidate],
    epochs: &[u64],
    cooled: &[bool],
    current: NetworkEpoch,
    request: SelectRequest,
) -> Result<Vec<usize>, EngineError> {
    select_for_epoch(candidates, epochs, cooled, current, request.for_attempts())
}

/// Selects current, uncooled candidates and returns indices into the original slice.
/// `epochs` and `cooled` must each have one entry per candidate, or this returns
/// `InvalidConfig`. No eligible candidates is a successful empty result.
pub fn select_for_epoch(
    candidates: &[Candidate],
    epochs: &[u64],
    cooled: &[bool],
    current: NetworkEpoch,
    request: SelectRequest,
) -> Result<Vec<usize>, EngineError> {
    if candidates.len() != epochs.len() || candidates.len() != cooled.len() {
        return Err(EngineError::InvalidConfig);
    }
    let mut current_candidates = Vec::new();
    let mut source_indices = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if !current.accepts(epochs[index]) || cooled[index] {
            continue;
        }
        current_candidates.push(candidate.clone());
        source_indices.push(index);
    }
    let selected_indices = select_candidates(&current_candidates, request);
    Ok(selected_indices
        .into_iter()
        .map(|index| source_indices[index])
        .collect())
}

/// Returns flags for unscoped candidate, endpoint, and failure-domain cooldowns.
pub fn cooled_flags(candidates: &[Candidate], table: &CooldownTable, now_ms: u64) -> Vec<bool> {
    candidates
        .iter()
        .map(|candidate| {
            [
                CooldownKey {
                    scope: FailureScope::Candidate,
                    id: candidate.endpoint_id,
                },
                CooldownKey {
                    scope: FailureScope::Endpoint,
                    id: candidate.endpoint_id,
                },
                CooldownKey {
                    scope: FailureScope::FailureDomain,
                    id: candidate.failure_domain,
                },
            ]
            .iter()
            .any(|key| table.cooled(*key, now_ms))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::BindingId;
    use crate::cooldown::CooldownTable;
    use crate::failure::{FailureClass, may_retry_other_endpoint};

    fn candidate(id: u64, rtt_hint_ms: u32) -> Candidate {
        Candidate {
            endpoint_id: id,
            binding: BindingId::H2,
            failure_domain: id,
            rtt_hint_ms,
            supports_unreliable: false,
            supports_ech: false,
            exhausted: false,
            binding_allowed: true,
        }
    }

    fn request() -> SelectRequest {
        SelectRequest {
            require_unreliable: false,
            require_ech: false,
            max_parallel: 2,
            max_attempts: 4,
        }
    }

    #[test]
    fn cooldown_and_stale_epoch_drop_out_of_selection() {
        let candidates = [candidate(1, 10), candidate(2, 20)];
        let mut table = CooldownTable::new();
        table
            .record(
                CooldownKey {
                    scope: FailureScope::Candidate,
                    id: 1,
                },
                0,
                1_000,
            )
            .unwrap();
        let cooled = cooled_flags(&candidates, &table, 10);
        let current = NetworkEpoch::start();
        let selected = select_for_epoch(&candidates, &[1, 1], &cooled, current, request()).unwrap();
        assert_eq!(selected, vec![1]);

        let next = current.advance().unwrap();
        let selected =
            select_for_epoch(&candidates, &[1, 2], &[false, false], next, request()).unwrap();
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn endpoint_cooldown_drops_matching_candidate() {
        let mut matched = candidate(1, 10);
        matched.failure_domain = 70;
        let candidates = [matched, candidate(2, 20)];
        let mut table = CooldownTable::new();
        table
            .record(
                CooldownKey {
                    scope: FailureScope::Endpoint,
                    id: 1,
                },
                0,
                1_000,
            )
            .unwrap();
        let cooled = cooled_flags(&candidates, &table, 10);
        let selected = select_for_epoch(
            &candidates,
            &[1, 1],
            &cooled,
            NetworkEpoch::start(),
            request(),
        )
        .unwrap();
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn candidate_cooldown_on_other_id_keeps_endpoint() {
        let candidates = [candidate(1, 10), candidate(2, 20)];
        let mut table = CooldownTable::new();
        table
            .record(
                CooldownKey {
                    scope: FailureScope::Candidate,
                    id: 9,
                },
                0,
                1_000,
            )
            .unwrap();
        let cooled = cooled_flags(&candidates, &table, 10);
        let selected = select_for_epoch(
            &candidates,
            &[1, 1],
            &cooled,
            NetworkEpoch::start(),
            request(),
        )
        .unwrap();
        assert_eq!(selected, vec![0, 1]);
    }

    #[test]
    fn failure_domain_cooldown_drops_matching_candidate() {
        let mut matched = candidate(1, 10);
        matched.failure_domain = 40;
        let candidates = [matched, candidate(2, 20)];
        let mut table = CooldownTable::new();
        table
            .record(
                CooldownKey {
                    scope: FailureScope::FailureDomain,
                    id: 40,
                },
                0,
                1_000,
            )
            .unwrap();
        let cooled = cooled_flags(&candidates, &table, 10);
        let selected = select_for_epoch(
            &candidates,
            &[1, 1],
            &cooled,
            NetworkEpoch::start(),
            request(),
        )
        .unwrap();
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn peer_trust_is_not_retryable() {
        assert!(!may_retry_other_endpoint(FailureClass::PeerTrust));
    }

    #[test]
    fn scoped_failure_uses_only_its_endpoint_binding_and_network() {
        let first = candidate(1, 10);
        let second = candidate(2, 20);
        let context = CandidateContext {
            endpoint_generation: 1,
            address: "127.0.0.1:443".parse().unwrap(),
            network_epoch: NetworkEpoch::start(),
        };
        let mut table = CooldownTable::new();
        table
            .record_scoped(
                scoped_cooldown_key(&first, context, FailureClass::CandidateTransport).unwrap(),
                0,
                100,
            )
            .unwrap();
        assert!(candidate_cooled_in_epoch(&first, context, &table, 1));
        assert!(!candidate_cooled_in_epoch(&second, context, &table, 1));
        let mut h3 = first.clone();
        h3.binding = BindingId::H3;
        assert!(!candidate_cooled_in_epoch(&h3, context, &table, 1));
        assert!(!candidate_cooled_in_epoch(
            &first,
            CandidateContext {
                network_epoch: context.network_epoch.advance().unwrap(),
                ..context
            },
            &table,
            1
        ));
        assert!(scoped_cooldown_key(&first, context, FailureClass::Authentication).is_none());
        assert!(scoped_cooldown_key(&first, context, FailureClass::TargetConnect).is_none());
    }
}
