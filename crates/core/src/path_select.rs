#![forbid(unsafe_code)]

use crate::capability::BindingId;

pub const MAX_PARALLEL_CANDIDATES: usize = 2;
pub const MAX_CANDIDATE_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub endpoint_id: u64,
    pub binding: BindingId,
    pub failure_domain: u64,
    pub rtt_hint_ms: u32,
    pub supports_unreliable: bool,
    pub supports_ech: bool,
    pub exhausted: bool,
    pub binding_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectRequest {
    pub require_unreliable: bool,
    pub require_ech: bool,
    pub max_parallel: usize,
    pub max_attempts: usize,
}

impl SelectRequest {
    pub(crate) fn for_attempts(self) -> Self {
        let attempt_limit = if self.max_parallel == 0 {
            0
        } else {
            self.max_attempts.min(MAX_CANDIDATE_ATTEMPTS)
        };
        Self {
            max_parallel: attempt_limit,
            max_attempts: attempt_limit,
            ..self
        }
    }
}

/// Returns input indices, limited by the smaller request cap.
/// Chooses the lowest RTT in each admitted failure domain, with earlier indices
/// winning ties. Domains retain first-seen order; spare slots are filled from
/// eligible input order. Selection does not launch dials.
pub fn select_candidates(candidates: &[Candidate], request: SelectRequest) -> Vec<usize> {
    let selection_limit = request.max_parallel.min(request.max_attempts);
    if selection_limit == 0 {
        return Vec::new();
    }

    let mut domain_choices: Vec<(u64, usize)> = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if !is_eligible(candidate, request) {
            continue;
        }
        let failure_domain = candidate.failure_domain;
        if let Some((_, incumbent_index)) = domain_choices
            .iter_mut()
            .find(|choice| choice.0 == failure_domain)
        {
            if candidate.rtt_hint_ms < candidates[*incumbent_index].rtt_hint_ms {
                *incumbent_index = index;
            }
        } else if domain_choices.len() < selection_limit {
            domain_choices.push((failure_domain, index));
        }
    }

    let mut selected: Vec<_> = domain_choices.into_iter().map(|(_, index)| index).collect();

    if selected.len() < selection_limit {
        for (index, candidate) in candidates.iter().enumerate() {
            if selected.len() == selection_limit {
                break;
            }
            if is_eligible(candidate, request) && !selected.contains(&index) {
                selected.push(index);
            }
        }
    }
    selected
}

/// Returns an ordered attempt list capped by `max_attempts` and `MAX_CANDIDATE_ATTEMPTS`.
/// Zero `max_parallel` disables selection; otherwise it does not limit this list.
/// Callers enforce parallelism when launching the selected attempts.
pub fn select_attempts(candidates: &[Candidate], request: SelectRequest) -> Vec<usize> {
    select_candidates(candidates, request.for_attempts())
}

fn is_eligible(candidate: &Candidate, request: SelectRequest) -> bool {
    !candidate.exhausted
        && candidate.binding_allowed
        && (!request.require_ech || candidate.supports_ech)
        && (!request.require_unreliable || candidate.supports_unreliable)
}

#[cfg(test)]
mod tests {
    use super::{Candidate, SelectRequest, select_candidates};
    use crate::capability::BindingId;

    fn open_candidate() -> Candidate {
        Candidate {
            endpoint_id: 1,
            binding: BindingId::H2,
            failure_domain: 1,
            rtt_hint_ms: 20,
            supports_unreliable: true,
            supports_ech: true,
            exhausted: false,
            binding_allowed: true,
        }
    }

    fn request(
        require_unreliable: bool,
        require_ech: bool,
        max_parallel: usize,
        max_attempts: usize,
    ) -> SelectRequest {
        SelectRequest {
            require_unreliable,
            require_ech,
            max_parallel,
            max_attempts,
        }
    }

    #[test]
    fn ech_required_drops_faster_candidate_without_ech() {
        let candidates = [
            Candidate {
                rtt_hint_ms: 1,
                supports_ech: false,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 2,
                rtt_hint_ms: 500,
                supports_ech: true,
                ..open_candidate()
            },
        ];
        let selected = select_candidates(&candidates, request(false, true, 4, 4));
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn require_unreliable_drops_h2_like_candidate() {
        let candidates = [
            Candidate {
                binding: BindingId::H2,
                supports_unreliable: false,
                rtt_hint_ms: 1,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                binding: BindingId::H3,
                failure_domain: 2,
                supports_unreliable: true,
                rtt_hint_ms: 250,
                ..open_candidate()
            },
        ];
        let selected = select_candidates(&candidates, request(true, false, 4, 4));
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn exhausted_candidate_is_dropped() {
        let candidates = [
            Candidate {
                exhausted: true,
                rtt_hint_ms: 1,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 2,
                exhausted: false,
                rtt_hint_ms: 300,
                ..open_candidate()
            },
        ];
        let selected = select_candidates(&candidates, request(false, false, 4, 4));
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn max_parallel_two_returns_at_most_two() {
        let rtt = [90_u32, 70, 5, 1];
        let mut candidates = Vec::new();
        for (index, rtt_hint_ms) in rtt.into_iter().enumerate() {
            candidates.push(Candidate {
                endpoint_id: index as u64,
                failure_domain: index as u64,
                rtt_hint_ms,
                ..open_candidate()
            });
        }
        let selected = select_candidates(&candidates, request(false, false, 2, 8));
        assert!(selected.len() <= 2);
        assert_eq!(selected, vec![0, 1]);
    }

    #[test]
    fn same_domain_keeps_lower_rtt_first() {
        let candidates = [
            Candidate {
                failure_domain: 7,
                rtt_hint_ms: 80,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 7,
                rtt_hint_ms: 9,
                ..open_candidate()
            },
        ];
        let selected = select_candidates(&candidates, request(false, false, 2, 2));
        assert_eq!(selected, vec![1, 0]);
    }

    #[test]
    fn equal_rtt_keeps_the_earlier_index() {
        let candidates = [
            Candidate {
                failure_domain: 3,
                rtt_hint_ms: 12,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 3,
                rtt_hint_ms: 12,
                ..open_candidate()
            },
        ];
        assert_eq!(
            select_candidates(&candidates, request(false, false, 1, 1)),
            vec![0]
        );
    }

    #[test]
    fn disallowed_binding_stays_out_despite_low_rtt() {
        let candidates = [
            Candidate {
                binding_allowed: false,
                rtt_hint_ms: 1,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 2,
                binding_allowed: true,
                rtt_hint_ms: 200,
                ..open_candidate()
            },
        ];
        assert_eq!(
            select_candidates(&candidates, request(false, false, 4, 4)),
            vec![1]
        );
    }

    #[test]
    fn zero_cap_returns_empty() {
        let candidates = [open_candidate()];
        assert_eq!(
            select_candidates(&candidates, request(false, false, 0, 4)),
            Vec::<usize>::new()
        );
        assert_eq!(
            select_candidates(&candidates, request(false, false, 4, 0)),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn domain_seen_first_stays_ahead_of_a_faster_later_domain() {
        let candidates = [
            Candidate {
                failure_domain: 1,
                rtt_hint_ms: 100,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 2,
                rtt_hint_ms: 50,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 3,
                failure_domain: 1,
                rtt_hint_ms: 10,
                ..open_candidate()
            },
        ];
        assert_eq!(
            select_candidates(&candidates, request(false, false, 2, 2)),
            vec![2, 1]
        );
    }

    #[test]
    fn repeat_in_one_domain_waits_for_another_domain() {
        let candidates = [
            Candidate {
                failure_domain: 1,
                rtt_hint_ms: 10,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 2,
                failure_domain: 1,
                rtt_hint_ms: 40,
                ..open_candidate()
            },
            Candidate {
                endpoint_id: 3,
                failure_domain: 2,
                rtt_hint_ms: 100,
                ..open_candidate()
            },
        ];
        assert_eq!(
            select_candidates(&candidates, request(false, false, 2, 2)),
            vec![0, 2]
        );
        assert_eq!(
            select_candidates(&candidates, request(false, false, 3, 3)),
            vec![0, 2, 1]
        );
    }

    #[test]
    fn attempt_order_keeps_later_candidates_without_expanding_parallelism() {
        let candidates: Vec<_> = (1..=8)
            .map(|id| Candidate {
                endpoint_id: id,
                failure_domain: id,
                ..open_candidate()
            })
            .collect();
        let request = request(false, false, 2, 8);
        assert_eq!(select_candidates(&candidates, request), vec![0, 1]);
        assert_eq!(
            super::select_attempts(&candidates, request),
            vec![0, 1, 2, 3]
        );
    }
}
