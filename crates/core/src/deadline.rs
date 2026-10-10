use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    ConnectTotal,
    BootstrapDns,
    TransportHandshake,

    RemoteAuth,

    AuthorizerBackend,

    TargetOpen,

    GracefulDrain,

    IdleUdp,
}

/// Initial lab-small time budget for one operation stage.
///
/// The caller must cap this value by the remaining parent budget.
pub fn lab_cap(kind: DeadlineKind) -> Duration {
    Duration::from_secs(match kind {
        DeadlineKind::ConnectTotal => 20,
        DeadlineKind::BootstrapDns | DeadlineKind::RemoteAuth => 3,
        DeadlineKind::TransportHandshake => 5,
        DeadlineKind::AuthorizerBackend => 1,
        DeadlineKind::TargetOpen | DeadlineKind::GracefulDrain => 10,
        DeadlineKind::IdleUdp => 60,
    })
}

/// Return a child time budget capped by the parent's current remaining time.
pub fn child_deadline(parent_remaining: Duration, cap: Duration) -> Duration {
    parent_remaining.min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_deadline_keeps_the_tighter_bound() {
        assert_eq!(
            child_deadline(Duration::from_secs(2), Duration::from_secs(5)),
            Duration::from_secs(2)
        );
        assert_eq!(
            child_deadline(Duration::from_secs(10), Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn exhausted_parent_stays_zero() {
        assert_eq!(
            child_deadline(Duration::ZERO, Duration::from_secs(5)),
            Duration::ZERO
        );
    }

    #[test]
    fn later_candidate_cannot_extend_the_parent() {
        let parent = Duration::from_secs(4);
        let first = child_deadline(parent, lab_cap(DeadlineKind::TransportHandshake));
        let later = child_deadline(first, lab_cap(DeadlineKind::TransportHandshake));
        assert_eq!(first, parent);
        assert_eq!(later, first);
    }

    #[test]
    fn lab_caps_match_the_lab_small_table() {
        assert_eq!(lab_cap(DeadlineKind::ConnectTotal), Duration::from_secs(20));
        assert_eq!(lab_cap(DeadlineKind::BootstrapDns), Duration::from_secs(3));
        assert_eq!(
            lab_cap(DeadlineKind::TransportHandshake),
            Duration::from_secs(5)
        );
        assert_eq!(lab_cap(DeadlineKind::RemoteAuth), Duration::from_secs(3));
        assert_eq!(
            lab_cap(DeadlineKind::AuthorizerBackend),
            Duration::from_secs(1)
        );
        assert_eq!(lab_cap(DeadlineKind::TargetOpen), Duration::from_secs(10));
        assert_eq!(
            lab_cap(DeadlineKind::GracefulDrain),
            Duration::from_secs(10)
        );
        assert_eq!(lab_cap(DeadlineKind::IdleUdp), Duration::from_secs(60));
    }
}
