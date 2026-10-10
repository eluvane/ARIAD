use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Idle,
    ResolvingEndpoint,
    Connecting,
    VerifyingPeer,

    /// Peer verification is complete. [`crate::Core`] tracks authorization separately.
    Ready,
    Draining,
    Closed,
    Failed,
    Cancelled,
}

impl SessionPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionInput {
    BeginResolve,
    EndpointResolved,
    TransportHandshakeStarted,
    PeerVerified,
    Drain,
    Close,
    Cancel,
    Fail,
}

/// Connection lifecycle driven by results reported by an adapter.
pub struct SessionMachine {
    phase: SessionPhase,
}

impl SessionMachine {
    pub const fn new() -> Self {
        Self {
            phase: SessionPhase::Idle,
        }
    }

    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// Apply one lifecycle input.
    ///
    /// Invalid transitions, including every input after termination, return
    /// [`EngineError::ProtocolViolation`] without changing phase. `Close` is
    /// accepted only after a ready session enters `Draining`.
    pub fn apply(&mut self, input: SessionInput) -> Result<(), EngineError> {
        if self.phase.is_terminal() {
            return Err(EngineError::ProtocolViolation);
        }

        let next = match (self.phase, input) {
            (SessionPhase::Idle, SessionInput::BeginResolve) => SessionPhase::ResolvingEndpoint,
            (SessionPhase::ResolvingEndpoint, SessionInput::EndpointResolved) => {
                SessionPhase::Connecting
            }
            (SessionPhase::Connecting, SessionInput::TransportHandshakeStarted) => {
                SessionPhase::VerifyingPeer
            }
            (SessionPhase::VerifyingPeer, SessionInput::PeerVerified) => SessionPhase::Ready,
            (SessionPhase::Ready, SessionInput::Drain) => SessionPhase::Draining,
            (SessionPhase::Draining, SessionInput::Close) => SessionPhase::Closed,
            (_, SessionInput::Cancel) => SessionPhase::Cancelled,
            (_, SessionInput::Fail) => SessionPhase::Failed,
            _ => return Err(EngineError::ProtocolViolation),
        };
        self.phase = next;
        Ok(())
    }
}

impl Default for SessionMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_reaches_ready() {
        let mut session = SessionMachine::new();
        assert_eq!(session.phase(), SessionPhase::Idle);

        assert_eq!(session.apply(SessionInput::BeginResolve), Ok(()));
        assert_eq!(session.phase(), SessionPhase::ResolvingEndpoint);

        assert_eq!(session.apply(SessionInput::EndpointResolved), Ok(()));
        assert_eq!(session.phase(), SessionPhase::Connecting);

        assert_eq!(
            session.apply(SessionInput::TransportHandshakeStarted),
            Ok(())
        );
        assert_eq!(session.phase(), SessionPhase::VerifyingPeer);

        assert_eq!(session.apply(SessionInput::PeerVerified), Ok(()));
        assert_eq!(session.phase(), SessionPhase::Ready);
    }

    #[test]
    fn peer_verified_from_idle_leaves_idle() {
        let mut session = SessionMachine::new();
        assert_eq!(
            session.apply(SessionInput::PeerVerified),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(session.phase(), SessionPhase::Idle);
    }

    #[test]
    fn terminal_sessions_reject_all_inputs_without_changes() {
        for phase in [
            SessionPhase::Closed,
            SessionPhase::Failed,
            SessionPhase::Cancelled,
        ] {
            let mut session = SessionMachine { phase };
            for input in [
                SessionInput::BeginResolve,
                SessionInput::EndpointResolved,
                SessionInput::TransportHandshakeStarted,
                SessionInput::PeerVerified,
                SessionInput::Drain,
                SessionInput::Close,
                SessionInput::Cancel,
                SessionInput::Fail,
            ] {
                assert_eq!(session.apply(input), Err(EngineError::ProtocolViolation));
                assert_eq!(session.phase(), phase);
            }
        }
    }
}
