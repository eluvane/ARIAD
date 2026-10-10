#![forbid(unsafe_code)]

use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    Opening,
    Authorized,
    ConnectingTarget,
    Open,

    HalfClosedLocal,

    HalfClosedRemote,
    Closed,

    Reset,
    Cancelled,
    TimedOut,
    Truncated,
}

impl StreamPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        match self {
            Self::Closed | Self::Reset | Self::Cancelled | Self::TimedOut | Self::Truncated => true,
            Self::Opening
            | Self::Authorized
            | Self::ConnectingTarget
            | Self::Open
            | Self::HalfClosedLocal
            | Self::HalfClosedRemote => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInput {
    PolicyAllowed,
    TargetDialStarted,
    TargetConnected,

    /// Report `n` bytes accepted by the local write path.
    WriteAccepted {
        n: u64,
    },
    /// Close the local sending direction.
    HalfCloseLocal,
    /// Close the remote sending direction; local writes can continue.
    HalfCloseRemote,
    Reset,
    Cancel,
    Timeout,
    Truncated,
}

/// Lifecycle and local write acceptance counter for one target stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMachine {
    phase: StreamPhase,
    accepted_bytes: u64,
}

impl Default for StreamMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamMachine {
    pub const fn new() -> Self {
        Self {
            phase: StreamPhase::Opening,
            accepted_bytes: 0,
        }
    }

    pub const fn phase(&self) -> StreamPhase {
        self.phase
    }

    /// Total bytes reported as locally accepted, retained after termination.
    ///
    /// This counter does not confirm remote delivery.
    pub const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    /// Apply a lifecycle input or add locally accepted bytes.
    ///
    /// Writes are accepted in `Open` and `HalfClosedRemote`, including zero-byte
    /// increments.
    ///
    /// Invalid transitions and inputs after termination return
    /// [`EngineError::ProtocolViolation`]. Counter overflow returns
    /// [`EngineError::ResourceLimitExceeded`]. Both failures leave the phase and
    /// accepted-byte count unchanged.
    pub fn apply(&mut self, input: StreamInput) -> Result<(), EngineError> {
        if self.phase.is_terminal() {
            return Err(EngineError::ProtocolViolation);
        }

        let next = match (self.phase, input) {
            (StreamPhase::Opening, StreamInput::PolicyAllowed) => StreamPhase::Authorized,
            (StreamPhase::Authorized, StreamInput::TargetDialStarted) => {
                StreamPhase::ConnectingTarget
            }
            (StreamPhase::ConnectingTarget, StreamInput::TargetConnected) => StreamPhase::Open,

            (
                StreamPhase::Open | StreamPhase::HalfClosedRemote,
                StreamInput::WriteAccepted { n: byte_count },
            ) => {
                self.accepted_bytes = self
                    .accepted_bytes
                    .checked_add(byte_count)
                    .ok_or(EngineError::ResourceLimitExceeded)?;
                self.phase
            }

            (StreamPhase::Open, StreamInput::HalfCloseLocal) => StreamPhase::HalfClosedLocal,
            (StreamPhase::HalfClosedRemote, StreamInput::HalfCloseLocal) => StreamPhase::Closed,
            (StreamPhase::Open, StreamInput::HalfCloseRemote) => StreamPhase::HalfClosedRemote,
            (StreamPhase::HalfClosedLocal, StreamInput::HalfCloseRemote) => StreamPhase::Closed,

            (_, StreamInput::Reset) => StreamPhase::Reset,
            (_, StreamInput::Cancel) => StreamPhase::Cancelled,
            (_, StreamInput::Timeout) => StreamPhase::TimedOut,

            (
                StreamPhase::Open | StreamPhase::HalfClosedLocal | StreamPhase::HalfClosedRemote,
                StreamInput::Truncated,
            ) => StreamPhase::Truncated,

            _ => return Err(EngineError::ProtocolViolation),
        };

        self.phase = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive_to_open() -> StreamMachine {
        let mut stream = StreamMachine::new();
        stream.apply(StreamInput::PolicyAllowed).unwrap();
        stream.apply(StreamInput::TargetDialStarted).unwrap();
        stream.apply(StreamInput::TargetConnected).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Open);
        stream
    }

    #[test]
    fn local_half_close_rejects_later_writes() {
        let mut stream = StreamMachine::new();
        assert_eq!(stream.phase(), StreamPhase::Opening);
        assert_eq!(stream.accepted_bytes(), 0);

        stream.apply(StreamInput::PolicyAllowed).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Authorized);
        stream.apply(StreamInput::TargetDialStarted).unwrap();
        assert_eq!(stream.phase(), StreamPhase::ConnectingTarget);
        stream.apply(StreamInput::TargetConnected).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Open);

        stream.apply(StreamInput::WriteAccepted { n: 10 }).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Open);
        assert_eq!(stream.accepted_bytes(), 10);

        stream.apply(StreamInput::HalfCloseLocal).unwrap();
        assert_eq!(stream.phase(), StreamPhase::HalfClosedLocal);
        assert_eq!(stream.accepted_bytes(), 10);

        assert_eq!(
            stream.apply(StreamInput::WriteAccepted { n: 1 }),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(stream.phase(), StreamPhase::HalfClosedLocal);
        assert_eq!(stream.accepted_bytes(), 10);
    }

    #[test]
    fn write_before_open_is_protocol_violation() {
        let mut stream = StreamMachine::new();
        assert_eq!(
            stream.apply(StreamInput::WriteAccepted { n: 4 }),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(stream.phase(), StreamPhase::Opening);
        assert_eq!(stream.accepted_bytes(), 0);

        stream.apply(StreamInput::PolicyAllowed).unwrap();
        assert_eq!(
            stream.apply(StreamInput::WriteAccepted { n: 1 }),
            Err(EngineError::ProtocolViolation)
        );
        stream.apply(StreamInput::TargetDialStarted).unwrap();
        assert_eq!(
            stream.apply(StreamInput::WriteAccepted { n: u64::MAX }),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(stream.phase(), StreamPhase::ConnectingTarget);
        assert_eq!(stream.accepted_bytes(), 0);
    }

    #[test]
    fn write_overflow_leaves_phase_and_accepted_unchanged() {
        let mut stream = drive_to_open();
        stream
            .apply(StreamInput::WriteAccepted { n: u64::MAX - 1 })
            .unwrap();
        assert_eq!(
            stream.apply(StreamInput::WriteAccepted { n: 2 }),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(stream.phase(), StreamPhase::Open);
        assert_eq!(stream.accepted_bytes(), u64::MAX - 1);

        stream.apply(StreamInput::WriteAccepted { n: 1 }).unwrap();
        assert_eq!(stream.accepted_bytes(), u64::MAX);
        assert_eq!(stream.apply(StreamInput::WriteAccepted { n: 0 }), Ok(()));
        assert_eq!(stream.accepted_bytes(), u64::MAX);
    }

    #[test]
    fn local_half_close_waits_for_remote_half_close() {
        let mut stream = drive_to_open();
        stream.apply(StreamInput::WriteAccepted { n: 10 }).unwrap();
        stream.apply(StreamInput::HalfCloseLocal).unwrap();
        assert_eq!(stream.phase(), StreamPhase::HalfClosedLocal);

        stream.apply(StreamInput::HalfCloseRemote).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Closed);
        assert_eq!(stream.accepted_bytes(), 10);
    }

    #[test]
    fn remote_half_close_still_accepts_local_writes() {
        let mut stream = drive_to_open();
        stream.apply(StreamInput::HalfCloseRemote).unwrap();
        assert_eq!(stream.phase(), StreamPhase::HalfClosedRemote);
        stream.apply(StreamInput::WriteAccepted { n: 7 }).unwrap();
        assert_eq!(stream.phase(), StreamPhase::HalfClosedRemote);
        assert_eq!(stream.accepted_bytes(), 7);
        stream.apply(StreamInput::HalfCloseLocal).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Closed);
        assert_eq!(stream.accepted_bytes(), 7);
    }

    #[test]
    fn reset_is_not_eof() {
        let mut stream = drive_to_open();
        stream.apply(StreamInput::WriteAccepted { n: 3 }).unwrap();
        stream.apply(StreamInput::Reset).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Reset);
        assert_eq!(stream.accepted_bytes(), 3);
        assert_eq!(
            stream.apply(StreamInput::HalfCloseRemote),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(stream.phase(), StreamPhase::Reset);
        assert_eq!(stream.accepted_bytes(), 3);
    }

    #[test]
    fn reset_cancel_and_timeout_end_any_non_terminal() {
        let opening = StreamMachine::new();
        let mut authorized = StreamMachine::new();
        authorized.apply(StreamInput::PolicyAllowed).unwrap();
        let mut connecting = authorized.clone();
        connecting.apply(StreamInput::TargetDialStarted).unwrap();
        let open = drive_to_open();
        let mut half_local = open.clone();
        half_local.apply(StreamInput::HalfCloseLocal).unwrap();
        let mut half_remote = open.clone();
        half_remote.apply(StreamInput::HalfCloseRemote).unwrap();

        for stream in [
            opening,
            authorized,
            connecting,
            open,
            half_local,
            half_remote,
        ] {
            let accepted = stream.accepted_bytes();

            let mut reset = stream.clone();
            reset.apply(StreamInput::Reset).unwrap();
            assert_eq!(reset.phase(), StreamPhase::Reset);
            assert_eq!(reset.accepted_bytes(), accepted);

            let mut cancel = stream.clone();
            cancel.apply(StreamInput::Cancel).unwrap();
            assert_eq!(cancel.phase(), StreamPhase::Cancelled);
            assert_eq!(cancel.accepted_bytes(), accepted);

            let mut timed = stream.clone();
            timed.apply(StreamInput::Timeout).unwrap();
            assert_eq!(timed.phase(), StreamPhase::TimedOut);
            assert_eq!(timed.accepted_bytes(), accepted);
        }
    }

    #[test]
    fn truncated_only_from_an_open_direction() {
        let mut opening = StreamMachine::new();
        assert_eq!(
            opening.apply(StreamInput::Truncated),
            Err(EngineError::ProtocolViolation)
        );
        opening.apply(StreamInput::PolicyAllowed).unwrap();
        assert_eq!(
            opening.apply(StreamInput::Truncated),
            Err(EngineError::ProtocolViolation)
        );
        opening.apply(StreamInput::TargetDialStarted).unwrap();
        assert_eq!(
            opening.apply(StreamInput::Truncated),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(opening.phase(), StreamPhase::ConnectingTarget);

        let mut open = drive_to_open();
        open.apply(StreamInput::Truncated).unwrap();
        assert_eq!(open.phase(), StreamPhase::Truncated);

        let mut half_local = drive_to_open();
        half_local.apply(StreamInput::HalfCloseLocal).unwrap();
        half_local.apply(StreamInput::Truncated).unwrap();
        assert_eq!(half_local.phase(), StreamPhase::Truncated);

        let mut half_remote = drive_to_open();
        half_remote.apply(StreamInput::HalfCloseRemote).unwrap();
        half_remote.apply(StreamInput::Truncated).unwrap();
        assert_eq!(half_remote.phase(), StreamPhase::Truncated);
    }

    #[test]
    fn inputs_to_terminal_streams_are_rejected_without_changes() {
        let samples = [
            {
                let mut stream = drive_to_open();
                stream.apply(StreamInput::HalfCloseLocal).unwrap();
                stream.apply(StreamInput::HalfCloseRemote).unwrap();
                stream
            },
            {
                let mut stream = drive_to_open();
                stream.apply(StreamInput::Reset).unwrap();
                stream
            },
            {
                let mut stream = drive_to_open();
                stream.apply(StreamInput::Cancel).unwrap();
                stream
            },
            {
                let mut stream = drive_to_open();
                stream.apply(StreamInput::Timeout).unwrap();
                stream
            },
            {
                let mut stream = drive_to_open();
                stream.apply(StreamInput::Truncated).unwrap();
                stream
            },
        ];

        let inputs = [
            StreamInput::PolicyAllowed,
            StreamInput::TargetDialStarted,
            StreamInput::TargetConnected,
            StreamInput::WriteAccepted { n: 1 },
            StreamInput::HalfCloseLocal,
            StreamInput::HalfCloseRemote,
            StreamInput::Reset,
            StreamInput::Cancel,
            StreamInput::Timeout,
            StreamInput::Truncated,
        ];

        for stream in samples {
            let phase = stream.phase();
            let accepted = stream.accepted_bytes();
            assert!(phase.is_terminal());
            let mut stream = stream;
            for input in inputs {
                assert_eq!(stream.apply(input), Err(EngineError::ProtocolViolation));
                assert_eq!(stream.phase(), phase);
                assert_eq!(stream.accepted_bytes(), accepted);
            }
        }
    }

    #[test]
    fn connecting_target_is_not_retried_or_rewound() {
        let mut stream = StreamMachine::new();
        stream.apply(StreamInput::PolicyAllowed).unwrap();
        stream.apply(StreamInput::TargetDialStarted).unwrap();
        assert_eq!(
            stream.apply(StreamInput::TargetDialStarted),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(
            stream.apply(StreamInput::PolicyAllowed),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(stream.phase(), StreamPhase::ConnectingTarget);
        assert_eq!(stream.accepted_bytes(), 0);
        stream.apply(StreamInput::TargetConnected).unwrap();
        assert_eq!(stream.phase(), StreamPhase::Open);
    }

    #[test]
    fn new_stream_does_not_carry_accepted_bytes() {
        let mut first = drive_to_open();
        first.apply(StreamInput::WriteAccepted { n: 10 }).unwrap();
        let second = StreamMachine::new();
        assert_eq!(second.phase(), StreamPhase::Opening);
        assert_eq!(second.accepted_bytes(), 0);
        assert_eq!(first.accepted_bytes(), 10);
    }
}
