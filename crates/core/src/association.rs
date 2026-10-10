use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationPhase {
    Opening,
    Authorized,
    Bound,
    Closing,
    Closed,
    Cancelled,
}

impl AssociationPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationInput {
    Begin,
    Authorized,
    Bound,

    Incoming { generation: u64 },
    Close,
    Cancel,
}

/// The result of the lifecycle and generation gate.
///
/// `Deliver` permits further payload and queue checks; it does not enqueue data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationEffect {
    Deliver,

    Drop,

    Reject,
}

/// Lifecycle and generation filter for one UDP association.
///
/// Callers supply authorization and binding results.
pub struct AssociationMachine {
    phase: AssociationPhase,
    generation: u64,
}

impl AssociationMachine {
    pub const fn new(generation: u64) -> Self {
        Self {
            phase: AssociationPhase::Opening,
            generation,
        }
    }

    pub const fn phase(&self) -> AssociationPhase {
        self.phase
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Replace the accepted generation without changing phase.
    ///
    /// The caller owns generation advancement and reuse policy.
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Apply a control input or classify an incoming datagram.
    ///
    /// Incoming datagrams yield `Deliver` only when bound with a matching
    /// generation; all other incoming datagrams yield `Drop`. Successful
    /// opening, authorization and binding controls yield `Reject`.
    ///
    /// Two `Close` inputs advance `Bound` through `Closing` to `Closed`.
    /// Invalid controls return [`EngineError::ProtocolViolation`] without
    /// changing phase or generation.
    pub fn apply(&mut self, input: AssociationInput) -> Result<AssociationEffect, EngineError> {
        match (self.phase, input) {
            (
                AssociationPhase::Bound,
                AssociationInput::Incoming {
                    generation: incoming_generation,
                },
            ) if incoming_generation == self.generation => Ok(AssociationEffect::Deliver),
            (_, AssociationInput::Incoming { .. }) => Ok(AssociationEffect::Drop),
            (phase, _) if phase.is_terminal() => Err(EngineError::ProtocolViolation),
            (AssociationPhase::Opening, AssociationInput::Begin) => Ok(AssociationEffect::Reject),
            (AssociationPhase::Opening, AssociationInput::Authorized) => {
                self.phase = AssociationPhase::Authorized;
                Ok(AssociationEffect::Reject)
            }
            (AssociationPhase::Authorized, AssociationInput::Bound) => {
                self.phase = AssociationPhase::Bound;
                Ok(AssociationEffect::Reject)
            }
            (AssociationPhase::Bound, AssociationInput::Close) => {
                self.phase = AssociationPhase::Closing;
                Ok(AssociationEffect::Drop)
            }
            (AssociationPhase::Closing, AssociationInput::Close) => {
                self.phase = AssociationPhase::Closed;
                Ok(AssociationEffect::Drop)
            }
            (_, AssociationInput::Cancel) => {
                self.phase = AssociationPhase::Cancelled;
                Ok(AssociationEffect::Drop)
            }
            _ => Err(EngineError::ProtocolViolation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_step(
        machine: &mut AssociationMachine,
        input: AssociationInput,
        expected_effect: AssociationEffect,
        expected_phase: AssociationPhase,
    ) {
        assert_eq!(machine.apply(input).unwrap(), expected_effect);
        assert_eq!(machine.phase(), expected_phase);
    }

    fn machine_in(phase: AssociationPhase, generation: u64) -> AssociationMachine {
        let mut machine = AssociationMachine::new(generation);
        assert_eq!(machine.phase(), AssociationPhase::Opening);
        assert_eq!(machine.generation(), generation);
        if phase == AssociationPhase::Opening {
            return machine;
        }
        assert_step(
            &mut machine,
            AssociationInput::Authorized,
            AssociationEffect::Reject,
            AssociationPhase::Authorized,
        );
        if phase == AssociationPhase::Authorized {
            return machine;
        }
        assert_step(
            &mut machine,
            AssociationInput::Bound,
            AssociationEffect::Reject,
            AssociationPhase::Bound,
        );
        if phase == AssociationPhase::Bound {
            return machine;
        }
        assert_step(
            &mut machine,
            AssociationInput::Close,
            AssociationEffect::Drop,
            AssociationPhase::Closing,
        );
        if phase == AssociationPhase::Closing {
            return machine;
        }
        assert_step(
            &mut machine,
            AssociationInput::Close,
            AssociationEffect::Drop,
            AssociationPhase::Closed,
        );
        assert_eq!(phase, AssociationPhase::Closed);
        machine
    }

    #[test]
    fn delivers_only_when_bound_with_matching_generation() {
        let mut machine = AssociationMachine::new(7);
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 7 })
                .unwrap(),
            AssociationEffect::Drop
        );

        assert_step(
            &mut machine,
            AssociationInput::Authorized,
            AssociationEffect::Reject,
            AssociationPhase::Authorized,
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 7 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(machine.phase(), AssociationPhase::Authorized);

        assert_step(
            &mut machine,
            AssociationInput::Bound,
            AssociationEffect::Reject,
            AssociationPhase::Bound,
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 7 })
                .unwrap(),
            AssociationEffect::Deliver
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 7 })
                .unwrap(),
            AssociationEffect::Deliver
        );
        assert_eq!(machine.phase(), AssociationPhase::Bound);
        assert_eq!(machine.generation(), 7);

        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 6 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 8 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(machine.phase(), AssociationPhase::Bound);
        assert_eq!(machine.generation(), 7);
    }

    #[test]
    fn incoming_while_opening_is_drop() {
        let mut machine = AssociationMachine::new(1);
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 1 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(machine.phase(), AssociationPhase::Opening);
        assert_eq!(machine.generation(), 1);
    }

    #[test]
    fn incoming_after_close_sequence_is_drop() {
        let mut machine = machine_in(AssociationPhase::Bound, 3);
        assert_step(
            &mut machine,
            AssociationInput::Close,
            AssociationEffect::Drop,
            AssociationPhase::Closing,
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 3 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(machine.phase(), AssociationPhase::Closing);

        assert_step(
            &mut machine,
            AssociationInput::Close,
            AssociationEffect::Drop,
            AssociationPhase::Closed,
        );
        assert_eq!(
            machine
                .apply(AssociationInput::Incoming { generation: 3 })
                .unwrap(),
            AssociationEffect::Drop
        );
        assert_eq!(machine.phase(), AssociationPhase::Closed);
        assert_eq!(machine.generation(), 3);
    }

    #[test]
    fn begin_on_opening_rejects_and_stays_open() {
        let mut machine = AssociationMachine::new(2);
        assert_step(
            &mut machine,
            AssociationInput::Begin,
            AssociationEffect::Reject,
            AssociationPhase::Opening,
        );
        assert_eq!(machine.generation(), 2);
    }

    #[test]
    fn cancel_from_each_non_terminal_phase_drops() {
        for phase in [
            AssociationPhase::Opening,
            AssociationPhase::Authorized,
            AssociationPhase::Bound,
            AssociationPhase::Closing,
        ] {
            let mut machine = machine_in(phase, 9);
            assert_step(
                &mut machine,
                AssociationInput::Cancel,
                AssociationEffect::Drop,
                AssociationPhase::Cancelled,
            );
            assert_eq!(machine.generation(), 9);
            assert_eq!(
                machine
                    .apply(AssociationInput::Incoming { generation: 9 })
                    .unwrap(),
                AssociationEffect::Drop
            );
            assert_eq!(machine.phase(), AssociationPhase::Cancelled);
        }
    }

    #[test]
    fn illegal_or_terminal_input_is_protocol_violation_and_unchanged() {
        let mut opening = AssociationMachine::new(4);
        assert_eq!(
            opening.apply(AssociationInput::Bound).unwrap_err(),
            EngineError::ProtocolViolation
        );
        assert_eq!(opening.phase(), AssociationPhase::Opening);
        assert_eq!(opening.generation(), 4);
        assert_step(
            &mut opening,
            AssociationInput::Authorized,
            AssociationEffect::Reject,
            AssociationPhase::Authorized,
        );

        let mut cancelled = machine_in(AssociationPhase::Opening, 4);
        assert_step(
            &mut cancelled,
            AssociationInput::Cancel,
            AssociationEffect::Drop,
            AssociationPhase::Cancelled,
        );

        for mut terminal in [machine_in(AssociationPhase::Closed, 4), cancelled] {
            let phase = terminal.phase();
            for input in [
                AssociationInput::Begin,
                AssociationInput::Authorized,
                AssociationInput::Bound,
                AssociationInput::Close,
                AssociationInput::Cancel,
            ] {
                assert_eq!(
                    terminal.apply(input).unwrap_err(),
                    EngineError::ProtocolViolation
                );
                assert_eq!(terminal.phase(), phase);
                assert_eq!(terminal.generation(), 4);
            }
            for generation in [3, 4, 5] {
                assert_eq!(
                    terminal
                        .apply(AssociationInput::Incoming { generation })
                        .unwrap(),
                    AssociationEffect::Drop
                );
                assert_eq!(terminal.phase(), phase);
                assert_eq!(terminal.generation(), 4);
            }
        }
    }
}
