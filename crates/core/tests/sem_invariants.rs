#![forbid(unsafe_code)]

use ariad_core::{
    BudgetLimits, Core, CoreConfig, CoreInput, CoreOutput, Destination, EngineError,
    FlowGeneration, FlowId, RetryScope, SessionPhase, StreamInput, StreamPhase,
};

mod common;

use common::{assert_category, assert_no_dial, authorize};

fn ready() -> Core {
    ready_with_limits(BudgetLimits::lab_small())
}

fn ready_with_limits(limits: BudgetLimits) -> Core {
    let mut core = Core::new(CoreConfig {
        limits,
        allow_private_egress: false,
    })
    .unwrap();
    authorize(&mut core);
    core
}

fn connecting_stream() -> (Core, FlowId, FlowGeneration) {
    let mut core = ready();
    let outputs = core.handle(CoreInput::OpenStream {
        destination: Destination::parse("1.1.1.1:443").unwrap(),
    });
    let (id, generation) = dial_identity(&outputs);
    assert_eq!(generation, FlowGeneration(1));
    assert_eq!(core.stream_phase(id), Some(StreamPhase::ConnectingTarget));
    (core, id, generation)
}

fn opened_stream() -> (Core, FlowId, FlowGeneration) {
    let (mut core, id, generation) = connecting_stream();
    mark_connected(&mut core, id, generation);
    (core, id, generation)
}

fn dial_identity(outputs: &[CoreOutput]) -> (FlowId, FlowGeneration) {
    match outputs {
        [CoreOutput::DialTarget { id, generation, .. }] => (*id, *generation),
        _ => panic!("expected exactly one DialTarget, got {outputs:?}"),
    }
}

fn on_stream(
    core: &mut Core,
    id: FlowId,
    generation: FlowGeneration,
    input: StreamInput,
) -> Vec<CoreOutput> {
    core.handle(CoreInput::Stream {
        id,
        generation,
        input,
    })
}

fn mark_connected(core: &mut Core, id: FlowId, generation: FlowGeneration) {
    let outputs = on_stream(core, id, generation, StreamInput::TargetConnected);
    assert_quiet(&outputs);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));
}

fn assert_quiet(outputs: &[CoreOutput]) {
    assert!(outputs.is_empty(), "{outputs:?}");
}

fn assert_violation(outputs: &[CoreOutput]) {
    assert_category(outputs, EngineError::ProtocolViolation);
    assert_no_dial(outputs);
}

#[test]
fn write_before_open_is_violation() {
    let (mut core, id, generation) = connecting_stream();
    let outputs = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 5 },
    );
    assert_violation(&outputs);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::ConnectingTarget));
    mark_connected(&mut core, id, generation);
}

#[test]
fn zero_port_does_not_dial_or_consume_a_flow() {
    for addr in ["1.1.1.1", "2606:4700:4700::1111"] {
        let mut core = ready();
        let outputs = core.handle(CoreInput::OpenStream {
            destination: Destination::Ip {
                addr: addr.parse().unwrap(),
                port: 0,
            },
        });
        assert!(matches!(
            outputs.as_slice(),
            [CoreOutput::Failure(failure)]
                if failure.category == EngineError::InvalidConfig
                    && failure.retry == RetryScope::Never
        ));
        assert_eq!(core.stream_phase(FlowId(1)), None);

        let outputs = core.handle(CoreInput::OpenStream {
            destination: Destination::parse("1.1.1.1:443").unwrap(),
        });
        assert_eq!(dial_identity(&outputs).0, FlowId(1));
    }
}

#[test]
fn local_half_close_rejects_writes_then_remote_close_removes_stream() {
    let (mut core, id, generation) = opened_stream();
    let half_local = on_stream(&mut core, id, generation, StreamInput::HalfCloseLocal);
    assert_quiet(&half_local);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::HalfClosedLocal));

    let written = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_violation(&written);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::HalfClosedLocal));

    let half_remote = on_stream(&mut core, id, generation, StreamInput::HalfCloseRemote);
    assert_quiet(&half_remote);
    assert_eq!(core.stream_phase(id), None);
}

#[test]
fn reset_is_not_eof() {
    let (mut core, id, generation) = opened_stream();
    let reset = on_stream(&mut core, id, generation, StreamInput::Reset);
    assert_quiet(&reset);
    assert_eq!(core.stream_phase(id), None);

    let eof = on_stream(&mut core, id, generation, StreamInput::HalfCloseRemote);
    assert_violation(&eof);
    assert_eq!(core.stream_phase(id), None);
}

#[test]
fn cancel_does_not_redial() {
    let (mut core, id, generation) = opened_stream();
    let accepted = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 10 },
    );
    let cancelled = on_stream(&mut core, id, generation, StreamInput::Cancel);
    assert_quiet(&accepted);
    assert_quiet(&cancelled);
    assert_eq!(core.stream_phase(id), None);
}

#[test]
fn mismatched_generation_does_not_complete_target_open() {
    let (mut core, id, generation) = connecting_stream();
    assert_eq!(generation, FlowGeneration(1));
    let mismatched = on_stream(
        &mut core,
        id,
        FlowGeneration(99),
        StreamInput::TargetConnected,
    );
    assert_violation(&mismatched);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::ConnectingTarget));
    mark_connected(&mut core, id, generation);
}

#[test]
fn write_overflow_stays_open_without_dial() {
    let (mut core, id, generation) = opened_stream();
    let filled = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: u64::MAX },
    );
    assert_quiet(&filled);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));

    let overflow = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_category(&overflow, EngineError::ResourceLimitExceeded);
    assert_no_dial(&overflow);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));
}

#[test]
fn unknown_stream_is_violation() {
    let (mut core, id, generation) = connecting_stream();
    let outputs = on_stream(
        &mut core,
        FlowId(id.0 + 1),
        generation,
        StreamInput::TargetConnected,
    );
    assert_violation(&outputs);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::ConnectingTarget));
    assert_eq!(core.stream_phase(FlowId(id.0 + 1)), None);
}

#[test]
fn write_after_cancel_is_violation() {
    let (mut core, id, generation) = opened_stream();
    assert_quiet(&core.handle(CoreInput::Cancel));
    assert_eq!(core.session_phase(), SessionPhase::Cancelled);
    let written = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_violation(&written);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));
}

#[test]
fn write_after_close_is_violation() {
    let (mut core, id, generation) = opened_stream();
    assert_quiet(&core.handle(CoreInput::Drain));
    assert_eq!(core.session_phase(), SessionPhase::Draining);
    let during_drain = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_quiet(&during_drain);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));

    assert_quiet(&core.handle(CoreInput::Close));
    assert_eq!(core.session_phase(), SessionPhase::Closed);
    let written = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_violation(&written);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));
}

#[test]
fn write_after_tunnel_failed_is_violation() {
    let (mut core, id, generation) = opened_stream();
    let failed = core.handle(CoreInput::TunnelFailed);
    assert_no_dial(&failed);
    assert_eq!(core.session_phase(), SessionPhase::Failed);
    let written = on_stream(
        &mut core,
        id,
        generation,
        StreamInput::WriteAccepted { n: 1 },
    );
    assert_violation(&written);
    assert_eq!(core.stream_phase(id), Some(StreamPhase::Open));
}

#[test]
fn terminal_stream_sequences_release_admission_and_reject_late_completions() {
    let sequences = [
        vec![StreamInput::Reset],
        vec![StreamInput::Cancel],
        vec![StreamInput::Timeout],
        vec![StreamInput::Truncated],
        vec![StreamInput::HalfCloseLocal, StreamInput::HalfCloseRemote],
        vec![StreamInput::HalfCloseRemote, StreamInput::HalfCloseLocal],
        vec![StreamInput::HalfCloseLocal, StreamInput::Reset],
        vec![StreamInput::HalfCloseRemote, StreamInput::Cancel],
    ];
    for sequence in sequences {
        let mut limits = BudgetLimits::lab_small();
        limits.active_flows_per_session = 1;
        limits.pending_egress_opens = 1;
        let mut core = ready_with_limits(limits);
        let first = core.handle(CoreInput::OpenStream {
            destination: Destination::parse("1.1.1.1:443").unwrap(),
        });
        let (id, generation) = dial_identity(&first);
        mark_connected(&mut core, id, generation);
        assert_quiet(&on_stream(
            &mut core,
            id,
            generation,
            StreamInput::WriteAccepted { n: 3 },
        ));
        for input in &sequence {
            assert_quiet(&on_stream(&mut core, id, generation, *input));
        }
        assert_eq!(core.stream_phase(id), None, "{sequence:?}");

        let next = core.handle(CoreInput::OpenStream {
            destination: Destination::parse("1.1.1.1:8443").unwrap(),
        });
        let (next_id, next_generation) = dial_identity(&next);
        assert_ne!(next_id, id, "{sequence:?}");
        for input in [
            StreamInput::TargetConnected,
            StreamInput::WriteAccepted { n: 3 },
        ] {
            let late = on_stream(&mut core, id, generation, input);
            assert_violation(&late);
            assert_eq!(
                core.stream_phase(next_id),
                Some(StreamPhase::ConnectingTarget)
            );
        }
        let mismatched = on_stream(
            &mut core,
            next_id,
            FlowGeneration(next_generation.0 + 1),
            StreamInput::TargetConnected,
        );
        assert_violation(&mismatched);
        assert_eq!(
            core.stream_phase(next_id),
            Some(StreamPhase::ConnectingTarget)
        );
        mark_connected(&mut core, next_id, next_generation);
    }
}
