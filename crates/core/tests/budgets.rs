#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::time::Duration;

use ariad_core::{
    BudgetLimits, CapabilitySet, Core, CoreConfig, CoreInput, CoreOutput, DeadlineKind,
    DeliveryMode, Destination, EngineError, MemoryBudget, ResourceBudget, ScopedMemoryReservation,
    child_deadline, lab_cap,
};

mod common;

use common::{assert_category, assert_no_dial, authorize};

#[test]
fn lab_small_validates() {
    assert_eq!(BudgetLimits::lab_small().validate(), Ok(()));
}

#[test]
fn zero_control_message_max_is_rejected() {
    let limits = BudgetLimits {
        control_message_max: 0,
        ..BudgetLimits::lab_small()
    };
    assert_eq!(limits.validate(), Err(EngineError::InvalidConfig));
}

#[test]
fn control_reserve_past_session_budget_is_rejected() {
    let limits = BudgetLimits::lab_small();
    let over = BudgetLimits {
        control_reserve: limits.session_application_budget + 1,
        ..limits
    };
    assert_eq!(over.validate(), Err(EngineError::InvalidConfig));
}

#[test]
fn udp_payload_absolute_max_rejects_one_past_the_ceiling() {
    let limits = BudgetLimits::lab_small();
    assert_eq!(limits.udp_payload_absolute_max, 65_507);
    let over = BudgetLimits {
        udp_payload_absolute_max: 65_508,
        ..limits
    };
    assert_eq!(over.validate(), Err(EngineError::InvalidConfig));
}

#[test]
fn child_deadline_keeps_the_tighter_bound() {
    assert_eq!(
        child_deadline(
            Duration::from_secs(2),
            lab_cap(DeadlineKind::TransportHandshake)
        ),
        Duration::from_secs(2)
    );
    assert_eq!(
        child_deadline(Duration::from_secs(10), lab_cap(DeadlineKind::BootstrapDns)),
        Duration::from_secs(3)
    );
    assert_eq!(
        child_deadline(Duration::ZERO, lab_cap(DeadlineKind::TransportHandshake)),
        Duration::ZERO
    );
    assert_eq!(lab_cap(DeadlineKind::IdleUdp), Duration::from_secs(60));
}

#[test]
fn v0_h2_only_encapsulates_unless_unreliable_is_required() {
    let caps = CapabilitySet::v0_h2_only();
    assert_eq!(
        caps.resolve_delivery(true),
        Err(EngineError::UnsupportedCapability)
    );
    assert_eq!(
        caps.resolve_delivery(false),
        Ok(DeliveryMode::ReliableEncapsulation)
    );
    assert_eq!(caps.udp_mode(), DeliveryMode::ReliableEncapsulation);
}

#[test]
fn lab_flow_cap_dials_sixty_four_targets_then_stops() {
    let mut core = Core::new(CoreConfig {
        limits: BudgetLimits::lab_small(),
        allow_private_egress: false,
    })
    .unwrap();

    authorize(&mut core);

    for port in 1u16..=64 {
        let outputs = open_stream(&mut core, port);
        let expected = Destination::parse(&format!("1.1.1.1:{port}")).unwrap();
        let dials: Vec<_> = outputs
            .iter()
            .filter_map(|output| match output {
                CoreOutput::DialTarget { destination, .. } => Some(destination),
                _ => None,
            })
            .collect();
        assert_eq!(outputs.len(), 1, "port {port}: {outputs:?}");
        assert_eq!(dials, vec![&expected], "port {port}: {outputs:?}");
    }

    let blocked = open_stream(&mut core, 65);
    assert_category(&blocked, EngineError::ResourceLimitExceeded);
    assert_no_dial(&blocked);
}

fn open_stream(core: &mut Core, port: u16) -> Vec<CoreOutput> {
    let destination = Destination::parse(&format!("1.1.1.1:{port}")).unwrap();
    core.handle(CoreInput::OpenStream { destination })
}

#[test]
fn reservation_sequences_match_an_independent_live_bytes_model() {
    for mut schedule in 0usize..6usize.pow(4) {
        let process = MemoryBudget::new(16).expect("process budget");
        let session = MemoryBudget::new(11).expect("session budget");
        let other_session_reservation = process.try_acquire(5).expect("other session");
        let mut reservations: VecDeque<ScopedMemoryReservation> = VecDeque::new();
        let mut model_charges: VecDeque<usize> = VecDeque::new();
        for _ in 0..4 {
            let action = schedule % 6;
            schedule /= 6;
            match action {
                0 | 1 | 2 | 5 => {
                    let bytes = match action {
                        0 => 3,
                        1 => 7,
                        2 => 0,
                        _ => usize::MAX,
                    };
                    let model_reserved_bytes: usize = model_charges.iter().sum();
                    let model_admits = model_reserved_bytes
                        .checked_add(bytes)
                        .is_some_and(|total_bytes| total_bytes <= 11);
                    let result = process.try_acquire_scoped(&session, bytes);
                    if model_admits {
                        let guard = result.expect("admission");
                        assert_eq!(guard.bytes(), bytes);
                        reservations.push_back(guard);
                        model_charges.push_back(bytes);
                    } else {
                        assert_eq!(result.unwrap_err(), EngineError::ResourceLimitExceeded);
                    }
                }
                3 => {
                    assert_eq!(
                        reservations.pop_front().map(|guard| guard.bytes()),
                        model_charges.pop_front()
                    );
                }
                4 => {
                    if let (Some(reservation), Some(bytes)) =
                        (reservations.front_mut(), model_charges.front_mut())
                    {
                        *bytes = (*bytes).min(1);
                        reservation.shrink_to(*bytes).expect("shrink");
                        assert_eq!(reservation.bytes(), *bytes);
                    }
                }
                _ => unreachable!("bounded action"),
            }
            let model_reserved_bytes: usize = model_charges.iter().sum();
            assert_eq!(session.used(), model_reserved_bytes);
            assert_eq!(process.used(), model_reserved_bytes + 5);
        }
        drop(reservations);
        assert_eq!(session.used(), 0);
        assert_eq!(process.used(), 5);
        drop(other_session_reservation);
        assert_eq!(process.used(), 0);
    }
}

#[test]
fn zero_byte_operations_still_exhaust_object_admission_and_release_on_drop() {
    let memory = MemoryBudget::new(8).expect("memory budget");
    let process = ResourceBudget::new(4).expect("process objects");
    let session = ResourceBudget::new(2).expect("session objects");
    let first = (
        memory.try_acquire(0).expect("zero bytes"),
        process.try_acquire_scoped(&session).expect("first object"),
    );
    let second = (
        memory.try_acquire(0).expect("zero bytes"),
        process.try_acquire_scoped(&session).expect("second object"),
    );
    assert_eq!(memory.used(), 0);
    assert_eq!(process.used(), 2);
    assert_eq!(session.used(), 2);
    assert_eq!(
        process.try_acquire_scoped(&session).unwrap_err(),
        EngineError::ResourceLimitExceeded
    );
    assert_eq!(process.used(), 2);
    drop(first);
    let replacement = process
        .try_acquire_scoped(&session)
        .expect("replacement object");
    drop(second);
    drop(replacement);
    assert_eq!(process.used(), 0);
    assert_eq!(session.used(), 0);
    assert_eq!(memory.used(), 0);
}
