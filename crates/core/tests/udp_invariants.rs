#![forbid(unsafe_code)]

use std::collections::VecDeque;

use ariad_core::{
    BudgetLimits, DatagramOutcome, DeliveryMode, EngineError, PathChange, UdpAssociation,
};

#[test]
fn bounded_datagram_sequences_preserve_generation_and_queue_contents() {
    let mut limits = BudgetLimits::lab_small();
    limits.udp_queue_bytes = 5;
    limits.udp_queue_datagrams = 2;
    limits.udp_payload_absolute_max = 12;
    for mode in [
        DeliveryMode::UnreliableNative,
        DeliveryMode::ReliableEncapsulation,
    ] {
        for mut schedule in 0usize..6usize.pow(4) {
            let mut association = UdpAssociation::open(3, mode, limits, 17).expect("association");
            let mut expected_generation = 3;
            let mut expected_queue: VecDeque<Vec<u8>> = VecDeque::new();
            for _ in 0..4 {
                let action = schedule % 6;
                schedule /= 6;
                match action {
                    0 | 1 => {
                        let payload: &[u8] = if action == 0 { b"abc" } else { &[] };
                        let queued_payload_bytes: usize = expected_queue.iter().map(Vec::len).sum();
                        let queue_has_capacity =
                            expected_queue.len() < 2 && queued_payload_bytes + payload.len() <= 5;
                        let expected = if queue_has_capacity {
                            DatagramOutcome::Queued
                        } else {
                            DatagramOutcome::Dropped
                        };
                        assert_eq!(association.push(expected_generation, payload), Ok(expected));
                        if queue_has_capacity {
                            expected_queue.push_back(payload.to_vec());
                        }
                    }
                    2 => {
                        assert_eq!(
                            association.push(expected_generation - 1, b"old"),
                            Ok(DatagramOutcome::Dropped)
                        );
                    }
                    3 => assert_eq!(association.pop(), expected_queue.pop_front()),
                    4 => {
                        expected_generation += 1;
                        assert_eq!(
                            association.rebind(),
                            Ok((expected_generation, PathChange::Superseded))
                        );
                        expected_queue.clear();
                    }
                    5 => {
                        let oversized = vec![0u8; association.max_payload() + 1];
                        assert_eq!(
                            association.push(expected_generation, &oversized),
                            Err(EngineError::MessageTooLarge)
                        );
                        assert_eq!(
                            association.send(&oversized),
                            Err(EngineError::MessageTooLarge)
                        );
                    }
                    _ => unreachable!("bounded action"),
                }
                assert_eq!(association.len(), expected_queue.len());
                assert_eq!(association.generation(), expected_generation);
                assert_eq!(association.mode(), mode);
            }
            while let Some(payload) = expected_queue.pop_front() {
                assert_eq!(association.pop(), Some(payload));
            }
            assert_eq!(association.pop(), None);
        }
    }
}

#[test]
fn terminal_associations_discard_queued_data_and_never_resume_delivery() {
    for cancel in [false, true] {
        for mode in [
            DeliveryMode::UnreliableNative,
            DeliveryMode::ReliableEncapsulation,
        ] {
            let mut association =
                UdpAssociation::open(9, mode, BudgetLimits::lab_small(), 0).expect("association");
            assert_eq!(association.push(9, b"queued"), Ok(DatagramOutcome::Queued));
            if cancel {
                association.cancel().expect("cancel");
            } else {
                association.close().expect("close");
            }
            assert!(association.is_empty());
            assert_eq!(association.pop(), None);
            for generation in [8, 9, 10] {
                assert_eq!(
                    association.push(generation, b"late"),
                    Ok(DatagramOutcome::Dropped)
                );
            }
            assert_eq!(
                association.send(b"late"),
                Err(EngineError::ProtocolViolation)
            );
            let oversized = vec![0; association.max_payload() + 1];
            assert_eq!(
                association.send(&oversized),
                Err(EngineError::ProtocolViolation)
            );
            assert_eq!(association.rebind(), Err(EngineError::ProtocolViolation));
        }
    }
}

#[test]
fn generation_overflow_preserves_the_existing_queue() {
    let mut association = UdpAssociation::open(
        u64::MAX,
        DeliveryMode::ReliableEncapsulation,
        BudgetLimits::lab_small(),
        0,
    )
    .expect("association");
    assert_eq!(
        association.push(u64::MAX, b"retained"),
        Ok(DatagramOutcome::Queued)
    );
    assert_eq!(
        association.rebind(),
        Err(EngineError::ResourceLimitExceeded)
    );
    assert_eq!(association.generation(), u64::MAX);
    assert_eq!(association.pop().as_deref(), Some(b"retained".as_slice()));
    assert_eq!(
        association.push(0, b"wrapped"),
        Ok(DatagramOutcome::Dropped)
    );
}
