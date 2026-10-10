#![forbid(unsafe_code)]

use std::collections::VecDeque;

use crate::association::{
    AssociationEffect, AssociationInput, AssociationMachine, AssociationPhase,
};
use crate::budget::BudgetLimits;
use crate::capability::DeliveryMode;
use crate::capsule::{datagram_max_payload, encode_datagram_capsule, encode_http_datagram};
use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramAdmit {
    Queue,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    Queued,
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChange {
    Superseded,
}

/// Checks a payload against its byte limit and current queue occupancy.
/// `queue_bytes` and `queue_datagrams` are limits; `queued_bytes` and
/// `queued_count` are current payload bytes and datagram count. Oversized
/// payloads return `MessageTooLarge`, accounting overflow returns
/// `ResourceLimitExceeded`, and a full queue returns `Drop`.
pub fn admit_datagram(
    max_payload: usize,
    queue_bytes: usize,
    queue_datagrams: usize,
    queued_bytes: usize,
    queued_count: usize,
    payload_len: usize,
) -> Result<DatagramAdmit, EngineError> {
    if payload_len > max_payload {
        return Err(EngineError::MessageTooLarge);
    }
    let next_queued_bytes = queued_bytes
        .checked_add(payload_len)
        .ok_or(EngineError::ResourceLimitExceeded)?;
    if queued_count >= queue_datagrams || next_queued_bytes > queue_bytes {
        Ok(DatagramAdmit::Drop)
    } else {
        Ok(DatagramAdmit::Queue)
    }
}

/// In-memory association state with a bounded FIFO of received payloads.
/// Generations separate datagrams from superseded paths.
pub struct UdpAssociation {
    machine: AssociationMachine,
    mode: DeliveryMode,
    limits: BudgetLimits,
    context_id: u64,
    max_payload_bytes: usize,
    queued_payload_bytes: usize,
    receive_queue: VecDeque<Vec<u8>>,
}

impl UdpAssociation {
    /// Creates bound association state for an encodable context and supported mode.
    /// The payload limit includes the effect of delivery framing overhead.
    pub fn open(
        generation: u64,
        mode: DeliveryMode,
        limits: BudgetLimits,
        context_id: u64,
    ) -> Result<Self, EngineError> {
        if mode == DeliveryMode::Unsupported {
            return Err(EngineError::UnsupportedCapability);
        }
        limits.validate()?;
        let max_payload_bytes = datagram_max_payload(
            mode == DeliveryMode::UnreliableNative,
            context_id,
            limits.udp_payload_absolute_max,
        )?;
        let mut machine = AssociationMachine::new(generation);
        machine.apply(AssociationInput::Authorized)?;
        machine.apply(AssociationInput::Bound)?;
        Ok(Self {
            machine,
            mode,
            limits,
            context_id,
            max_payload_bytes,
            queued_payload_bytes: 0,
            receive_queue: VecDeque::new(),
        })
    }

    pub const fn mode(&self) -> DeliveryMode {
        self.mode
    }

    pub const fn generation(&self) -> u64 {
        self.machine.generation()
    }

    /// Maximum payload bytes after subtracting this mode's encoding overhead.
    pub const fn max_payload(&self) -> usize {
        self.max_payload_bytes
    }

    pub fn len(&self) -> usize {
        self.receive_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receive_queue.is_empty()
    }

    /// Copies a current-generation payload into the receive queue.
    /// Stale or terminal datagrams are dropped before checking payload size.
    /// Full queues drop the new payload. Oversized current payloads return
    /// `MessageTooLarge`; allocation or accounting failure returns
    /// `ResourceLimitExceeded`. Errors preserve queued payloads and their byte count.
    pub fn push(
        &mut self,
        generation: u64,
        payload: &[u8],
    ) -> Result<DatagramOutcome, EngineError> {
        let effect = self
            .machine
            .apply(AssociationInput::Incoming { generation })?;
        if effect != AssociationEffect::Deliver {
            return Ok(DatagramOutcome::Dropped);
        }
        self.enqueue(payload)
    }

    /// Encodes an outgoing payload for the caller to transmit.
    /// Closed or cancelled associations return `ProtocolViolation`; oversized
    /// payloads return `MessageTooLarge`. Allocation failure returns `ResourceLimitExceeded`.
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, EngineError> {
        self.ensure_bound()?;
        if payload.len() > self.max_payload_bytes {
            return Err(EngineError::MessageTooLarge);
        }
        match self.mode {
            DeliveryMode::UnreliableNative => encode_http_datagram(self.context_id, payload),
            DeliveryMode::ReliableEncapsulation => {
                encode_datagram_capsule(self.context_id, payload)
            }
            DeliveryMode::Unsupported => Err(EngineError::UnsupportedCapability),
        }
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let payload = self.receive_queue.pop_front()?;
        self.queued_payload_bytes = self.queued_payload_bytes.saturating_sub(payload.len());
        Some(payload)
    }

    /// Advances a bound association's generation and discards queued payloads.
    /// Generation overflow returns `ResourceLimitExceeded` and preserves both
    /// generation and queue. Terminal associations return `ProtocolViolation`.
    pub fn rebind(&mut self) -> Result<(u64, PathChange), EngineError> {
        self.ensure_bound()?;
        let next_generation = self
            .machine
            .generation()
            .checked_add(1)
            .ok_or(EngineError::ResourceLimitExceeded)?;
        self.clear_receive_queue();
        self.machine.set_generation(next_generation);
        Ok((next_generation, PathChange::Superseded))
    }

    /// Closes a bound association and discards queued payloads.
    /// Repeated close succeeds; closing a cancelled association returns `ProtocolViolation`.
    pub fn close(&mut self) -> Result<(), EngineError> {
        if self.machine.phase() == AssociationPhase::Closed {
            return Ok(());
        }
        self.machine.apply(AssociationInput::Close)?;
        self.machine.apply(AssociationInput::Close)?;
        self.clear_receive_queue();
        Ok(())
    }

    /// Cancels the association and discards queued payloads.
    /// Repeated calls and calls after close succeed.
    pub fn cancel(&mut self) -> Result<(), EngineError> {
        if self.machine.phase().is_terminal() {
            return Ok(());
        }
        self.machine.apply(AssociationInput::Cancel)?;
        self.clear_receive_queue();
        Ok(())
    }

    fn ensure_bound(&self) -> Result<(), EngineError> {
        if self.machine.phase() != AssociationPhase::Bound {
            return Err(EngineError::ProtocolViolation);
        }
        Ok(())
    }

    fn clear_receive_queue(&mut self) {
        self.receive_queue.clear();
        self.queued_payload_bytes = 0;
    }

    fn enqueue(&mut self, payload: &[u8]) -> Result<DatagramOutcome, EngineError> {
        match admit_datagram(
            self.max_payload_bytes,
            self.limits.udp_queue_bytes,
            self.limits.udp_queue_datagrams,
            self.queued_payload_bytes,
            self.receive_queue.len(),
            payload.len(),
        )? {
            DatagramAdmit::Drop => Ok(DatagramOutcome::Dropped),
            DatagramAdmit::Queue => {
                self.receive_queue
                    .try_reserve(1)
                    .map_err(|_| EngineError::ResourceLimitExceeded)?;
                let mut owned_payload = Vec::new();
                owned_payload
                    .try_reserve_exact(payload.len())
                    .map_err(|_| EngineError::ResourceLimitExceeded)?;
                owned_payload.extend_from_slice(payload);
                self.queued_payload_bytes = self
                    .queued_payload_bytes
                    .checked_add(owned_payload.len())
                    .ok_or(EngineError::ResourceLimitExceeded)?;
                self.receive_queue.push_back(owned_payload);
                Ok(DatagramOutcome::Queued)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilitySet;

    fn association(mode: DeliveryMode) -> UdpAssociation {
        UdpAssociation::open(1, mode, BudgetLimits::lab_small(), 0).unwrap()
    }

    #[test]
    fn require_unreliable_does_not_silently_encapsulate() {
        let caps = CapabilitySet::v0_h2_only();
        assert_eq!(
            caps.resolve_delivery(true),
            Err(EngineError::UnsupportedCapability)
        );
        assert!(
            UdpAssociation::open(1, DeliveryMode::Unsupported, BudgetLimits::lab_small(), 0)
                .is_err()
        );
    }

    #[test]
    fn unencodable_context_is_rejected_before_opening() {
        for mode in [
            DeliveryMode::UnreliableNative,
            DeliveryMode::ReliableEncapsulation,
        ] {
            for context_id in [1u64 << 62, u64::MAX] {
                assert_eq!(
                    UdpAssociation::open(1, mode, BudgetLimits::lab_small(), context_id).err(),
                    Some(EngineError::MessageTooLarge)
                );
            }
        }
    }

    #[test]
    fn largest_context_round_trips_in_both_delivery_modes() {
        let context_id = (1u64 << 62) - 1;
        for mode in [
            DeliveryMode::UnreliableNative,
            DeliveryMode::ReliableEncapsulation,
        ] {
            let mut udp =
                UdpAssociation::open(1, mode, BudgetLimits::lab_small(), context_id).unwrap();
            let encoded = udp.send(b"ping").unwrap();
            let value = if mode == DeliveryMode::ReliableEncapsulation {
                let (capsule, consumed) = crate::capsule::decode_capsule(&encoded, 64).unwrap();
                assert_eq!(consumed, encoded.len());
                capsule.value
            } else {
                encoded.as_slice()
            };
            let (decoded_context, payload) = crate::capsule::split_http_datagram(value).unwrap();
            assert_eq!(decoded_context, context_id);
            assert_eq!(payload, b"ping");
            assert_eq!(udp.push(1, payload), Ok(DatagramOutcome::Queued));
            assert_eq!(udp.pop().unwrap(), b"ping");
        }
    }

    #[test]
    fn oversized_payload_is_rejected_before_queueing() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        let error = udp.push(1, &vec![0u8; 65_507]).expect_err("oversize");
        assert_eq!(error, EngineError::MessageTooLarge);
        assert_eq!(udp.len(), 0);
    }

    #[test]
    fn full_queue_drops_without_growing() {
        let mut limits = BudgetLimits::lab_small();
        limits.udp_queue_datagrams = 2;
        limits.udp_queue_bytes = 8;
        let mut udp =
            UdpAssociation::open(3, DeliveryMode::ReliableEncapsulation, limits, 0).unwrap();
        assert_eq!(udp.push(3, b"ab").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.push(3, b"cd").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.push(3, b"ef").unwrap(), DatagramOutcome::Dropped);
        assert_eq!(udp.len(), 2);
        assert_eq!(udp.pop().unwrap(), b"ab");
        assert_eq!(udp.pop().unwrap(), b"cd");
    }

    #[test]
    fn duplicates_stay_in_arrival_order() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        assert_eq!(udp.push(1, b"aa").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.push(1, b"aa").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.push(1, b"bb").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.pop().unwrap(), b"aa");
        assert_eq!(udp.pop().unwrap(), b"aa");
        assert_eq!(udp.pop().unwrap(), b"bb");
    }

    #[test]
    fn late_generation_does_not_enter_the_new_association() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        assert_eq!(udp.push(1, b"old").unwrap(), DatagramOutcome::Queued);
        let (generation, change) = udp.rebind().unwrap();
        assert_eq!(generation, 2);
        assert_eq!(change, PathChange::Superseded);
        assert!(udp.is_empty());
        assert_eq!(udp.push(1, b"late").unwrap(), DatagramOutcome::Dropped);
        assert!(udp.is_empty());
        assert_eq!(udp.push(2, b"new").unwrap(), DatagramOutcome::Queued);
        assert_eq!(udp.pop().unwrap(), b"new");
    }

    #[test]
    fn oversized_stale_datagram_is_dropped_before_payload_validation() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        let (generation, _) = udp.rebind().unwrap();
        let payload = vec![0u8; 65_507];
        assert_eq!(udp.push(1, &payload), Ok(DatagramOutcome::Dropped));
        assert!(udp.is_empty());
        assert_eq!(
            udp.push(generation, &payload),
            Err(EngineError::MessageTooLarge)
        );
        assert_eq!(udp.push(generation, b"new"), Ok(DatagramOutcome::Queued));
        assert_eq!(udp.pop().unwrap(), b"new");
    }

    #[test]
    fn failed_rebind_preserves_generation_and_queued_datagrams() {
        let mut udp = UdpAssociation::open(
            u64::MAX,
            DeliveryMode::ReliableEncapsulation,
            BudgetLimits::lab_small(),
            0,
        )
        .unwrap();
        assert_eq!(udp.push(u64::MAX, b"first"), Ok(DatagramOutcome::Queued));
        assert_eq!(udp.push(u64::MAX, b"second"), Ok(DatagramOutcome::Queued));
        assert_eq!(udp.rebind(), Err(EngineError::ResourceLimitExceeded));
        assert_eq!(udp.generation(), u64::MAX);
        assert_eq!(udp.len(), 2);
        assert_eq!(udp.queued_payload_bytes, 11);
        assert_eq!(udp.pop().unwrap(), b"first");
        assert_eq!(udp.pop().unwrap(), b"second");
        assert_eq!(
            udp.push(u64::MAX, b"still bound"),
            Ok(DatagramOutcome::Queued)
        );
    }

    #[test]
    fn closed_association_drops_without_queueing() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        udp.close().unwrap();
        assert_eq!(udp.push(1, b"late").unwrap(), DatagramOutcome::Dropped);
        assert!(udp.is_empty());
    }

    #[test]
    fn oversized_datagram_after_close_is_dropped() {
        let mut udp = association(DeliveryMode::ReliableEncapsulation);
        udp.close().unwrap();
        assert_eq!(
            udp.push(1, &vec![0u8; 65_507]),
            Ok(DatagramOutcome::Dropped)
        );
        assert!(udp.is_empty());
    }

    #[test]
    fn native_and_capsule_encodings_differ() {
        let mut native = association(DeliveryMode::UnreliableNative);
        let mut capsule = association(DeliveryMode::ReliableEncapsulation);
        let native_bytes = native.send(b"ping").unwrap();
        let capsule_bytes = capsule.send(b"ping").unwrap();
        assert_ne!(native_bytes, capsule_bytes);
        assert!(capsule_bytes.windows(4).any(|window| window == b"ping"));
        assert!(native_bytes.windows(4).any(|window| window == b"ping"));
    }

    #[test]
    fn many_drops_do_not_grow_the_queue() {
        let mut limits = BudgetLimits::lab_small();
        limits.udp_queue_datagrams = 1;
        limits.udp_queue_bytes = 4;
        let mut udp =
            UdpAssociation::open(1, DeliveryMode::ReliableEncapsulation, limits, 0).unwrap();
        assert_eq!(udp.push(1, b"ab").unwrap(), DatagramOutcome::Queued);
        for _ in 0..1_000 {
            assert_eq!(udp.push(1, b"cd").unwrap(), DatagramOutcome::Dropped);
        }
        assert_eq!(udp.len(), 1);
    }
}
