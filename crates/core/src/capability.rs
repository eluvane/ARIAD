#![forbid(unsafe_code)]

use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingId {
    H2,

    H3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    UnreliableNative,
    ReliableEncapsulation,
    Unsupported,
}

/// Features reported by a transport binding.
///
/// Delivery selection uses these flags without negotiating peer support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    pub h2_streams: bool,
    pub h3: bool,
    pub unreliable_datagram: bool,

    pub ech: bool,
}

impl CapabilitySet {
    pub const fn v0_h2_only() -> Self {
        Self {
            h2_streams: true,
            h3: false,
            unreliable_datagram: false,
            ech: false,
        }
    }

    /// Select a delivery mode with reliable encapsulation allowed.
    ///
    /// Missing delivery support is returned as [`DeliveryMode::Unsupported`].
    pub fn udp_mode(self) -> DeliveryMode {
        self.resolve_delivery(false)
            .unwrap_or(DeliveryMode::Unsupported)
    }

    /// Prefer native unreliable datagrams when that capability is present.
    ///
    /// Otherwise, H2 streams or H3 allow reliable encapsulation unless
    /// `require_unreliable` is set. Return [`EngineError::UnsupportedCapability`]
    /// if no acceptable mode is available.
    pub fn resolve_delivery(self, require_unreliable: bool) -> Result<DeliveryMode, EngineError> {
        if self.unreliable_datagram {
            return Ok(DeliveryMode::UnreliableNative);
        }
        if require_unreliable {
            return Err(EngineError::UnsupportedCapability);
        }
        if self.h2_streams || self.h3 {
            Ok(DeliveryMode::ReliableEncapsulation)
        } else {
            Err(EngineError::UnsupportedCapability)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_h2_only_encapsulates_unless_unreliable_is_required() {
        let caps = CapabilitySet::v0_h2_only();
        assert_eq!(caps.udp_mode(), DeliveryMode::ReliableEncapsulation);
        assert_eq!(
            caps.resolve_delivery(true),
            Err(EngineError::UnsupportedCapability)
        );
        assert_eq!(
            caps.resolve_delivery(false),
            Ok(DeliveryMode::ReliableEncapsulation)
        );
    }

    #[test]
    fn unreliable_datagram_is_native_for_either_requirement() {
        let caps = CapabilitySet {
            h2_streams: false,
            h3: false,
            unreliable_datagram: true,
            ech: false,
        };
        assert_eq!(caps.udp_mode(), DeliveryMode::UnreliableNative);
        assert_eq!(
            caps.resolve_delivery(true),
            Ok(DeliveryMode::UnreliableNative)
        );
        assert_eq!(
            caps.resolve_delivery(false),
            Ok(DeliveryMode::UnreliableNative)
        );
    }
}
