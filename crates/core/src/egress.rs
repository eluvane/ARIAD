use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::address::{Destination, normalize_ip};
use crate::error::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenyReason {
    Loopback,

    Unspecified,

    LinkLocal,

    Private,

    Shared,

    Multicast,

    Broadcast,

    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny(EgressDenyReason),
}

/// Apply the target egress policy to one IP address.
///
/// IPv4-mapped IPv6 addresses use the IPv4 policy. `allow_private` permits
/// private and shared ranges; loopback, unspecified, link-local, multicast,
/// limited broadcast and the explicit metadata endpoints remain denied.
/// Addresses outside these classes are allowed; this is not a general test of
/// global routability.
#[must_use]
pub fn decide_egress(allow_private: bool, addr: IpAddr) -> EgressDecision {
    match normalize_ip(addr) {
        IpAddr::V4(addr) => classify_ipv4(allow_private, addr),
        IpAddr::V6(addr) => classify_ipv6(allow_private, addr),
    }
}

/// Return the stored IP of a nonzero-port target permitted by [`decide_egress`].
/// Zero ports return `InvalidConfig` before domain targets return
/// `TargetResolutionFailed`; denied IPs return `EgressDenied`.
/// The returned IP retains the destination's original address form.
pub fn validate_ip_target(
    allow_private: bool,
    destination: &Destination,
) -> Result<IpAddr, EngineError> {
    if destination.port() == 0 {
        return Err(EngineError::InvalidConfig);
    }
    let addr = destination
        .as_ip()
        .ok_or(EngineError::TargetResolutionFailed)?;
    if decide_egress(allow_private, addr) != EgressDecision::Allow {
        return Err(EngineError::EgressDenied);
    }
    Ok(addr)
}

fn classify_ipv4(allow_private: bool, addr: Ipv4Addr) -> EgressDecision {
    let [a, b, c, d] = addr.octets();

    if a == 127 {
        return EgressDecision::Deny(EgressDenyReason::Loopback);
    }
    if a == 0 && b == 0 && c == 0 && d == 0 {
        return EgressDecision::Deny(EgressDenyReason::Unspecified);
    }

    // Keep the metadata reason ahead of the enclosing link-local range.
    if a == 169 && b == 254 && c == 169 && d == 254 {
        return EgressDecision::Deny(EgressDenyReason::Metadata);
    }
    if a == 169 && b == 254 {
        return EgressDecision::Deny(EgressDenyReason::LinkLocal);
    }
    if !allow_private {
        if a == 10 || (a == 172 && (b & 0b1111_0000) == 0b0001_0000) || (a == 192 && b == 168) {
            return EgressDecision::Deny(EgressDenyReason::Private);
        }

        if a == 100 && (b & 0b1100_0000) == 0b0100_0000 {
            return EgressDecision::Deny(EgressDenyReason::Shared);
        }
    }

    if (a & 0b1111_0000) == 0b1110_0000 {
        return EgressDecision::Deny(EgressDenyReason::Multicast);
    }
    if a == 255 && b == 255 && c == 255 && d == 255 {
        return EgressDecision::Deny(EgressDenyReason::Broadcast);
    }
    EgressDecision::Allow
}

fn classify_ipv6(allow_private: bool, addr: Ipv6Addr) -> EgressDecision {
    if addr == Ipv6Addr::LOCALHOST {
        return EgressDecision::Deny(EgressDenyReason::Loopback);
    }
    if addr == Ipv6Addr::UNSPECIFIED {
        return EgressDecision::Deny(EgressDenyReason::Unspecified);
    }
    // This metadata address stays denied even when private egress is allowed.
    if addr == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        return EgressDecision::Deny(EgressDenyReason::Metadata);
    }

    let first_segment = addr.segments()[0];

    if (first_segment & 0b1111_1111_1100_0000) == 0xfe80 {
        return EgressDecision::Deny(EgressDenyReason::LinkLocal);
    }

    if !allow_private && (first_segment & 0b1111_1110_0000_0000) == 0xfc00 {
        return EgressDecision::Deny(EgressDenyReason::Private);
    }
    if (first_segment & 0b1111_1111_0000_0000) == 0xff00 {
        return EgressDecision::Deny(EgressDenyReason::Multicast);
    }
    EgressDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::{EgressDecision, EgressDenyReason, decide_egress};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        ))
    }

    fn deny(reason: EgressDenyReason) -> EgressDecision {
        EgressDecision::Deny(reason)
    }

    #[test]
    fn denies_ipv4_loopback() {
        assert_eq!(
            decide_egress(false, v4(127, 0, 0, 1)),
            deny(EgressDenyReason::Loopback)
        );
        assert_eq!(
            decide_egress(true, v4(127, 0, 0, 1)),
            deny(EgressDenyReason::Loopback)
        );
    }

    #[test]
    fn private_follows_allow_private() {
        assert_eq!(
            decide_egress(false, v4(10, 1, 1, 1)),
            deny(EgressDenyReason::Private)
        );
        assert_eq!(decide_egress(true, v4(10, 1, 1, 1)), EgressDecision::Allow);
    }

    #[test]
    fn denies_metadata_endpoints() {
        for metadata in [
            v4(169, 254, 169, 254),
            v6([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]),
        ] {
            for allow_private in [false, true] {
                assert_eq!(
                    decide_egress(allow_private, metadata),
                    deny(EgressDenyReason::Metadata),
                    "allow_private={allow_private} addr={metadata}"
                );
            }
        }
    }

    #[test]
    fn denies_shared_by_default() {
        assert_eq!(
            decide_egress(false, v4(100, 64, 0, 1)),
            deny(EgressDenyReason::Shared)
        );
        assert_eq!(
            decide_egress(true, v4(100, 64, 0, 1)),
            EgressDecision::Allow
        );
    }

    #[test]
    fn allows_public_dns() {
        assert_eq!(decide_egress(false, v4(8, 8, 8, 8)), EgressDecision::Allow);
        assert_eq!(decide_egress(false, v4(1, 1, 1, 1)), EgressDecision::Allow);
    }

    #[test]
    fn denies_ipv4_mapped_loopback() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(
            decide_egress(false, mapped),
            deny(EgressDenyReason::Loopback)
        );
        assert_eq!(
            decide_egress(true, mapped),
            deny(EgressDenyReason::Loopback)
        );
    }

    #[test]
    fn denies_limited_broadcast() {
        assert_eq!(
            decide_egress(false, v4(255, 255, 255, 255)),
            deny(EgressDenyReason::Broadcast)
        );
        assert_eq!(
            decide_egress(true, v4(255, 255, 255, 255)),
            deny(EgressDenyReason::Broadcast)
        );
    }

    #[test]
    fn ipv4_mapped_matches_inner_address() {
        let samples = [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(10, 1, 1, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
        ];
        for allow_private in [false, true] {
            for sample in samples {
                let plain = IpAddr::V4(sample);
                let mapped = IpAddr::V6(sample.to_ipv6_mapped());
                assert_eq!(
                    decide_egress(allow_private, plain),
                    decide_egress(allow_private, mapped),
                    "mapped mismatch for {sample} allow_private={allow_private}"
                );
            }
        }
    }

    #[test]
    fn prefix_boundaries_and_ipv6_classes() {
        let cases = [
            (
                false,
                v4(127, 255, 255, 255),
                deny(EgressDenyReason::Loopback),
            ),
            (false, v4(0, 0, 0, 0), deny(EgressDenyReason::Unspecified)),
            (false, v4(0, 0, 0, 1), EgressDecision::Allow),
            (false, v4(169, 254, 0, 1), deny(EgressDenyReason::LinkLocal)),
            (true, v4(169, 254, 0, 1), deny(EgressDenyReason::LinkLocal)),
            (
                false,
                v4(10, 255, 255, 255),
                deny(EgressDenyReason::Private),
            ),
            (false, v4(11, 0, 0, 1), EgressDecision::Allow),
            (false, v4(172, 16, 0, 0), deny(EgressDenyReason::Private)),
            (
                false,
                v4(172, 31, 255, 255),
                deny(EgressDenyReason::Private),
            ),
            (false, v4(172, 15, 255, 255), EgressDecision::Allow),
            (false, v4(172, 32, 0, 1), EgressDecision::Allow),
            (true, v4(172, 16, 5, 5), EgressDecision::Allow),
            (false, v4(192, 168, 0, 1), deny(EgressDenyReason::Private)),
            (false, v4(192, 169, 0, 1), EgressDecision::Allow),
            (false, v4(100, 64, 0, 0), deny(EgressDenyReason::Shared)),
            (
                false,
                v4(100, 127, 255, 255),
                deny(EgressDenyReason::Shared),
            ),
            (false, v4(100, 63, 255, 255), EgressDecision::Allow),
            (false, v4(100, 128, 0, 1), EgressDecision::Allow),
            (false, v4(224, 0, 0, 1), deny(EgressDenyReason::Multicast)),
            (
                false,
                v4(239, 255, 255, 255),
                deny(EgressDenyReason::Multicast),
            ),
            (true, v4(224, 0, 0, 1), deny(EgressDenyReason::Multicast)),
            (false, v4(240, 0, 0, 1), EgressDecision::Allow),
            (false, v4(192, 0, 2, 1), EgressDecision::Allow),
            (false, v4(198, 18, 0, 1), EgressDecision::Allow),
            (
                false,
                v6([0, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Loopback),
            ),
            (
                true,
                v6([0, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Loopback),
            ),
            (
                false,
                v6([0, 0, 0, 0, 0, 0, 0, 0]),
                deny(EgressDenyReason::Unspecified),
            ),
            (
                false,
                v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::LinkLocal),
            ),
            (
                true,
                v6([0xfebf, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::LinkLocal),
            ),
            (
                false,
                v6([0xfec0, 0, 0, 0, 0, 0, 0, 1]),
                EgressDecision::Allow,
            ),
            (
                false,
                v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Private),
            ),
            (
                false,
                v6([0xfd12, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Private),
            ),
            (
                true,
                v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]),
                EgressDecision::Allow,
            ),
            (
                false,
                v6([0xff00, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Multicast),
            ),
            (
                true,
                v6([0xff02, 0, 0, 0, 0, 0, 0, 1]),
                deny(EgressDenyReason::Multicast),
            ),
            (
                false,
                v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]),
                EgressDecision::Allow,
            ),
            (
                false,
                v6([0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1]),
                EgressDecision::Allow,
            ),
        ];

        for (allow_private, addr, expected) in cases {
            assert_eq!(
                decide_egress(allow_private, addr),
                expected,
                "allow_private={allow_private} addr={addr}"
            );
        }
    }
}
