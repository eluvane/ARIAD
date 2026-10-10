#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ariad_core::{
    BindingId, Destination, EgressDecision, EgressDenyReason, EndpointDescriptor, EngineError,
    decide_egress, normalize_ip, validate_ip_target,
};

#[test]
fn parse_accepts_domain_name_and_ip_literals() {
    assert_eq!(
        Destination::parse("example.com:443"),
        Ok(Destination::Domain {
            name: "example.com".into(),
            port: 443,
        })
    );

    assert_eq!(
        Destination::parse("1.2.3.4:443"),
        Ok(Destination::Ip {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 443,
        })
    );

    assert_eq!(
        Destination::parse("[2001:db8::1]:443"),
        Ok(Destination::Ip {
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: 443,
        })
    );
}

#[test]
fn parse_rejects_missing_port_uri_userinfo_zero_and_leading_space() {
    for input in [
        "example.com",
        "http://example.com:80",
        "user@host:1",
        "example.com:0",
        " ex.com:1",
        "example.com:443/x",
        "example.com:443?x",
        "example.com:443#x",
    ] {
        assert_eq!(
            Destination::parse(input),
            Err(EngineError::InvalidConfig),
            "{input}"
        );
    }
}

#[test]
fn decide_egress_classifies_resolved_addresses() {
    let cases = [
        (
            ip("127.0.0.1"),
            EgressDecision::Deny(EgressDenyReason::Loopback),
        ),
        (
            ip("10.1.1.1"),
            EgressDecision::Deny(EgressDenyReason::Private),
        ),
        (
            ip("169.254.169.254"),
            EgressDecision::Deny(EgressDenyReason::Metadata),
        ),
        (
            ip("100.64.0.1"),
            EgressDecision::Deny(EgressDenyReason::Shared),
        ),
        (ip("8.8.8.8"), EgressDecision::Allow),
        (
            ip("255.255.255.255"),
            EgressDecision::Deny(EgressDenyReason::Broadcast),
        ),
        (
            ip("0.0.0.0"),
            EgressDecision::Deny(EgressDenyReason::Unspecified),
        ),
        (
            ip("169.254.1.1"),
            EgressDecision::Deny(EgressDenyReason::LinkLocal),
        ),
        (
            ip("224.0.0.1"),
            EgressDecision::Deny(EgressDenyReason::Multicast),
        ),
        (ip("::1"), EgressDecision::Deny(EgressDenyReason::Loopback)),
        (
            ip("fd00::1"),
            EgressDecision::Deny(EgressDenyReason::Private),
        ),
    ];
    for (addr, expected) in cases {
        assert_eq!(decide_egress(false, addr), expected, "{addr}");
    }

    let mapped = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
    assert_eq!(
        decide_egress(false, mapped),
        EgressDecision::Deny(EgressDenyReason::Loopback)
    );

    assert_eq!(decide_egress(true, ip("10.1.1.1")), EgressDecision::Allow);
    assert_eq!(decide_egress(true, ip("fd00::1")), EgressDecision::Allow);
    assert_eq!(
        decide_egress(true, ip("127.0.0.1")),
        EgressDecision::Deny(EgressDenyReason::Loopback)
    );
    assert_eq!(
        decide_egress(true, ip("::1")),
        EgressDecision::Deny(EgressDenyReason::Loopback)
    );
    assert_eq!(
        decide_egress(true, ip("169.254.169.254")),
        EgressDecision::Deny(EgressDenyReason::Metadata)
    );
    assert_eq!(
        decide_egress(true, ip("255.255.255.255")),
        EgressDecision::Deny(EgressDenyReason::Broadcast)
    );
}

#[test]
fn mapped_ip_normalization_preserves_address_classes() {
    for ipv4 in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(8, 8, 8, 8),
    ] {
        let original = IpAddr::V4(ipv4);
        let mapped = IpAddr::V6(ipv4.to_ipv6_mapped());
        assert_eq!(normalize_ip(original), original);
        assert_eq!(normalize_ip(mapped), original);
        for allow_private in [false, true] {
            assert_eq!(
                decide_egress(allow_private, mapped),
                decide_egress(allow_private, original)
            );
        }
    }
    for original in [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 1)),
        ip("2001:db8::1"),
    ] {
        assert_eq!(normalize_ip(original), original);
    }
}

#[test]
fn ip_target_validation_preserves_error_precedence_and_address_form() {
    let literal = |addr: &str, port| Destination::Ip {
        addr: ip(addr),
        port,
    };
    for (allow_private, destination, expected) in [
        (
            false,
            literal("127.0.0.1", 0),
            Err(EngineError::InvalidConfig),
        ),
        (
            false,
            Destination::Domain {
                name: "example.com".into(),
                port: 0,
            },
            Err(EngineError::InvalidConfig),
        ),
        (
            false,
            Destination::Domain {
                name: "invalid domain".into(),
                port: 443,
            },
            Err(EngineError::TargetResolutionFailed),
        ),
        (
            false,
            literal("10.0.0.1", 443),
            Err(EngineError::EgressDenied),
        ),
        (true, literal("10.0.0.1", 443), Ok(ip("10.0.0.1"))),
        (
            true,
            literal("127.0.0.1", 443),
            Err(EngineError::EgressDenied),
        ),
        (
            false,
            literal("::ffff:8.8.8.8", 443),
            Ok(ip("::ffff:8.8.8.8")),
        ),
    ] {
        assert_eq!(
            validate_ip_target(allow_private, &destination),
            expected,
            "{destination:?}, allow_private={allow_private}"
        );
    }
}

#[test]
fn endpoint_descriptor_accepts_example_com() {
    let endpoint = descriptor("example.com");
    assert_eq!(endpoint.validate(), Ok(()));
}

#[test]
fn endpoint_descriptor_rejects_empty_hostname() {
    let endpoint = descriptor("");
    assert_eq!(endpoint.validate(), Err(EngineError::InvalidConfig));
}

#[test]
fn endpoint_descriptor_rejects_malformed_hostnames() {
    for hostname in [
        "example.com\n",
        "example.com\r",
        "ex\tample.com",
        "example.com\0",
        "example.com\u{007f}",
        "ex\u{00e4}mple.com",
        "example.\u{ff11}",
        "example.com?query",
        "example.com#fragment",
        "ex\\ample.com",
        "example..com",
        ".",
        ".example.com",
        "-example.com",
        "example-.com",
        "example.com.",
    ] {
        let endpoint = descriptor(hostname);
        assert_eq!(
            endpoint.validate(),
            Err(EngineError::InvalidConfig),
            "{hostname:?}"
        );
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap_or_else(|_| panic!("ip literal {text}"))
}

fn descriptor(hostname: &str) -> EndpointDescriptor {
    EndpointDescriptor {
        id: 1,
        generation: 1,
        identity_hostname: hostname.into(),
        trust_group: 1,
        bindings: vec![BindingId::H2],
        ech_required: false,
    }
}
