#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use crate::error::EngineError;

/// A target host and port. Direct construction does not validate either field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Ip { addr: IpAddr, port: u16 },

    Domain { name: String, port: u16 },
}

impl Destination {
    /// Maximum ASCII domain length accepted by [`Self::parse`].
    pub const MAX_DOMAIN_BYTES: usize = 253;
    /// Maximum dot-separated label length accepted by [`Self::parse`].
    pub const MAX_LABEL_BYTES: usize = 63;

    /// Parse `host:port` or `[ipv6]:port` without DNS or egress checks.
    ///
    /// Ports contain decimal digits and must be in `1..=65535`; leading zeroes
    /// are accepted. IPv6 literals require brackets. Domains are lowercased
    /// ASCII names bounded by [`Self::MAX_DOMAIN_BYTES`]. Dot-separated labels
    /// are bounded by [`Self::MAX_LABEL_BYTES`] and contain letters, digits and
    /// internal hyphens. Empty labels and trailing dots are rejected.
    /// Rejected forms return [`EngineError::InvalidConfig`].
    pub fn parse(input: &str) -> Result<Self, EngineError> {
        if let Some(after_open) = input.strip_prefix('[') {
            return parse_bracketed_ipv6(after_open);
        }
        parse_host_port(input)
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip { port, .. } | Self::Domain { port, .. } => *port,
        }
    }

    /// Return the stored literal address, or `None` for a domain name.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip { addr, .. } => Some(*addr),
            Self::Domain { .. } => None,
        }
    }
}

/// Convert IPv4-mapped IPv6 addresses to IPv4. Other addresses are preserved.
#[must_use]
pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

fn parse_bracketed_ipv6(after_open: &str) -> Result<Destination, EngineError> {
    let Some((literal, after_close)) = after_open.split_once(']') else {
        return Err(EngineError::InvalidConfig);
    };
    let Some(port_text) = after_close.strip_prefix(':') else {
        return Err(EngineError::InvalidConfig);
    };
    let addr = Ipv6Addr::from_str(literal).map_err(|_| EngineError::InvalidConfig)?;
    let port = parse_port(port_text)?;
    Ok(Destination::Ip {
        addr: IpAddr::V6(addr),
        port,
    })
}

fn parse_host_port(input: &str) -> Result<Destination, EngineError> {
    let Some((host, port_text)) = input.rsplit_once(':') else {
        return Err(EngineError::InvalidConfig);
    };
    let port = parse_port(port_text)?;
    if host.contains(':') {
        return Err(EngineError::InvalidConfig);
    }
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(Destination::Ip { addr, port });
    }
    Ok(Destination::Domain {
        name: ascii_domain(host)?,
        port,
    })
}

fn parse_port(raw: &str) -> Result<u16, EngineError> {
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EngineError::InvalidConfig);
    }
    match raw.parse::<u16>() {
        Ok(0) | Err(_) => Err(EngineError::InvalidConfig),
        Ok(port) => Ok(port),
    }
}

fn ascii_domain(host: &str) -> Result<String, EngineError> {
    validate_ascii_domain(host)?;
    Ok(host.to_ascii_lowercase())
}

pub(crate) fn validate_ascii_domain(host: &str) -> Result<(), EngineError> {
    if host.len() > Destination::MAX_DOMAIN_BYTES {
        return Err(EngineError::InvalidConfig);
    }

    let mut label_bytes = 0;
    let mut previous_hyphen = false;
    for byte in host.bytes() {
        match byte {
            b'.' => {
                if label_bytes == 0 || previous_hyphen {
                    return Err(EngineError::InvalidConfig);
                }
                label_bytes = 0;
                previous_hyphen = false;
            }
            b'-' => {
                if label_bytes == 0 {
                    return Err(EngineError::InvalidConfig);
                }
                label_bytes += 1;
                previous_hyphen = true;
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => {
                label_bytes += 1;
                previous_hyphen = false;
            }
            _ => return Err(EngineError::InvalidConfig),
        }
        if label_bytes > Destination::MAX_LABEL_BYTES {
            return Err(EngineError::InvalidConfig);
        }
    }
    if label_bytes == 0 || previous_hyphen {
        return Err(EngineError::InvalidConfig);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::error::EngineError;

    use super::Destination;

    fn assert_invalid(input: &str) {
        assert_eq!(
            Destination::parse(input),
            Err(EngineError::InvalidConfig),
            "input {input:?}"
        );
    }

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            Destination::parse("example.com:443"),
            Ok(Destination::Domain {
                name: String::from("example.com"),
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
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            Destination::parse("[2001:db8::1]:443"),
            Ok(Destination::Ip {
                addr: v6,
                port: 443
            })
        );
        assert_eq!(
            Destination::parse("[2001:DB8::1]:443"),
            Ok(Destination::Ip {
                addr: v6,
                port: 443
            })
        );
    }

    #[test]
    fn parses_loopback_literal() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            Destination::parse("127.0.0.1:80"),
            Ok(Destination::Ip { addr, port: 80 })
        );
    }

    #[test]
    fn rejects_missing_port_scheme_userinfo_zero_port_and_leading_space() {
        for input in [
            "example.com",
            "http://example.com:80",
            "user@host:1",
            "example.com:0",
            " ex.com:1",
        ] {
            assert_invalid(input);
        }
    }

    #[test]
    fn normalizes_domains_and_accepts_strict_literals() {
        assert_eq!(
            Destination::parse("Example.COM:443"),
            Ok(Destination::Domain {
                name: String::from("example.com"),
                port: 443,
            })
        );
        assert_eq!(
            Destination::parse("localhost:80"),
            Ok(Destination::Domain {
                name: String::from("localhost"),
                port: 80,
            })
        );
        assert_eq!(
            Destination::parse("my-host.example:7"),
            Ok(Destination::Domain {
                name: String::from("my-host.example"),
                port: 7,
            })
        );
        assert_eq!(
            Destination::parse("127.1:80"),
            Ok(Destination::Domain {
                name: String::from("127.1"),
                port: 80,
            })
        );
        assert_eq!(
            Destination::parse("example.com:08"),
            Ok(Destination::Domain {
                name: String::from("example.com"),
                port: 8,
            })
        );
        assert_eq!(
            Destination::parse("example.com:65535"),
            Ok(Destination::Domain {
                name: String::from("example.com"),
                port: 65535,
            })
        );

        let max = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(max.len(), 253);
        assert_eq!(
            Destination::parse(&format!("{max}:2")),
            Ok(Destination::Domain { name: max, port: 2 })
        );

        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(
            Destination::parse("[::ffff:127.0.0.1]:80"),
            Ok(Destination::Ip {
                addr: mapped,
                port: 80,
            })
        );
    }

    #[test]
    fn dns_labels_are_bounded_in_every_position() {
        let max_label = "A".repeat(63);
        for host in [
            max_label.clone(),
            format!("{max_label}.test"),
            format!("first.{max_label}.test"),
            format!("first.{max_label}"),
            format!("{}-a.test", "a".repeat(61)),
        ] {
            assert_eq!(
                Destination::parse(&format!("{host}:443")),
                Ok(Destination::Domain {
                    name: host.to_ascii_lowercase(),
                    port: 443,
                }),
                "host {host:?}"
            );
        }

        let too_long_label = "a".repeat(64);
        for host in [
            too_long_label.clone(),
            format!("{too_long_label}.test"),
            format!("first.{too_long_label}.test"),
            format!("first.{too_long_label}"),
            format!("{}-a.test", "a".repeat(62)),
        ] {
            assert_invalid(&format!("{host}:443"));
        }
    }

    #[test]
    fn rejects_malformed_destinations() {
        for input in [
            "example.com:443 ",
            "example.com:443\n",
            "example.com:443\r",
            "ex\u{000b}.com:1",
            "example.com:1\u{007f}",
            "example.com:443/x",
            "example.com:443?x",
            "example.com:443#x",
            "a\\b:1",
            "ex\u{00e4}mple.com:1",
            "1.2.3.\u{ff14}:443",
            "1.2.3.4:\u{ff14}43",
            "example.com.:443",
            "-bad.com:1",
            "bad-.com:1",
            "bad.-example:1",
            "example..com:1",
            "[fe80::1%eth0]:443",
            "[::\u{ff11}]:443",
            "[ ::1]:443",
            "[::1 ]:443",
            "[::1\n]:443",
            "[::1/]:443",
            "[::1]:\u{ff14}43",
            "[::1]:443?x",
            "[1.2.3.4]:443",
            "[2001:db8::1]",
            "2001:db8::1:443",
            "[::1]:0",
            "1.2.3.4:0",
            "example.com:",
            "example.com:+443",
            "example.com:-1",
            "example.com:65536",
            "",
            "example.com:99999999999999999999",
            ":",
            ":443",
        ] {
            assert_invalid(input);
        }

        let too_long = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ]
        .join(".");
        assert_eq!(too_long.len(), 254);
        assert_invalid(&format!("{too_long}:1"));
    }

    #[test]
    fn port_and_as_ip_follow_the_variant() {
        let domain = Destination::Domain {
            name: String::from("example.com"),
            port: 443,
        };
        assert_eq!(domain.port(), 443);
        assert_eq!(domain.as_ip(), None);

        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip = Destination::Ip { addr, port: 443 };
        assert_eq!(ip.port(), 443);
        assert_eq!(ip.as_ip(), Some(addr));
    }
}
