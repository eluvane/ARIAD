#![forbid(unsafe_code)]

use ariad_core::{BudgetLimits, Destination, EngineError};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};

use crate::connect::{attach_h2_versions, single_header_value, validate_h2_versions};

/// Extended CONNECT protocol token for UDP proxying.
pub const CONNECT_UDP: &str = "connect-udp";
/// Header that opts a flow into capsule framing.
pub const CAPSULE_PROTOCOL: &str = "capsule-protocol";
/// Ariad header carrying a peer's payload limit in bytes, excluding encapsulation.
pub const MAX_DATAGRAM_PAYLOAD: &str = "x-ariad-max-datagram-payload";
pub(crate) const CAPSULE_PROTOCOL_ENABLED: &str = "?1";
/// CONNECT-UDP uses only the default datagram context.
pub(crate) const CONNECT_UDP_CONTEXT_ID: u64 = 0;
const CONNECT_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp/";
const MAX_PORT_DIGITS: usize = u16::MAX.ilog10() as usize + 1;
const MAX_PROXY_AUTHORITY_BYTES: usize = Destination::MAX_DOMAIN_BYTES + 1 + MAX_PORT_DIGITS;

/// Builds an HTTPS CONNECT-UDP template with capsule and H2 version headers.
/// `proxy` is a URI authority with an optional nonzero decimal port. The target
/// port must be nonzero; its host is escaped as a URI path segment. No credential
/// is attached, and target authorization is a separate step.
pub fn connect_udp_template(proxy: &str, target: &Destination) -> Result<Request<()>, EngineError> {
    if target.port() == 0
        || proxy.is_empty()
        || proxy.len() > MAX_PROXY_AUTHORITY_BYTES
        || proxy.contains('/')
        || proxy.contains(' ')
        || proxy.contains('@')
        || proxy.contains('\\')
        || proxy.contains('?')
        || proxy.contains('#')
    {
        return Err(EngineError::InvalidConfig);
    }
    let host_segment = encode_target_host(target)?;
    let path = format!("{CONNECT_UDP_PATH_PREFIX}{host_segment}/{}/", target.port());
    let uri: Uri = format!("https://{proxy}{path}")
        .parse()
        .map_err(|_| EngineError::InvalidConfig)?;
    let authority = uri.authority().ok_or(EngineError::InvalidConfig)?;
    // Port lookup also returns None for an invalid explicit port.
    let proxy_has_port = authority.as_str().len() > authority.host().len();
    let target_port = target.port().to_string();
    if uri.host().is_none_or(str::is_empty)
        || (proxy_has_port
            && authority.port().is_none_or(|port| {
                port.as_u16() == 0 || !port.as_str().bytes().all(|byte| byte.is_ascii_digit())
            }))
        || !uri.path().starts_with(CONNECT_UDP_PATH_PREFIX)
        || !uri.path().ends_with(&format!("/{target_port}/"))
    {
        return Err(EngineError::InvalidConfig);
    }
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .map_err(|_| EngineError::InvalidConfig)?;
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(CONNECT_UDP));
    request.headers_mut().insert(
        CAPSULE_PROTOCOL,
        HeaderValue::from_static(CAPSULE_PROTOCOL_ENABLED),
    );
    attach_h2_versions(request.headers_mut())?;
    Ok(request)
}

/// Tests only the CONNECT method and extended protocol token.
/// Request syntax, versions, capsule negotiation, and credentials are unchecked.
pub fn is_connect_udp<B>(request: &Request<B>) -> bool {
    request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<h2::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str() == CONNECT_UDP)
}

/// True only for one `capsule-protocol` field with the exact value `?1`.
pub fn capsule_protocol_enabled(headers: &HeaderMap) -> bool {
    matches!(single_header_value(headers, CAPSULE_PROTOCOL), Ok(Some(value)) if value.as_bytes() == CAPSULE_PROTOCOL_ENABLED.as_bytes())
}

/// Rejects Capsule-forbidden statuses and Content-Length, Content-Type, or Transfer-Encoding.
/// Call only for successful Capsule negotiation, after HTTP error classification.
pub(crate) fn validate_capsule_response(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<(), EngineError> {
    if matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::PARTIAL_CONTENT
    ) || has_capsule_content_headers(headers)
    {
        return Err(EngineError::ProtocolViolation);
    }
    Ok(())
}

fn has_capsule_content_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(http::header::CONTENT_LENGTH)
        || headers.contains_key(http::header::CONTENT_TYPE)
        || headers.contains_key(http::header::TRANSFER_ENCODING)
}

/// Parses a single canonical nonzero decimal payload limit, bounded by
/// [`BudgetLimits::UDP_PAYLOAD_ABSOLUTE_CEILING`].
/// Absence returns `None`; duplicates, invalid syntax, and values outside this
/// range return `ProtocolViolation`. Callers apply the peer limit to local limits.
pub fn negotiated_datagram_payload(headers: &HeaderMap) -> Result<Option<usize>, EngineError> {
    let Some(value) = headers.get(MAX_DATAGRAM_PAYLOAD) else {
        return Ok(None);
    };
    let text = value.to_str().map_err(|_| EngineError::ProtocolViolation)?;
    let _ = single_header_value(headers, MAX_DATAGRAM_PAYLOAD)?;
    if text.is_empty()
        || text.len() > BudgetLimits::UDP_PAYLOAD_ABSOLUTE_CEILING.ilog10() as usize + 1
        || text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EngineError::ProtocolViolation);
    }
    let limit = text
        .parse::<usize>()
        .map_err(|_| EngineError::ProtocolViolation)?;
    if limit > BudgetLimits::UDP_PAYLOAD_ABSOLUTE_CEILING {
        return Err(EngineError::ProtocolViolation);
    }
    Ok(Some(limit))
}

/// Checks H2 versions and CONNECT-UDP request syntax, then parses the MASQUE target.
/// Requires HTTPS, a URI authority, exact capsule opt-in, and no query.
/// Content-Length, Content-Type, and Transfer-Encoding are forbidden.
/// Malformed requests return `ProtocolViolation`; allocation failure can return
/// `ResourceLimitExceeded`. Credentials, DNS, and egress policy are checked separately.
pub fn target_of_connect_udp<B>(request: &Request<B>) -> Result<Destination, EngineError> {
    validate_h2_versions(request.headers())?;
    target_of_connect_udp_unversioned(request)
}

/// Parses the same request syntax as `target_of_connect_udp` without H2 version checks.
/// The H3 caller must check its binding versions and authorize the parsed target.
pub(crate) fn target_of_connect_udp_unversioned<B>(
    request: &Request<B>,
) -> Result<Destination, EngineError> {
    if !is_connect_udp(request)
        || request.uri().scheme_str() != Some("https")
        || request.uri().authority().is_none()
        || request.uri().query().is_some()
        || !capsule_protocol_enabled(request.headers())
        || has_capsule_content_headers(request.headers())
    {
        return Err(EngineError::ProtocolViolation);
    }
    let path = request
        .uri()
        .path()
        .strip_prefix(CONNECT_UDP_PATH_PREFIX)
        .and_then(|path| path.strip_suffix('/'))
        .ok_or(EngineError::ProtocolViolation)?;
    let (host_segment, port) = path.split_once('/').ok_or(EngineError::ProtocolViolation)?;
    if host_segment.is_empty()
        || port.is_empty()
        || port.len() > MAX_PORT_DIGITS
        || port.contains('/')
        || host_segment.len() > 3 * Destination::MAX_DOMAIN_BYTES
    {
        return Err(EngineError::ProtocolViolation);
    }
    let host = decode_host_segment(host_segment)?;
    let target_authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Destination::parse(&target_authority).map_err(|_| EngineError::ProtocolViolation)
}

fn decode_host_segment(segment: &str) -> Result<String, EngineError> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(segment.len())
        .map_err(|_| EngineError::ResourceLimitExceeded)?;
    let mut input = segment.bytes();
    while let Some(byte) = input.next() {
        let byte = if byte == b'%' {
            let high = input
                .next()
                .and_then(hex_nibble)
                .ok_or(EngineError::ProtocolViolation)?;
            let low = input
                .next()
                .and_then(hex_nibble)
                .ok_or(EngineError::ProtocolViolation)?;
            high << 4 | low
        } else {
            byte
        };
        if !byte.is_ascii()
            || byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || is_reserved_host_byte(byte)
        {
            return Err(EngineError::ProtocolViolation);
        }
        decoded.push(byte);
    }
    String::from_utf8(decoded).map_err(|_| EngineError::ProtocolViolation)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_reserved_host_byte(byte: u8) -> bool {
    matches!(byte, b'/' | b'%' | b'?' | b'#' | b'@' | b'\\' | b'[' | b']')
}

fn encode_target_host(target: &Destination) -> Result<String, EngineError> {
    match target {
        Destination::Domain { name, .. } => {
            if name.is_empty()
                || name.len() > Destination::MAX_DOMAIN_BYTES
                || !name.is_ascii()
                || name
                    .bytes()
                    .any(|byte| matches!(byte, b':' | b' ') || is_reserved_host_byte(byte))
            {
                Err(EngineError::InvalidConfig)
            } else {
                // Keep invalid URI bytes rejected before percent-encoding hides them.
                format!("/{name}")
                    .parse::<http::uri::PathAndQuery>()
                    .map_err(|_| EngineError::InvalidConfig)?;
                Ok(encode_path_segment(name))
            }
        }
        Destination::Ip { addr, .. } => match addr {
            std::net::IpAddr::V4(ip) => Ok(ip.to_string()),
            std::net::IpAddr::V6(ip) => Ok(encode_path_segment(&ip.to_string())),
        },
    }
}

fn encode_path_segment(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_udp_uses_the_registered_protocol_and_path() {
        let target = Destination::parse("1.1.1.1:9").unwrap();
        let request = connect_udp_template("proxy.example:443", &target).unwrap();
        assert_eq!(*request.method(), Method::CONNECT);
        assert_eq!(request.uri().path(), "/.well-known/masque/udp/1.1.1.1/9/");
        assert_eq!(CONNECT_UDP, "connect-udp");
        assert!(capsule_protocol_enabled(request.headers()));
        assert_eq!(
            request
                .extensions()
                .get::<h2::ext::Protocol>()
                .unwrap()
                .as_str(),
            CONNECT_UDP
        );
    }

    #[test]
    fn server_target_parser_round_trips_supported_destinations() {
        for input in ["example.com:443", "1.1.1.1:9", "[2001:db8::1]:443"] {
            let target = Destination::parse(input).unwrap();
            let request = connect_udp_template("proxy.example", &target).unwrap();
            assert_eq!(target_of_connect_udp(&request), Ok(target));
        }
        let name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let target = Destination::parse(&format!("{name}:7")).unwrap();
        let request = connect_udp_template("proxy.example", &target).unwrap();
        assert_eq!(target_of_connect_udp(&request), Ok(target));
    }

    #[test]
    fn malformed_target_and_capsule_negotiation_fail_closed() {
        let target = Destination::parse("example.com:443").unwrap();
        for path in [
            "/.well-known/masque/udp/example.com/0/",
            "/.well-known/masque/udp/example.com/65536/",
            "/.well-known/masque/udp/example.com/+7/",
            "/.well-known/masque/udp/example.com/7/extra/",
            "/.well-known/masque/udp/example.com%2Fsecret/7/",
            "/.well-known/masque/udp/example.com%00/7/",
            "/.well-known/masque/udp/example.com%25/7/",
            "/.well-known/masque/udp/example.com%3F/7/",
            "/.well-known/masque/udp/example.com%23/7/",
            "/.well-known/masque/udp/example.com%40/7/",
            "/.well-known/masque/udp/example.com%5C/7/",
            "/.well-known/masque/udp/example.com%5B/7/",
            "/.well-known/masque/udp/example.com%5D/7/",
            "/.well-known/masque/udp/example.com%/7/",
            "/.well-known/masque/udp/example.com/7/?x=1",
        ] {
            let mut request = connect_udp_template("proxy.example", &target).unwrap();
            *request.uri_mut() = format!("https://proxy.example{path}").parse().unwrap();
            assert_eq!(
                target_of_connect_udp(&request),
                Err(EngineError::ProtocolViolation)
            );
        }
        for value in ["?0", "1", "?1, ?1", "true"] {
            let mut request = connect_udp_template("proxy.example", &target).unwrap();
            request
                .headers_mut()
                .insert(CAPSULE_PROTOCOL, value.parse().unwrap());
            assert_eq!(
                target_of_connect_udp(&request),
                Err(EngineError::ProtocolViolation)
            );
        }
        let mut request = connect_udp_template("proxy.example", &target).unwrap();
        request
            .headers_mut()
            .append(CAPSULE_PROTOCOL, HeaderValue::from_static("?1"));
        assert_eq!(
            target_of_connect_udp(&request),
            Err(EngineError::ProtocolViolation)
        );
    }

    #[test]
    fn connect_udp_rejects_capsule_content_headers_for_both_bindings() {
        let target = Destination::parse("example.com:443").unwrap();
        let request = connect_udp_template("proxy.example", &target).unwrap();
        assert_eq!(target_of_connect_udp(&request), Ok(target.clone()));
        assert_eq!(
            target_of_connect_udp_unversioned(&request),
            Ok(target.clone())
        );
        for (name, value) in [
            (http::header::CONTENT_LENGTH, "0"),
            (http::header::CONTENT_TYPE, "application/octet-stream"),
            (http::header::TRANSFER_ENCODING, "chunked"),
        ] {
            for value in ["", value] {
                let mut request = connect_udp_template("proxy.example", &target).unwrap();
                request
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static(value));
                assert_eq!(
                    target_of_connect_udp(&request),
                    Err(EngineError::ProtocolViolation),
                    "{name}: {value:?}"
                );
                assert_eq!(
                    target_of_connect_udp_unversioned(&request),
                    Err(EngineError::ProtocolViolation),
                    "{name}: {value:?}"
                );
            }
        }
    }

    #[test]
    fn capsule_response_status_boundaries() {
        let mut headers = HeaderMap::new();
        headers.insert(CAPSULE_PROTOCOL, HeaderValue::from_static("?1"));
        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::PARTIAL_CONTENT,
        ] {
            assert_eq!(
                validate_capsule_response(status, &headers),
                Err(EngineError::ProtocolViolation)
            );
        }
        for code in [200, 203, 207, 299] {
            let status = StatusCode::from_u16(code).unwrap();
            assert_eq!(validate_capsule_response(status, &headers), Ok(()));
        }
    }

    #[test]
    fn capsule_response_rejects_content_headers() {
        for (name, value) in [
            (http::header::CONTENT_LENGTH, "0"),
            (http::header::CONTENT_TYPE, "application/octet-stream"),
            (http::header::TRANSFER_ENCODING, "chunked"),
        ] {
            for value in ["", value] {
                let mut headers = HeaderMap::new();
                headers.insert(CAPSULE_PROTOCOL, HeaderValue::from_static("?1"));
                headers.insert(name.clone(), HeaderValue::from_static(value));
                assert_eq!(
                    validate_capsule_response(StatusCode::OK, &headers),
                    Err(EngineError::ProtocolViolation),
                    "{name}: {value:?}"
                );
            }
        }
    }

    #[test]
    fn negotiated_payload_limit_is_single_bounded_canonical_decimal() {
        let mut headers = HeaderMap::new();
        assert_eq!(negotiated_datagram_payload(&headers), Ok(None));
        for value in ["1", "1200", "65507"] {
            headers.insert(MAX_DATAGRAM_PAYLOAD, value.parse().unwrap());
            assert_eq!(
                negotiated_datagram_payload(&headers),
                Ok(Some(value.parse().unwrap()))
            );
        }
        for value in ["0", "01", "+1", "-1", "65508", "999999", "1 ", "1, 2"] {
            headers.insert(MAX_DATAGRAM_PAYLOAD, value.parse().unwrap());
            assert_eq!(
                negotiated_datagram_payload(&headers),
                Err(EngineError::ProtocolViolation)
            );
        }
        headers.insert(MAX_DATAGRAM_PAYLOAD, HeaderValue::from_static("1200"));
        headers.append(MAX_DATAGRAM_PAYLOAD, HeaderValue::from_static("1200"));
        assert_eq!(
            negotiated_datagram_payload(&headers),
            Err(EngineError::ProtocolViolation)
        );
    }

    #[test]
    fn ipv6_target_is_percent_encoded() {
        let target = Destination::parse("[2001:db8::1]:443").unwrap();
        let request = connect_udp_template("proxy.example", &target).unwrap();
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"
        );
        assert_eq!(
            request
                .extensions()
                .get::<h2::ext::Protocol>()
                .unwrap()
                .as_str(),
            "connect-udp"
        );
    }

    #[test]
    fn domain_target_uses_uri_template_encoding() {
        for (name, segment) in [
            ("a+b.example", "a%2Bb.example"),
            ("a;b.example", "a%3Bb.example"),
            ("A-B.example", "A-B.example"),
            ("a_b.example", "a_b.example"),
            ("a~b.example", "a~b.example"),
        ] {
            let target = Destination::Domain {
                name: name.to_string(),
                port: 443,
            };
            let request = connect_udp_template("proxy.example", &target).unwrap();
            assert_eq!(
                request.uri().path(),
                format!("/.well-known/masque/udp/{segment}/443/")
            );
        }
    }

    #[test]
    fn invalid_domain_hosts_are_rejected_before_encoding() {
        for name in [
            "a\n.example",
            "a\t.example",
            "a\0.example",
            "a\u{007f}.example",
            "a<.example",
            "a>.example",
            "a`.example",
            "example/com",
            "example%com",
            "example?com",
            "example#com",
            "user@example.com",
            "example\\com",
            "[example.com",
            "example.com]",
            "example:443",
            "example com",
            "ex\u{00e4}mple.com",
        ] {
            let target = Destination::Domain {
                name: name.to_string(),
                port: 443,
            };
            assert_eq!(
                connect_udp_template("proxy.example", &target).unwrap_err(),
                EngineError::InvalidConfig,
                "{name:?}"
            );
        }
    }

    #[test]
    fn zero_target_port_is_rejected() {
        let targets = [
            Destination::Domain {
                name: "example.com".to_string(),
                port: 0,
            },
            Destination::Ip {
                addr: "1.1.1.1".parse().unwrap(),
                port: 0,
            },
            Destination::Ip {
                addr: "2001:db8::1".parse().unwrap(),
                port: 0,
            },
        ];
        for target in targets {
            assert_eq!(
                connect_udp_template("proxy.example", &target).unwrap_err(),
                EngineError::InvalidConfig
            );
        }
    }

    #[test]
    fn empty_proxy_host_is_rejected() {
        let target = Destination::parse("example.com:443").unwrap();
        for proxy in [":443", ":"] {
            assert_eq!(
                connect_udp_template(proxy, &target).unwrap_err(),
                EngineError::InvalidConfig
            );
        }
    }

    #[test]
    fn invalid_proxy_ports_are_rejected() {
        let target = Destination::parse("example.com:443").unwrap();
        for proxy in [
            "proxy.example:",
            "proxy.example:0",
            "proxy.example:abc",
            "proxy.example:65536",
            "proxy.example:+443",
            "[2001:db8::1]:",
            "[2001:db8::1]:0",
            "[2001:db8::1]:abc",
            "[2001:db8::1]:65536",
            "[2001:db8::1]:+443",
        ] {
            assert_eq!(
                connect_udp_template(proxy, &target).unwrap_err(),
                EngineError::InvalidConfig,
                "proxy {proxy:?}"
            );
        }
    }

    #[test]
    fn optional_and_valid_proxy_ports_are_preserved() {
        let target = Destination::parse("example.com:443").unwrap();
        for proxy in [
            "proxy.example",
            "proxy.example:1",
            "proxy.example:65535",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
        ] {
            let request = connect_udp_template(proxy, &target).unwrap();
            assert_eq!(request.uri().authority().unwrap().as_str(), proxy);
        }
    }

    #[test]
    fn query_and_fragment_are_rejected_for_proxy_and_domain() {
        let target = Destination::parse("example.com:443").unwrap();
        for (proxy, name) in [
            ("proxy.example?udp", "example.com?udp"),
            ("proxy.example#udp", "example.com#udp"),
        ] {
            assert_eq!(
                connect_udp_template(proxy, &target).unwrap_err(),
                EngineError::InvalidConfig,
                "{proxy:?}"
            );
            let domain = Destination::Domain {
                name: name.to_string(),
                port: 443,
            };
            assert_eq!(
                connect_udp_template("proxy.example", &domain).unwrap_err(),
                EngineError::InvalidConfig,
                "{name:?}"
            );
        }

        let request = connect_udp_template("proxy.example", &target).unwrap();
        let path = request.uri().path();
        assert!(path.contains("/.well-known/masque/udp/"));
        assert!(path.contains(&format!("/{}/", target.port())));
        assert!(!path.contains('?'));
        assert!(!path.contains('#'));
    }
}
