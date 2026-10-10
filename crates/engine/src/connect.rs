#![forbid(unsafe_code)]

use std::net::IpAddr;

use ariad_core::{Credential, Destination, EngineError, H2_BINDING_VERSION, PROTOCOL_VERSION};
use http::{HeaderMap, HeaderValue, Method, Request, Uri};

pub const EXPERIMENTAL_CREDENTIAL_HEADER: &str = "x-ariad-experimental-credential";
pub const EXPERIMENTAL_PROTOCOL_VERSION_HEADER: &str = "x-ariad-protocol-version";
pub const EXPERIMENTAL_H2_BINDING_VERSION_HEADER: &str = "x-ariad-h2-binding-version";

const MAX_VERSION_DIGITS: usize = u16::MAX.ilog10() as usize + 1;
pub(crate) static PROTOCOL_VERSION_TEXT: VersionText = VersionText::new(PROTOCOL_VERSION.0);
static H2_BINDING_VERSION_TEXT: VersionText = VersionText::new(H2_BINDING_VERSION.0);

/// Static instances provide version headers without heap allocation.
pub(crate) struct VersionText {
    digits: [u8; MAX_VERSION_DIGITS],
    start: usize,
}

impl VersionText {
    pub(crate) const fn new(mut version: u16) -> Self {
        let mut digits = [b'0'; MAX_VERSION_DIGITS];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (version % 10) as u8;
            version /= 10;
            if version == 0 {
                break;
            }
        }
        Self { digits, start }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.digits[self.start..]
    }

    pub(crate) fn header_value(&'static self) -> HeaderValue {
        let text = std::str::from_utf8(self.as_bytes()).expect("version digits are ASCII");
        HeaderValue::from_static(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2VersionMode {
    /// Both headers are present and match the supported versions.
    Explicit,
    /// Both headers are absent while both supported versions are zero.
    LegacyExperimental,
}

/// Replace both H2 version headers with the supported version strings.
pub fn attach_h2_versions(headers: &mut HeaderMap) -> Result<(), EngineError> {
    let protocol = PROTOCOL_VERSION_TEXT.header_value();
    let binding = H2_BINDING_VERSION_TEXT.header_value();
    headers.insert(EXPERIMENTAL_PROTOCOL_VERSION_HEADER, protocol);
    headers.insert(EXPERIMENTAL_H2_BINDING_VERSION_HEADER, binding);
    Ok(())
}

/// Accept exact supported version strings, or absent headers while both versions are zero.
/// Partial, duplicate or different version headers return `ProtocolViolation`.
pub fn validate_h2_versions(headers: &HeaderMap) -> Result<H2VersionMode, EngineError> {
    let protocol = single_header_value(headers, EXPERIMENTAL_PROTOCOL_VERSION_HEADER)?;
    let binding = single_header_value(headers, EXPERIMENTAL_H2_BINDING_VERSION_HEADER)?;
    match (protocol, binding) {
        (None, None) if PROTOCOL_VERSION.0 == 0 && H2_BINDING_VERSION.0 == 0 => {
            Ok(H2VersionMode::LegacyExperimental)
        }
        (Some(protocol), Some(binding))
            if protocol.as_bytes() == PROTOCOL_VERSION_TEXT.as_bytes()
                && binding.as_bytes() == H2_BINDING_VERSION_TEXT.as_bytes() =>
        {
            Ok(H2VersionMode::Explicit)
        }
        _ => Err(EngineError::ProtocolViolation),
    }
}

pub(crate) fn single_header_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, EngineError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        Err(EngineError::ProtocolViolation)
    } else {
        Ok(value)
    }
}

/// Build an authority-form CONNECT request with the supported H2 version headers.
/// Invalid destinations, including port zero, return `InvalidConfig`.
pub fn connect_template(destination: &Destination) -> Result<Request<()>, EngineError> {
    if destination.port() == 0 {
        return Err(EngineError::InvalidConfig);
    }
    let uri = connect_uri(destination)?;
    let mut request = Request::new(());
    *request.method_mut() = Method::CONNECT;
    *request.uri_mut() = uri;
    attach_h2_versions(request.headers_mut())?;
    Ok(request)
}

/// Replace the experimental credential header with sensitive lowercase hexadecimal.
/// The caller must verify the peer before sending the request.
///
/// If the URI contains the full hexadecimal credential in any ASCII letter case,
/// it is replaced with `/`, and the function returns `ProtocolViolation`.
pub fn attach_credential(
    request: &mut Request<()>,
    credential: &Credential,
) -> Result<(), EngineError> {
    let credential_hex = CredentialHex::from_credential(credential);
    if uri_contains_credential(request.uri(), credential_hex.as_bytes()) {
        *request.uri_mut() = Uri::from_static("/");
        return Err(EngineError::ProtocolViolation);
    }

    let mut credential_header = HeaderValue::from_bytes(credential_hex.as_bytes())
        .map_err(|_| EngineError::InvalidConfig)?;
    credential_header.set_sensitive(true);
    request
        .headers_mut()
        .insert(EXPERIMENTAL_CREDENTIAL_HEADER, credential_header);
    Ok(())
}

fn connect_uri(destination: &Destination) -> Result<Uri, EngineError> {
    let authority = match destination {
        Destination::Domain { name, port } => domain_authority(name, *port)?,
        Destination::Ip { addr, port } => ip_authority(*addr, *port),
    };
    parse_authority_uri(authority)
}

fn domain_authority(name: &str, port: u16) -> Result<String, EngineError> {
    if name.is_empty() || name.contains(':') || contains_disallowed_authority_text(name) {
        return Err(EngineError::InvalidConfig);
    }
    let authority = format!("{name}:{port}");
    Destination::parse(&authority)?;
    Ok(authority)
}

fn ip_authority(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(addr) => format!("{addr}:{port}"),
        IpAddr::V6(addr) => format!("[{addr}]:{port}"),
    }
}

fn contains_disallowed_authority_text(text: &str) -> bool {
    text.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(byte, b'@' | b'/' | b'?' | b'#' | b'\\')
    })
}

fn parse_authority_uri(authority: String) -> Result<Uri, EngineError> {
    let uri = Uri::from_maybe_shared(authority.clone()).map_err(|_| EngineError::InvalidConfig)?;
    if authority_form_matches(&uri, &authority) {
        Ok(uri)
    } else {
        Err(EngineError::InvalidConfig)
    }
}

fn authority_form_matches(uri: &Uri, authority: &str) -> bool {
    if uri.scheme().is_some() || *uri != *authority {
        return false;
    }
    let Some(parsed_authority) = uri.authority() else {
        return false;
    };
    if parsed_authority.as_str() != authority
        || parsed_authority.port_u16().is_none()
        || parsed_authority.as_str().contains('@')
    {
        return false;
    }
    let host = parsed_authority.host();
    !host.is_empty() && (!host.contains(':') || host.starts_with('['))
}

fn uri_contains_credential(uri: &Uri, credential_hex: &[u8; Credential::HEX_LEN]) -> bool {
    let rendered_uri = uri.to_string();
    let uri_bytes = rendered_uri.as_bytes();
    uri_bytes.windows(credential_hex.len()).any(|window| {
        window
            .iter()
            .zip(credential_hex.iter())
            .all(|(byte, expected)| byte.to_ascii_lowercase() == *expected)
    })
}

struct CredentialHex([u8; Credential::HEX_LEN]);

impl CredentialHex {
    fn from_credential(credential: &Credential) -> Self {
        let mut digits = Self([0; Credential::HEX_LEN]);
        credential.write_hex(&mut digits.0);
        digits
    }

    fn as_bytes(&self) -> &[u8; Credential::HEX_LEN] {
        &self.0
    }
}

impl Drop for CredentialHex {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EXPERIMENTAL_CREDENTIAL_HEADER, EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
        EXPERIMENTAL_PROTOCOL_VERSION_HEADER, H2VersionMode, VersionText, attach_credential,
        attach_h2_versions, connect_template, validate_h2_versions,
    };
    use ariad_core::{Credential, Destination, EngineError};
    use http::{HeaderMap, HeaderValue, Method, Request};

    fn example() -> Destination {
        Destination::parse("example.com:443").unwrap()
    }

    #[test]
    fn version_text_preserves_decimal_width_boundaries() {
        static CASES: [(VersionText, &str); 10] = [
            (VersionText::new(0), "0"),
            (VersionText::new(1), "1"),
            (VersionText::new(9), "9"),
            (VersionText::new(10), "10"),
            (VersionText::new(99), "99"),
            (VersionText::new(100), "100"),
            (VersionText::new(999), "999"),
            (VersionText::new(1000), "1000"),
            (VersionText::new(10000), "10000"),
            (VersionText::new(u16::MAX), "65535"),
        ];
        for (version, expected) in &CASES {
            assert_eq!(version.as_bytes(), expected.as_bytes());
            assert_eq!(version.header_value().as_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn template_uses_connect_without_scheme_or_userinfo() {
        let request = connect_template(&example()).unwrap();
        assert_eq!(*request.method(), Method::CONNECT);
        let uri = request.uri().to_string();
        assert_eq!(uri, "example.com:443");
        assert!(!uri.contains("http://"));
        assert!(!uri.contains('@'));
        assert!(request.uri().scheme().is_none());
        assert_eq!(
            validate_h2_versions(request.headers()),
            Ok(H2VersionMode::Explicit)
        );
        assert!(
            request
                .headers()
                .get(EXPERIMENTAL_CREDENTIAL_HEADER)
                .is_none()
        );
    }

    #[test]
    fn legacy_experimental_headers_remain_accepted() {
        assert_eq!(
            validate_h2_versions(&HeaderMap::new()),
            Ok(H2VersionMode::LegacyExperimental)
        );
    }

    #[test]
    fn partial_duplicate_or_unknown_versions_are_rejected() {
        for name in [
            EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
            EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
        ] {
            let mut partial = HeaderMap::new();
            partial.insert(name, HeaderValue::from_static("0"));
            assert_eq!(
                validate_h2_versions(&partial),
                Err(EngineError::ProtocolViolation)
            );

            let mut duplicate = HeaderMap::new();
            attach_h2_versions(&mut duplicate).expect("versions");
            duplicate.append(name, HeaderValue::from_static("0"));
            assert_eq!(
                validate_h2_versions(&duplicate),
                Err(EngineError::ProtocolViolation)
            );

            for value in ["1", "65535", "65536", "00", "+0", " 0", "0 ", "0, 0", ""] {
                let mut unknown = HeaderMap::new();
                attach_h2_versions(&mut unknown).expect("versions");
                unknown.insert(name, HeaderValue::from_str(value).expect("header value"));
                assert_eq!(
                    validate_h2_versions(&unknown),
                    Err(EngineError::ProtocolViolation),
                    "{name}: {value:?}"
                );
            }
        }
    }

    #[test]
    fn attach_credential_header_is_64_hex_digits_and_stays_out_of_the_uri() {
        let mut request = connect_template(&example()).unwrap();
        let credential = Credential::from_bytes([0x0b; Credential::BYTE_LEN]);
        attach_credential(&mut request, &credential).unwrap();

        assert_eq!(
            EXPERIMENTAL_CREDENTIAL_HEADER,
            "x-ariad-experimental-credential"
        );
        let value = request
            .headers()
            .get(EXPERIMENTAL_CREDENTIAL_HEADER)
            .unwrap();
        assert!(value.is_sensitive());
        let header = value.to_str().unwrap();
        assert_eq!(header.len(), Credential::HEX_LEN);
        assert_eq!(header, "0b".repeat(Credential::BYTE_LEN));
        assert!(
            header
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(!request.uri().to_string().contains(header));
        assert_eq!(request.uri().to_string(), "example.com:443");
    }

    #[test]
    fn ipv6_authority_is_bracketed() {
        let destination = Destination::parse("[2001:db8::1]:443").unwrap();
        let request = connect_template(&destination).unwrap();
        let uri = request.uri().to_string();
        assert_eq!(uri, "[2001:db8::1]:443");
        assert!(uri.starts_with('['));
        assert!(!uri.contains("http://"));
        assert!(!uri.contains('@'));
    }

    #[test]
    fn manually_constructed_domains_follow_address_policy() {
        for name in [
            String::new(),
            "-host".to_owned(),
            "host-".to_owned(),
            "bad_host".to_owned(),
            "a..b".to_owned(),
            "example.com.".to_owned(),
            "a".repeat(Destination::MAX_DOMAIN_BYTES + 1),
            "user@example.com".to_owned(),
            "example.com/path".to_owned(),
            "https://example.com".to_owned(),
            "example.com bad".to_owned(),
        ] {
            let destination = Destination::Domain { name, port: 443 };
            assert_eq!(
                connect_template(&destination).unwrap_err(),
                EngineError::InvalidConfig,
                "{destination:?}"
            );
        }
    }

    #[test]
    fn zero_port_is_invalid_config_for_all_destination_types() {
        let destinations = [
            Destination::Ip {
                addr: "1.1.1.1".parse().unwrap(),
                port: 0,
            },
            Destination::Ip {
                addr: "2001:db8::1".parse().unwrap(),
                port: 0,
            },
            Destination::Domain {
                name: "example.com".into(),
                port: 0,
            },
        ];
        for destination in destinations {
            assert_eq!(
                connect_template(&destination).unwrap_err(),
                EngineError::InvalidConfig
            );
        }
    }

    #[test]
    fn uri_containing_credential_hex_is_cleared() {
        let credential = Credential::from_bytes([0x0b; Credential::BYTE_LEN]);
        let mut hex = [0u8; Credential::HEX_LEN];
        credential.write_hex(&mut hex);
        let hex = std::str::from_utf8(&hex).unwrap();
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("/{hex}"))
            .body(())
            .unwrap();

        let error = attach_credential(&mut request, &credential).unwrap_err();
        assert_eq!(error, EngineError::ProtocolViolation);
        assert!(!request.uri().to_string().contains(hex));
        assert!(
            request
                .headers()
                .get(EXPERIMENTAL_CREDENTIAL_HEADER)
                .is_none()
        );
    }

    #[test]
    fn mixed_case_hex_in_connect_uri_is_protocol_violation() {
        let credential = Credential::from_bytes([0xab; Credential::BYTE_LEN]);
        let mut hex = [0u8; Credential::HEX_LEN];
        credential.write_hex(&mut hex);
        let lower = std::str::from_utf8(&hex).unwrap();
        let mixed: String = lower
            .chars()
            .enumerate()
            .map(|(index, ch)| {
                if index % 2 == 0 {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                }
            })
            .collect();
        assert_ne!(mixed, lower);
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("{mixed}:443"))
            .body(())
            .unwrap();
        assert!(request.uri().to_string().contains(&mixed));
        assert!(!request.uri().to_string().contains(lower));

        let error = attach_credential(&mut request, &credential).unwrap_err();
        assert_eq!(error, EngineError::ProtocolViolation);
        assert_eq!(request.uri().to_string(), "/");
        assert!(
            request
                .headers()
                .get(EXPERIMENTAL_CREDENTIAL_HEADER)
                .is_none()
        );
    }
}
