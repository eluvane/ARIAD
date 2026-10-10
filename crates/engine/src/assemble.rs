#![forbid(unsafe_code)]

use ariad_core::{Credential, Destination, EngineError};
use http::Request;

use crate::connect::{attach_credential, connect_template};

/// Builds a CONNECT request with a sensitive credential header.
///
/// The caller must verify the peer and select a credential allowed for its trust
/// group before setting `peer_verified`. A false value fails before destination
/// validation. This function assembles the request without TLS or transport I/O.
pub fn assemble_connect(
    destination: &Destination,
    credential: &Credential,
    peer_verified: bool,
) -> Result<Request<()>, EngineError> {
    if !peer_verified {
        return Err(EngineError::PeerIdentityFailed);
    }
    let mut request = connect_template(destination)?;
    attach_credential(&mut request, credential)?;
    Ok(request)
}

#[cfg(feature = "tls-rustls")]
/// Builds a CONNECT request using proof of a verified TLS channel.
///
/// The caller must select a credential allowed for the channel's trust group.
/// This function assembles the request without sending it on the channel.
pub fn assemble_verified_connect(
    destination: &Destination,
    credential: &Credential,
    _channel: &crate::tls::VerifiedTlsChannel,
) -> Result<Request<()>, EngineError> {
    assemble_connect(destination, credential, true)
}

#[cfg(test)]
mod tests {
    use super::assemble_connect;
    use ariad_core::{Credential, Destination, EngineError};
    use http::Method;

    fn test_credential() -> Credential {
        Credential::from_bytes([0x11; Credential::BYTE_LEN])
    }

    #[test]
    fn unverified_peer_rejects_before_destination_validation() {
        for name in ["example.com", ""] {
            let destination = Destination::Domain {
                name: name.into(),
                port: 443,
            };
            let error = assemble_connect(&destination, &test_credential(), false).unwrap_err();
            assert_eq!(error, EngineError::PeerIdentityFailed, "{name:?}");
        }
    }

    #[test]
    fn zero_port_rejection_preserves_peer_identity_precedence() {
        let destination = Destination::Domain {
            name: "example.com".into(),
            port: 0,
        };
        for (peer_verified, expected) in [
            (false, EngineError::PeerIdentityFailed),
            (true, EngineError::InvalidConfig),
        ] {
            assert_eq!(
                assemble_connect(&destination, &test_credential(), peer_verified).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn verified_domain_connect_marks_credential_header_sensitive() {
        let destination = Destination::Domain {
            name: "example.com".into(),
            port: 443,
        };
        let request = assemble_connect(&destination, &test_credential(), true).unwrap();
        assert_eq!(*request.method(), Method::CONNECT);
        assert_eq!(request.uri().to_string(), "example.com:443");
        assert_eq!(
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
            Some("example.com:443")
        );
        assert_eq!(request.headers().len(), 3);
        let value = request
            .headers()
            .get(crate::connect::EXPERIMENTAL_CREDENTIAL_HEADER)
            .unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.to_str().unwrap(), "11".repeat(Credential::BYTE_LEN));
    }
}
