#![forbid(unsafe_code)]

use ariad_core::EngineError;
use http::{Response, StatusCode};

use crate::connect::validate_h2_versions;

/// Checks H2 version headers before applying `classify_connect_status`.
/// Version failures return `ProtocolViolation` regardless of the response status.
/// The response body and UDP capability headers are unchecked.
pub fn classify_connect_response<B>(response: &Response<B>) -> Result<(), EngineError> {
    validate_h2_versions(response.headers())?;
    classify_connect_status(response.status())
}

/// Accepts only HTTP 200 as CONNECT success.
/// Maps 501 to `UnsupportedCapability`, 401/403 to `AuthenticationDenied`, and
/// 502/504 to `TargetConnectFailed`. Other codes return `ProtocolViolation`.
/// Binding versions and capability headers must be checked separately.
pub fn classify_connect_status(status: http::StatusCode) -> Result<(), EngineError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::NOT_IMPLEMENTED => Err(EngineError::UnsupportedCapability),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(EngineError::AuthenticationDenied),
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
            Err(EngineError::TargetConnectFailed)
        }
        _ => Err(EngineError::ProtocolViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_connect_response, classify_connect_status};
    use ariad_core::EngineError;
    use http::{HeaderValue, Response, StatusCode};

    use crate::connect::{
        EXPERIMENTAL_H2_BINDING_VERSION_HEADER, EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
        attach_h2_versions,
    };

    #[test]
    fn explicit_and_legacy_success_responses_are_accepted() {
        let mut response = Response::new(());
        assert_eq!(classify_connect_response(&response), Ok(()));
        attach_h2_versions(response.headers_mut()).expect("versions");
        assert_eq!(classify_connect_response(&response), Ok(()));
    }

    #[test]
    fn incompatible_response_cannot_open_a_stream() {
        for name in [
            EXPERIMENTAL_PROTOCOL_VERSION_HEADER,
            EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
        ] {
            let mut response = Response::new(());
            attach_h2_versions(response.headers_mut()).expect("versions");
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static("1"));
            assert_eq!(
                classify_connect_response(&response),
                Err(EngineError::ProtocolViolation)
            );
            response.headers_mut().remove(name);
            assert_eq!(
                classify_connect_response(&response),
                Err(EngineError::ProtocolViolation)
            );
        }
    }

    #[test]
    fn connect_status_classification() {
        for (status, expected) in [
            (StatusCode::OK, Ok(())),
            (
                StatusCode::NOT_IMPLEMENTED,
                Err(EngineError::UnsupportedCapability),
            ),
            (
                StatusCode::UNAUTHORIZED,
                Err(EngineError::AuthenticationDenied),
            ),
            (
                StatusCode::FORBIDDEN,
                Err(EngineError::AuthenticationDenied),
            ),
            (
                StatusCode::BAD_GATEWAY,
                Err(EngineError::TargetConnectFailed),
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                Err(EngineError::TargetConnectFailed),
            ),
            (StatusCode::NOT_FOUND, Err(EngineError::ProtocolViolation)),
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                Err(EngineError::ProtocolViolation),
            ),
        ] {
            assert_eq!(classify_connect_status(status), expected, "{status}");
        }
    }
}
