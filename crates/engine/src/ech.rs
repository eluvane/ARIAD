#![forbid(unsafe_code)]

use ariad_core::EngineError;

/// Reports ECH support as `UnsupportedCapability`.
pub fn ech_end_to_end() -> Result<(), EngineError> {
    Err(EngineError::UnsupportedCapability)
}

/// Checks supplied policy flags for verified TLS and absence of replay.
///
/// The caller supplies the flags; this check performs no TLS verification.
/// Unverified TLS or replay returns `ProtocolViolation`.
pub fn availability_keeps_tls(tls_verified: bool, replayed: bool) -> Result<(), EngineError> {
    if tls_verified && !replayed {
        Ok(())
    } else {
        Err(EngineError::ProtocolViolation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::SentCount;
    use crate::trust::{TrustVerdict, credential_gate};

    #[test]
    fn ech_check_does_not_weaken_verification_or_replay() {
        let cases = [
            (TrustVerdict::Verified, Ok(())),
            (
                TrustVerdict::NameMismatch,
                Err(EngineError::PeerIdentityFailed),
            ),
            (
                TrustVerdict::UntrustedChain,
                Err(EngineError::PeerIdentityFailed),
            ),
            (
                TrustVerdict::PinMismatch,
                Err(EngineError::PeerIdentityFailed),
            ),
            (TrustVerdict::Expired, Err(EngineError::PeerIdentityFailed)),
        ];
        let before = cases.map(|(verdict, _)| credential_gate(verdict));
        let ech = ech_end_to_end();
        assert_eq!(ech, Err(EngineError::UnsupportedCapability));
        for ((verdict, expected), before) in cases.into_iter().zip(before) {
            assert_eq!(before, expected, "{verdict:?} before ECH");
            assert_eq!(credential_gate(verdict), expected, "{verdict:?} after ECH");
        }
        assert_eq!(
            availability_keeps_tls(false, false),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(
            availability_keeps_tls(true, true),
            Err(EngineError::ProtocolViolation)
        );
        assert_eq!(availability_keeps_tls(true, false), Ok(()));
        let sent = SentCount::new();
        assert_eq!(
            sent.bytes_for_new_connection(),
            Err(EngineError::ProtocolViolation)
        );
    }
}
