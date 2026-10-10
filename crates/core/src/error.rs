use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EngineError {
    #[error("invalid config")]
    InvalidConfig,
    #[error("unsupported capability")]
    UnsupportedCapability,
    #[error("endpoint resolution failed")]
    EndpointResolutionFailed,
    #[error("peer identity failed")]
    PeerIdentityFailed,
    #[error("authentication denied")]
    AuthenticationDenied,
    #[error("authorization unavailable")]
    AuthorizationUnavailable,
    #[error("egress denied")]
    EgressDenied,
    #[error("target resolution failed")]
    TargetResolutionFailed,
    #[error("target connect failed")]
    TargetConnectFailed,
    #[error("transport unavailable")]
    TransportUnavailable,
    #[error("transfer stalled")]
    TransferStalled,
    #[error("resource limit exceeded")]
    ResourceLimitExceeded,
    #[error("message too large")]
    MessageTooLarge,
    #[error("cancelled")]
    Cancelled,
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("remote reset")]
    RemoteReset,
    #[error("protocol violation")]
    ProtocolViolation,
    #[error("truncated stream")]
    TruncatedStream,
    #[error("no reachable trusted path")]
    NoReachableTrustedPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RetryScope {
    #[error("never")]
    Never,
    #[error("same path")]
    SamePath,
    #[error("new candidate")]
    NewCandidate,
    #[error("new failure domain")]
    NewFailureDomain,
}

/// A failure category paired with the permitted scope of a retry.
///
/// This value reports policy; it does not schedule or perform a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicFailure {
    pub category: EngineError,
    pub retry: RetryScope,
}

impl PublicFailure {
    pub const fn new(category: EngineError, retry: RetryScope) -> Self {
        Self { category, retry }
    }
}
