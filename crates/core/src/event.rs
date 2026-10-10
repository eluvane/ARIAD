use crate::address::Destination;
use crate::error::PublicFailure;
use crate::stream::StreamInput;

/// Stream identity within one [`crate::Core`]. The wrapper does not check existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(pub u64);

/// Generation paired with a stream identity when reporting a completion.
///
/// Core emits generation one and does not reuse stream identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowGeneration(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreInput {
    BeginResolve,
    EndpointResolved,
    TransportHandshakeStarted,
    /// Report peer identity verification completed by the adapter.
    PeerVerified,
    PeerIdentityFailed,
    /// Report successful authorization. Core checks the event order only.
    Authorize,
    AuthorizationDenied,
    AuthorizationUnavailable,
    OpenStream {
        destination: Destination,
    },
    Stream {
        id: FlowId,
        generation: FlowGeneration,
        input: StreamInput,
    },
    TunnelFailed,
    Cancel,
    Drain,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreOutput {
    Failure(PublicFailure),

    /// Request a target dial with the allocated flow identity.
    ///
    /// The connection is still pending when this action is emitted.
    DialTarget {
        id: FlowId,
        generation: FlowGeneration,
        destination: Destination,
    },
    /// A failed tunnel must not trigger a direct connection.
    NoDirectConnect,
}
