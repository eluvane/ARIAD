#![forbid(unsafe_code)]

#[cfg(feature = "h2")]
mod allocation;
mod api;
mod assemble;
mod catalog;
mod connect;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
mod connector;
#[cfg(feature = "h2")]
mod datagram;
#[cfg(feature = "h2")]
mod deadline;
mod dir;
mod ech;
#[cfg(feature = "h2")]
mod h2_tunnel;
#[cfg(feature = "h3")]
mod h3_tunnel;
mod host;
#[cfg(feature = "h2")]
mod masque;
#[cfg(feature = "tls-boring")]
mod native_tls;
mod replay;
#[cfg(feature = "h2")]
mod resolver;
mod response;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
mod session_api;
#[cfg(feature = "tls-rustls")]
mod tls;
mod tls_policy;
mod trust;

#[cfg(feature = "h2")]
pub(crate) use allocation::retained_bytes_charge;
pub use api::{Engine, EngineConfig, ShutdownReport};
pub use ariad_core::{
    AuthzDecision, BudgetLimits, Credential, Destination, EndpointDescriptor, EngineError,
    FlowGeneration, FlowId, SessionPhase,
};
pub use assemble::assemble_connect;
#[cfg(feature = "tls-rustls")]
pub use assemble::assemble_verified_connect;
pub use catalog::{TrustedEndpoints, endpoint_from_header};
pub use connect::{
    EXPERIMENTAL_CREDENTIAL_HEADER, EXPERIMENTAL_H2_BINDING_VERSION_HEADER,
    EXPERIMENTAL_PROTOCOL_VERSION_HEADER, H2VersionMode, attach_credential, attach_h2_versions,
    connect_template, validate_h2_versions,
};
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
pub use connector::{
    CANDIDATE_RACE_DELAY, ConnectRequest, DialCandidate, EndpointConnector, EndpointPolicy,
    MAX_DIAL_CANDIDATES, ReadyH2Channel, SelectedChannel, SelectedTransport,
};
#[cfg(feature = "h2")]
pub use datagram::{
    DatagramAssociation, DatagramControl, DatagramOptions, DatagramPayload, DatagramRecvHalf,
    DatagramSendHalf, handle_h2_connect_udp, relay_h2_udp,
};
#[cfg(feature = "h2")]
pub use deadline::Deadline;
pub use dir::ReadOutcome;
pub use ech::{availability_keeps_tls, ech_end_to_end};
#[cfg(feature = "h2")]
pub use h2_tunnel::{
    ClientRoundtrip, H2Config, H2Connect, H2ReadHalf, H2Session, H2StreamControl, H2WriteHalf,
    Route, check_h2_credential, client_roundtrip, client_roundtrip_with_limit, handle_h2_connect,
    handle_h2_connect_authorized, open_h2, request_route, serve_h2, serve_h2_with_handler,
    serve_one,
};
#[cfg(feature = "h3")]
pub use h3_tunnel::{
    EXPERIMENTAL_H3_BINDING_VERSION_HEADER, H3Config, H3Connect, H3DatagramAssociation,
    H3DatagramControl, H3DatagramRecvHalf, H3DatagramSendHalf, H3Incoming, H3ReadHalf,
    H3ServerSession, H3Session, H3StreamControl, H3WriteHalf,
};
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
pub use host::HostServices;
pub use host::{Authorizer, EndpointProvider, StaticAuthorizer};
#[cfg(feature = "h2")]
pub use host::{DefaultSocketFactory, SocketFactory};
#[cfg(feature = "h2")]
pub use masque::{
    CAPSULE_PROTOCOL, CONNECT_UDP, MAX_DATAGRAM_PAYLOAD, capsule_protocol_enabled,
    connect_udp_template, is_connect_udp, negotiated_datagram_payload, target_of_connect_udp,
};
#[cfg(feature = "tls-boring")]
pub use native_tls::{NativeTlsConnector, NativeTlsServer, NativeVerifiedTlsChannel};
pub use replay::SentCount;
#[cfg(feature = "h2")]
pub use resolver::{BootstrapResolution, BootstrapResolver, SystemBootstrapResolver};
pub use response::{classify_connect_response, classify_connect_status};
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
pub use session_api::{
    Association, AssociationControl, AssociationRecvHalf, AssociationSendHalf, CloseMode,
    CloseOutcome, DatagramRequirements, EngineResources, NegotiatedCapabilities, Session, Stream,
    StreamControl, StreamOptions, StreamReadHalf, StreamWriteHalf,
};
#[cfg(feature = "tls-rustls")]
pub use tls::VerifiedTlsChannel;
pub use trust::{EchState, SpkiPin, TrustPolicy};
pub use trust::{TrustVerdict, credential_gate, may_present_credential};
