#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::address::Destination;
use crate::budget::BudgetLimits;
use crate::egress::validate_ip_target;
use crate::error::{EngineError, PublicFailure, RetryScope};
use crate::event::{CoreInput, CoreOutput, FlowGeneration, FlowId};
use crate::session::{SessionInput, SessionMachine, SessionPhase};
use crate::stream::{StreamInput, StreamMachine, StreamPhase};

const FIRST_FLOW_ID: u64 = 1;

const INITIAL_FLOW_GENERATION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreConfig {
    /// Limits validated at construction. Stream admission uses
    /// `active_flows_per_session`.
    pub limits: BudgetLimits,

    /// Permit private and shared ranges under [`crate::decide_egress`].
    pub allow_private_egress: bool,
}

/// Sans-I/O policy and lifecycle coordinator for one session.
///
/// Adapters establish peer identity and authorization before reporting those
/// results. This type emits actions without verifying TLS, resolving names or
/// opening sockets.
pub struct Core {
    config: CoreConfig,
    session: SessionMachine,
    peer_verified: bool,
    authorized: bool,
    tunnel_failed: bool,
    next_flow_id: u64,
    streams: HashMap<FlowId, StreamMachine>,
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, EngineError> {
        config.limits.validate()?;
        Ok(Self {
            config,
            session: SessionMachine::new(),
            peer_verified: false,
            authorized: false,
            tunnel_failed: false,
            next_flow_id: FIRST_FLOW_ID,
            streams: HashMap::new(),
        })
    }

    /// Apply one input and return adapter actions or public failures in order.
    ///
    /// Stream admission requires a ready session, verified peer, authorization
    /// and an IP target permitted by the egress policy. Resolve domain targets
    /// before submitting an open. All reported failures use [`RetryScope::Never`].
    ///
    /// Terminal stream transitions remove the stream and release its admission
    /// slot. Session termination rejects further stream inputs but retains the
    /// stored stream phases.
    pub fn handle(&mut self, input: CoreInput) -> Vec<CoreOutput> {
        match input {
            CoreInput::BeginResolve => self.apply_session(SessionInput::BeginResolve),
            CoreInput::EndpointResolved => self.apply_session(SessionInput::EndpointResolved),
            CoreInput::TransportHandshakeStarted => {
                self.apply_session(SessionInput::TransportHandshakeStarted)
            }
            CoreInput::Drain => self.apply_session(SessionInput::Drain),
            CoreInput::Close => self.apply_session(SessionInput::Close),
            CoreInput::Cancel => self.apply_session(SessionInput::Cancel),
            CoreInput::PeerVerified => self.on_peer_verified(),
            CoreInput::PeerIdentityFailed => self.on_peer_identity_failed(),
            CoreInput::Authorize => self.on_authorize(),
            CoreInput::AuthorizationDenied => {
                self.on_authorization_failed(EngineError::AuthenticationDenied)
            }
            CoreInput::AuthorizationUnavailable => {
                self.on_authorization_failed(EngineError::AuthorizationUnavailable)
            }
            CoreInput::TunnelFailed => self.on_tunnel_failed(),
            CoreInput::OpenStream { destination } => self.open_stream(destination),
            CoreInput::Stream {
                id,
                generation,
                input,
            } => self.on_stream(id, generation, input),
        }
    }

    pub fn session_phase(&self) -> SessionPhase {
        self.session.phase()
    }

    /// Return the stored phase, or `None` for an unknown or removed stream.
    pub fn stream_phase(&self, id: FlowId) -> Option<StreamPhase> {
        self.streams.get(&id).map(StreamMachine::phase)
    }

    /// Recorded peer verification result; session termination alone does not clear it.
    pub fn peer_verified(&self) -> bool {
        self.peer_verified
    }

    /// Recorded authorization result; stream admission also requires a ready session.
    pub fn authorized(&self) -> bool {
        self.authorized
    }

    fn apply_session(&mut self, input: SessionInput) -> Vec<CoreOutput> {
        match self.session.apply(input) {
            Ok(()) => Vec::new(),
            Err(category) => vec![failure(category)],
        }
    }

    fn on_peer_verified(&mut self) -> Vec<CoreOutput> {
        match self.session.apply(SessionInput::PeerVerified) {
            Ok(()) => {
                self.peer_verified = true;
                Vec::new()
            }
            Err(category) => {
                vec![failure(category)]
            }
        }
    }

    fn on_peer_identity_failed(&mut self) -> Vec<CoreOutput> {
        self.peer_verified = false;
        self.authorized = false;
        self.fail_session_if_possible();
        vec![failure(EngineError::PeerIdentityFailed)]
    }

    fn on_authorize(&mut self) -> Vec<CoreOutput> {
        if !self.peer_verified {
            return vec![failure(EngineError::PeerIdentityFailed)];
        }
        if self.session.phase() != SessionPhase::Ready {
            return vec![failure(EngineError::ProtocolViolation)];
        }
        self.authorized = true;
        Vec::new()
    }

    fn on_authorization_failed(&mut self, category: EngineError) -> Vec<CoreOutput> {
        self.authorized = false;
        vec![failure(category)]
    }

    fn on_tunnel_failed(&mut self) -> Vec<CoreOutput> {
        self.tunnel_failed = true;
        self.fail_session_if_possible();
        no_direct_connect()
    }

    fn open_stream(&mut self, destination: Destination) -> Vec<CoreOutput> {
        if self.tunnel_failed {
            return no_direct_connect();
        }
        if !self.peer_verified {
            return vec![failure(EngineError::PeerIdentityFailed)];
        }
        if !self.authorized {
            return vec![failure(EngineError::AuthenticationDenied)];
        }

        if self.session.phase() != SessionPhase::Ready {
            return vec![failure(EngineError::ProtocolViolation)];
        }
        if self.streams.len() >= self.config.limits.active_flows_per_session {
            return vec![failure(EngineError::ResourceLimitExceeded)];
        }

        if let Err(category) = validate_ip_target(self.config.allow_private_egress, &destination) {
            return vec![failure(category)];
        }

        let Some(next_flow_id) = self.next_flow_id.checked_add(1) else {
            return vec![failure(EngineError::ResourceLimitExceeded)];
        };
        let id = FlowId(self.next_flow_id);
        self.next_flow_id = next_flow_id;
        let generation = FlowGeneration(INITIAL_FLOW_GENERATION);
        let mut stream = StreamMachine::new();
        if let Err(category) = stream.apply(StreamInput::PolicyAllowed) {
            return vec![failure(category)];
        }
        if let Err(category) = stream.apply(StreamInput::TargetDialStarted) {
            return vec![failure(category)];
        }
        self.streams.insert(id, stream);

        vec![CoreOutput::DialTarget {
            id,
            generation,
            destination,
        }]
    }

    fn on_stream(
        &mut self,
        id: FlowId,
        generation: FlowGeneration,
        input: StreamInput,
    ) -> Vec<CoreOutput> {
        if self.session.phase().is_terminal() {
            return vec![failure(EngineError::ProtocolViolation)];
        }
        let Some(stream) = self.streams.get_mut(&id) else {
            return vec![failure(EngineError::ProtocolViolation)];
        };
        if generation != FlowGeneration(INITIAL_FLOW_GENERATION) {
            return vec![failure(EngineError::ProtocolViolation)];
        }
        match stream.apply(input) {
            Ok(()) => {
                if stream.phase().is_terminal() {
                    self.streams.remove(&id);
                }
                Vec::new()
            }
            Err(category) => vec![failure(category)],
        }
    }

    fn fail_session_if_possible(&mut self) {
        if self.session.phase().is_terminal() {
            return;
        }
        // Fail is accepted from every nonterminal session phase.
        let _ = self.session.apply(SessionInput::Fail);
    }
}

fn failure(category: EngineError) -> CoreOutput {
    CoreOutput::Failure(PublicFailure::new(category, RetryScope::Never))
}

fn no_direct_connect() -> Vec<CoreOutput> {
    vec![
        CoreOutput::NoDirectConnect,
        failure(EngineError::NoReachableTrustedPath),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Destination;

    fn ready() -> Core {
        let mut core = Core::new(CoreConfig {
            limits: BudgetLimits::lab_small(),
            allow_private_egress: false,
        })
        .expect("lab-small");
        for input in [
            CoreInput::BeginResolve,
            CoreInput::EndpointResolved,
            CoreInput::TransportHandshakeStarted,
            CoreInput::PeerVerified,
            CoreInput::Authorize,
        ] {
            assert!(core.handle(input).is_empty());
        }
        core
    }

    fn assert_no_dial(outputs: &[CoreOutput]) {
        assert!(
            !outputs
                .iter()
                .any(|output| matches!(output, CoreOutput::DialTarget { .. })),
            "{outputs:?}"
        );
    }

    #[test]
    fn terminal_stream_frees_the_flow_cap() {
        let mut core = ready();
        let destination = Destination::parse("1.1.1.1:9").expect("public");
        for _ in 0..64 {
            let outputs = core.handle(CoreInput::OpenStream {
                destination: destination.clone(),
            });
            let CoreOutput::DialTarget { id, generation, .. } = outputs[0] else {
                panic!("{outputs:?}");
            };
            let done = core.handle(CoreInput::Stream {
                id,
                generation,
                input: StreamInput::Reset,
            });
            assert!(done.is_empty(), "{done:?}");
        }
        let again = core.handle(CoreInput::OpenStream { destination });
        assert!(matches!(again.as_slice(), [CoreOutput::DialTarget { .. }]));
    }

    #[test]
    fn domain_is_not_a_dial_target() {
        let mut core = ready();
        let outputs = core.handle(CoreInput::OpenStream {
            destination: Destination::Domain {
                name: "localhost".to_string(),
                port: 80,
            },
        });
        assert_no_dial(&outputs);
        assert!(matches!(
            outputs.as_slice(),
            [CoreOutput::Failure(failure)]
                if failure.category == EngineError::TargetResolutionFailed
        ));
    }

    #[test]
    fn open_after_drain_close_or_cancel_does_not_dial() {
        let destination = Destination::parse("1.1.1.1:443").expect("public destination");

        let mut drained = ready();
        assert!(drained.handle(CoreInput::Drain).is_empty());
        let during_drain = drained.handle(CoreInput::OpenStream {
            destination: destination.clone(),
        });
        assert_no_dial(&during_drain);
        assert!(matches!(
            during_drain.as_slice(),
            [CoreOutput::Failure(failure)] if failure.category == EngineError::ProtocolViolation
        ));

        assert!(drained.handle(CoreInput::Close).is_empty());
        let after_close = drained.handle(CoreInput::OpenStream {
            destination: destination.clone(),
        });
        assert_no_dial(&after_close);

        let mut cancelled = ready();
        assert!(cancelled.handle(CoreInput::Cancel).is_empty());
        let after_cancel = cancelled.handle(CoreInput::OpenStream { destination });
        assert_no_dial(&after_cancel);
    }
}
