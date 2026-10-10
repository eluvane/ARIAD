//! Exercises a standalone core oracle and CONNECT request assembly.
//! Peer verification and authorization are assumed model inputs. No network I/O occurs.

#![forbid(unsafe_code)]

use ariad_core::{
    BudgetLimits, Core, CoreConfig, CoreInput, CoreOutput, Credential, Destination, EngineError,
    SessionPhase, StreamInput, StreamPhase,
};
use ariad_engine::{EXPERIMENTAL_CREDENTIAL_HEADER, assemble_connect};

fn main() {
    let credential = Credential::from_bytes([0x11; Credential::BYTE_LEN]);
    let public = Destination::parse("1.1.1.1:443").expect("public target");
    assert!(matches!(
        assemble_connect(&public, &credential, false),
        Err(EngineError::PeerIdentityFailed)
    ));
    let request = assemble_connect(&public, &credential, true).expect("model request");
    assert_eq!(request.method().as_str(), "CONNECT");
    assert_eq!(
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str()),
        Some("1.1.1.1:443")
    );
    assert!(
        request
            .headers()
            .get(EXPERIMENTAL_CREDENTIAL_HEADER)
            .expect("credential header")
            .is_sensitive()
    );

    let mut limits = BudgetLimits::lab_small();
    limits.active_flows_per_session = 1;
    let mut core = Core::new(CoreConfig {
        limits,
        allow_private_egress: false,
    })
    .expect("model limits");
    assert!(matches!(
        core.handle(CoreInput::OpenStream {
            destination: public.clone(),
        })
        .as_slice(),
        [CoreOutput::Failure(failure)] if failure.category == EngineError::PeerIdentityFailed
    ));
    for input in [
        CoreInput::BeginResolve,
        CoreInput::EndpointResolved,
        CoreInput::TransportHandshakeStarted,
        CoreInput::PeerVerified,
    ] {
        assert!(core.handle(input).is_empty());
    }
    assert_eq!(core.session_phase(), SessionPhase::Ready);
    assert!(matches!(
        core.handle(CoreInput::OpenStream {
            destination: public.clone(),
        })
        .as_slice(),
        [CoreOutput::Failure(failure)] if failure.category == EngineError::AuthenticationDenied
    ));
    assert!(core.handle(CoreInput::Authorize).is_empty());
    assert!(matches!(
        core.handle(CoreInput::OpenStream {
            destination: Destination::parse("127.0.0.1:9").expect("loopback target"),
        })
        .as_slice(),
        [CoreOutput::Failure(failure)] if failure.category == EngineError::EgressDenied
    ));

    let outputs = core.handle(CoreInput::OpenStream {
        destination: public.clone(),
    });
    let [
        CoreOutput::DialTarget {
            id,
            generation,
            destination,
        },
    ] = outputs.as_slice()
    else {
        panic!("expected one target action");
    };
    assert_eq!(destination, &public);
    let (id, generation) = (*id, *generation);
    assert!(matches!(
        core.handle(CoreInput::OpenStream {
            destination: public,
        })
        .as_slice(),
        [CoreOutput::Failure(failure)] if failure.category == EngineError::ResourceLimitExceeded
    ));
    for input in [
        StreamInput::TargetConnected,
        StreamInput::WriteAccepted { n: 4 },
        StreamInput::HalfCloseLocal,
    ] {
        assert!(
            core.handle(CoreInput::Stream {
                id,
                generation,
                input,
            })
            .is_empty()
        );
    }
    assert_eq!(core.stream_phase(id), Some(StreamPhase::HalfClosedLocal));
    assert!(matches!(
        core.handle(CoreInput::Stream {
            id,
            generation,
            input: StreamInput::WriteAccepted { n: 1 },
        })
        .as_slice(),
        [CoreOutput::Failure(failure)] if failure.category == EngineError::ProtocolViolation
    ));
    assert!(
        core.handle(CoreInput::Stream {
            id,
            generation,
            input: StreamInput::HalfCloseRemote,
        })
        .is_empty()
    );
    assert_eq!(core.stream_phase(id), None);
    assert!(core.handle(CoreInput::Drain).is_empty());
    assert!(core.handle(CoreInput::Close).is_empty());
    assert_eq!(core.session_phase(), SessionPhase::Closed);
    println!("model_oracle=ok");
}
