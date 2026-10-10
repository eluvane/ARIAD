#![forbid(unsafe_code)]

use ariad_core::{
    BudgetLimits, Core, CoreConfig, CoreInput, CoreOutput, Credential, Destination, EngineError,
    FlowId, SessionPhase,
};

mod common;

use common::{assert_category, assert_no_dial, authorize};

fn new_core() -> Core {
    new_core_with_private(false)
}

fn new_core_with_private(allow_private_egress: bool) -> Core {
    Core::new(CoreConfig {
        limits: BudgetLimits::lab_small(),
        allow_private_egress,
    })
    .expect("lab-small limits are valid")
}

fn assert_quiet_step(core: &mut Core, input: CoreInput) {
    let output = core.handle(input);
    assert!(output.is_empty(), "{output:?}");
}

fn authorized_core() -> Core {
    authorized_core_with_private(false)
}

fn authorized_core_with_private(allow_private_egress: bool) -> Core {
    let mut core = new_core_with_private(allow_private_egress);
    authorize(&mut core);
    core
}

fn parse_destination(text: &str) -> Destination {
    Destination::parse(text).expect("destination")
}

fn assert_first_flow_absent(core: &Core) {
    assert_eq!(core.stream_phase(FlowId(1)), None);
}

#[test]
fn open_before_peer_verified() {
    let mut core = new_core();
    let outputs = core.handle(CoreInput::OpenStream {
        destination: parse_destination("1.1.1.1:443"),
    });
    assert_no_dial(&outputs);
    assert_category(&outputs, EngineError::PeerIdentityFailed);
    assert!(!core.peer_verified());
    assert_first_flow_absent(&core);
}

#[test]
fn open_before_authorize() {
    let mut core = new_core();
    assert_quiet_step(&mut core, CoreInput::BeginResolve);
    assert_quiet_step(&mut core, CoreInput::EndpointResolved);
    assert_quiet_step(&mut core, CoreInput::TransportHandshakeStarted);
    assert_quiet_step(&mut core, CoreInput::PeerVerified);
    let outputs = core.handle(CoreInput::OpenStream {
        destination: parse_destination("1.1.1.1:443"),
    });
    assert_no_dial(&outputs);
    assert_category(&outputs, EngineError::AuthenticationDenied);
    assert_first_flow_absent(&core);
}

#[test]
fn authorized_open_dials_public() {
    let mut core = authorized_core();
    let destination = parse_destination("1.1.1.1:443");
    let outputs = core.handle(CoreInput::OpenStream {
        destination: destination.clone(),
    });
    let dials: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            CoreOutput::DialTarget { destination, .. } => Some(destination),
            _ => None,
        })
        .collect();
    assert_eq!(outputs.len(), 1, "{outputs:?}");
    assert_eq!(dials.len(), 1, "{outputs:?}");
    assert_eq!(dials[0], &destination);
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, CoreOutput::NoDirectConnect | CoreOutput::Failure(_))),
        "{outputs:?}"
    );
}

#[test]
fn loopback_not_dialed() {
    let mut core = authorized_core();
    let outputs = core.handle(CoreInput::OpenStream {
        destination: parse_destination("127.0.0.1:80"),
    });
    assert_no_dial(&outputs);
    assert_category(&outputs, EngineError::EgressDenied);
    assert_first_flow_absent(&core);
}

#[test]
fn metadata_not_dialed_with_either_private_policy() {
    for allow_private in [false, true] {
        for text in ["169.254.169.254:80", "[fd00:ec2::254]:80"] {
            let mut core = authorized_core_with_private(allow_private);
            let outputs = core.handle(CoreInput::OpenStream {
                destination: parse_destination(text),
            });
            assert_no_dial(&outputs);
            assert_category(&outputs, EngineError::EgressDenied);
            assert_first_flow_absent(&core);

            let allowed = core.handle(CoreInput::OpenStream {
                destination: parse_destination("1.1.1.1:443"),
            });
            assert!(matches!(
                allowed.as_slice(),
                [CoreOutput::DialTarget { id: FlowId(1), .. }]
            ));
        }
    }
}

#[test]
fn tunnel_failure_blocks_later_dial_requests() {
    let mut core = authorized_core();
    let failed = core.handle(CoreInput::TunnelFailed);
    assert!(
        failed
            .iter()
            .any(|output| matches!(output, CoreOutput::NoDirectConnect)),
        "{failed:?}"
    );
    assert_category(&failed, EngineError::NoReachableTrustedPath);
    assert_no_dial(&failed);

    let opened = core.handle(CoreInput::OpenStream {
        destination: parse_destination("1.1.1.1:443"),
    });
    assert_no_dial(&opened);
    assert!(
        opened
            .iter()
            .any(|output| matches!(output, CoreOutput::NoDirectConnect)),
        "{opened:?}"
    );
    assert_category(&opened, EngineError::NoReachableTrustedPath);
    assert_first_flow_absent(&core);
}

#[test]
fn credential_debug_redacts() {
    let rendered = format!("{:?}", Credential::from_bytes([0x41; 32]));
    assert_eq!(rendered, "Credential([redacted])");
    assert!(!rendered.contains("41"));
}

#[test]
fn peer_identity_failure_blocks_open() {
    let mut core = authorized_core();
    let failed = core.handle(CoreInput::PeerIdentityFailed);
    assert_no_dial(&failed);
    assert_category(&failed, EngineError::PeerIdentityFailed);
    assert!(!core.peer_verified());
    assert!(!core.authorized());
    assert_eq!(core.session_phase(), SessionPhase::Failed);

    let opened = core.handle(CoreInput::OpenStream {
        destination: parse_destination("1.1.1.1:443"),
    });
    assert_no_dial(&opened);
    assert_category(&opened, EngineError::PeerIdentityFailed);
    assert_first_flow_absent(&core);
}

#[test]
fn authorization_failure_blocks_open() {
    for (input, category) in [
        (
            CoreInput::AuthorizationDenied,
            EngineError::AuthenticationDenied,
        ),
        (
            CoreInput::AuthorizationUnavailable,
            EngineError::AuthorizationUnavailable,
        ),
    ] {
        let mut core = authorized_core();
        let failed = core.handle(input);
        assert_no_dial(&failed);
        assert_category(&failed, category);
        assert!(core.peer_verified());
        assert!(!core.authorized());
        assert_eq!(core.session_phase(), SessionPhase::Ready);

        let opened = core.handle(CoreInput::OpenStream {
            destination: parse_destination("1.1.1.1:443"),
        });
        assert_no_dial(&opened);
        assert_category(&opened, EngineError::AuthenticationDenied);
        assert_first_flow_absent(&core);
    }
}

#[test]
fn non_public_literals_are_not_dialed() {
    for text in [
        "[::ffff:127.0.0.1]:80",
        "10.1.1.1:443",
        "169.254.169.254:80",
        "100.64.0.1:443",
        "[::1]:443",
        "[fd00::1]:443",
    ] {
        let mut core = authorized_core();
        let outputs = core.handle(CoreInput::OpenStream {
            destination: parse_destination(text),
        });
        assert_no_dial(&outputs);
        assert_category(&outputs, EngineError::EgressDenied);
        assert_first_flow_absent(&core);
    }
}
