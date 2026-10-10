#![forbid(unsafe_code)]

use ariad_core::{Core, CoreInput, CoreOutput, EngineError, RetryScope};

pub fn authorize(core: &mut Core) {
    for input in [
        CoreInput::BeginResolve,
        CoreInput::EndpointResolved,
        CoreInput::TransportHandshakeStarted,
        CoreInput::PeerVerified,
        CoreInput::Authorize,
    ] {
        let outputs = core.handle(input.clone());
        assert!(outputs.is_empty(), "{input:?}: {outputs:?}");
    }
    assert!(core.peer_verified());
    assert!(core.authorized());
}

pub fn assert_no_dial(outputs: &[CoreOutput]) {
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, CoreOutput::DialTarget { .. })),
        "{outputs:?}"
    );
}

pub fn assert_category(outputs: &[CoreOutput], category: EngineError) {
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            CoreOutput::Failure(failure)
                if failure.category == category && failure.retry == RetryScope::Never
        )),
        "{outputs:?}"
    );
}
