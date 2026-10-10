#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ariad_embed::{
    BindingId, BudgetLimits, EndpointDescriptor, EngineError, EngineResources, NetworkEpoch,
    PinnedH2Builder, SocketFactory, TrustPolicy, pinned_h2_engine,
};
use tokio::net::TcpSocket;

struct CountingSocketFactory {
    calls: Arc<AtomicUsize>,
}

impl SocketFactory for CountingSocketFactory {
    fn create_tcp(&self, _address: SocketAddr) -> Result<TcpSocket, EngineError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(EngineError::TransportUnavailable)
    }

    fn prepare_tcp(
        &self,
        _socket: &TcpSocket,
        _endpoint: &EndpointDescriptor,
        _address: SocketAddr,
    ) -> Result<(), EngineError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(EngineError::TransportUnavailable)
    }
}

fn counting_socket_factory() -> Arc<CountingSocketFactory> {
    Arc::new(CountingSocketFactory {
        calls: Arc::new(AtomicUsize::new(0)),
    })
}

#[track_caller]
fn assert_unused_resources(resources: &EngineResources) {
    assert_eq!(resources.application_memory_used(), 0);
    assert_eq!(resources.active_sessions(), 0);
    assert_eq!(resources.pending_handshakes(), 0);
}

fn trust_root() -> Vec<u8> {
    rcgen::generate_simple_self_signed(vec!["endpoint.test".to_owned()])
        .expect("certificate")
        .cert
        .der()
        .to_vec()
}

#[test]
fn construction_needs_no_runtime_and_retains_shared_resources() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let mut limits = BudgetLimits::lab_small();
    limits.active_sessions = 2;
    limits.pending_handshakes = 1;
    limits.global_application_budget = 8 * 1024 * 1024;
    limits.active_flows_per_session = 2;
    let resources = Arc::new(EngineResources::new(limits).expect("resources"));
    let socket_factory = counting_socket_factory();
    let socket_calls = Arc::clone(&socket_factory.calls);
    let retained_socket_factory = Arc::downgrade(&socket_factory);
    let address = "127.0.0.1:443".parse().expect("address");
    let root = trust_root();
    let (first, first_policy) = PinnedH2Builder::new(address, "endpoint.test", root.clone())
        .with_limits(limits)
        .with_socket_factory(socket_factory.clone())
        .with_resources(Arc::clone(&resources))
        .build()
        .expect("first engine");
    let mut second_limits = limits;
    second_limits.active_flows_per_session = 1;
    let (second, second_policy) = PinnedH2Builder::new(address, "endpoint.test", root)
        .with_limits(second_limits)
        .with_socket_factory(socket_factory)
        .with_resources(Arc::clone(&resources))
        .build()
        .expect("second engine");

    assert_eq!(first.config().limits, limits);
    assert_eq!(second.config().limits, second_limits);
    assert!(Arc::ptr_eq(&first.resources(), &resources));
    assert!(Arc::ptr_eq(&second.resources(), &resources));
    assert_eq!(first.network_epoch(), NetworkEpoch::start());
    assert_eq!(first_policy, second_policy);
    assert_eq!(first_policy.candidates[0].address, address);
    assert_eq!(first_policy.candidates[0].binding, BindingId::H2);
    assert_eq!(
        first_policy.candidates[0].endpoint.identity_hostname,
        "endpoint.test"
    );
    assert_eq!(first_policy.credential_trust_group, 1);
    assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
    assert_unused_resources(&resources);
    assert!(retained_socket_factory.upgrade().is_some());
    drop(first);
    assert!(retained_socket_factory.upgrade().is_some());
    drop(second);
    assert!(retained_socket_factory.upgrade().is_none());
}

#[test]
fn legacy_helper_keeps_default_limits_and_independent_pools() {
    let address = "127.0.0.1:443".parse().expect("address");
    let root = trust_root();
    let (legacy, legacy_policy) =
        pinned_h2_engine(address, "endpoint.test".to_owned(), root.clone()).expect("legacy engine");
    let (configured, configured_policy) = PinnedH2Builder::new(address, "endpoint.test", root)
        .build()
        .expect("builder engine");

    assert_eq!(legacy.config().limits, BudgetLimits::lab_small());
    assert_eq!(legacy.config(), configured.config());
    assert_eq!(legacy_policy, configured_policy);
    assert!(!Arc::ptr_eq(&legacy.resources(), &configured.resources()));
}

#[test]
fn builder_rejects_invalid_limits_and_incompatible_resource_pools() {
    let address = "127.0.0.1:443".parse().expect("address");
    let root = trust_root();
    let limits = BudgetLimits::lab_small();
    let resources = Arc::new(EngineResources::new(limits).expect("resources"));
    let mut invalid_limits = limits;
    invalid_limits.active_sessions = 0;
    assert_eq!(
        PinnedH2Builder::new(address, "endpoint.test", root.clone())
            .with_limits(invalid_limits)
            .build()
            .map(|_| ()),
        Err(EngineError::InvalidConfig)
    );

    for incompatible in [
        BudgetLimits {
            global_application_budget: limits.global_application_budget + 1,
            ..limits
        },
        BudgetLimits {
            active_sessions: limits.active_sessions + 1,
            ..limits
        },
        BudgetLimits {
            pending_handshakes: limits.pending_handshakes + 1,
            ..limits
        },
    ] {
        assert_eq!(
            PinnedH2Builder::new(address, "endpoint.test", root.clone())
                .with_limits(incompatible)
                .with_resources(Arc::clone(&resources))
                .build()
                .map(|_| ()),
            Err(EngineError::InvalidConfig)
        );
    }
    assert_unused_resources(&resources);
}

#[test]
fn builder_bounds_identity_labels_without_socket_work() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let address = "127.0.0.1:443".parse().expect("address");
    let root = trust_root();
    let resources = Arc::new(EngineResources::new(BudgetLimits::lab_small()).expect("resources"));
    let socket_factory = counting_socket_factory();
    let socket_calls = Arc::clone(&socket_factory.calls);
    let too_long_label = "a".repeat(64);
    for hostname in [
        format!("{too_long_label}.test"),
        format!("first.{too_long_label}.test"),
        format!("first.{too_long_label}"),
    ] {
        assert_eq!(
            PinnedH2Builder::new(address, hostname.clone(), root.clone())
                .with_socket_factory(socket_factory.clone())
                .with_resources(Arc::clone(&resources))
                .build()
                .map(|_| ()),
            Err(EngineError::InvalidConfig),
            "hostname {hostname:?}"
        );
        assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
    }

    let valid_hostname = format!("{}.test", "A".repeat(63));
    let (_engine, policy) = PinnedH2Builder::new(address, valid_hostname.clone(), root)
        .with_socket_factory(socket_factory)
        .with_resources(Arc::clone(&resources))
        .build()
        .expect("63-byte identity label");
    assert_eq!(
        policy.candidates[0].endpoint.identity_hostname,
        valid_hostname
    );
    assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
    assert_unused_resources(&resources);
}

#[test]
fn trust_rejection_preserves_legacy_errors_without_socket_work() {
    let address = "127.0.0.1:443".parse().expect("address");
    let socket_factory = counting_socket_factory();
    let socket_calls = Arc::clone(&socket_factory.calls);
    for (root, expected) in [
        (Vec::new(), EngineError::InvalidConfig),
        (vec![0], EngineError::InvalidConfig),
        (
            vec![0; TrustPolicy::MAX_ROOT_CERTIFICATE_BYTES + 1],
            EngineError::InvalidConfig,
        ),
        (
            vec![0; PinnedH2Builder::MAX_TRUST_ROOT_INPUT_BYTES + 1],
            EngineError::MessageTooLarge,
        ),
    ] {
        assert_eq!(
            pinned_h2_engine(address, "endpoint.test".to_owned(), root.clone()).map(|_| ()),
            Err(expected)
        );
        assert_eq!(
            PinnedH2Builder::new(address, "endpoint.test", root)
                .with_socket_factory(socket_factory.clone())
                .build()
                .map(|_| ()),
            Err(expected)
        );
    }
    assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
}
