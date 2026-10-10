use std::time::Duration;

use ariad_core::{AuthzDecision, Credential, EndpointDescriptor, EngineError};

/// Provides host-selected endpoint descriptors for connection policy.
pub trait EndpointProvider {
    /// Borrows the available descriptors; peer headers are not a trust source.
    fn endpoints(&self) -> &[EndpointDescriptor];
}

/// Decides server admission for a presented credential.
pub trait Authorizer {
    /// Returns the principal, quota class, and lifetime of an accepted credential.
    ///
    /// Runs synchronously in the caller's task and must finish promptly. Server
    /// handlers validate the returned decision before opening a target.
    fn authorize(&self, credential: &Credential) -> Result<AuthzDecision, EngineError>;
}

/// Accepts one configured credential with a fixed principal and quota class zero.
pub struct StaticAuthorizer {
    expected: Credential,
    principal: u64,
}

impl StaticAuthorizer {
    /// Retains `expected` and grants matching credentials a 60-second decision.
    /// A zero principal is retained here but rejected by server admission handlers.
    pub fn new(expected: Credential, principal: u64) -> Self {
        Self {
            expected,
            principal,
        }
    }
}

impl Authorizer for StaticAuthorizer {
    fn authorize(&self, credential: &Credential) -> Result<AuthzDecision, EngineError> {
        if self.expected.verify(credential) {
            let principal = self.principal;
            Ok(AuthzDecision {
                principal,
                quota_class: 0,
                valid_for: Duration::from_secs(60),
            })
        } else {
            Err(EngineError::AuthenticationDenied)
        }
    }
}

#[cfg(feature = "h2")]
mod sockets {
    use std::net::SocketAddr;

    use ariad_core::{EndpointDescriptor, EngineError};
    use tokio::net::TcpSocket;

    /// Supplies owned sockets and synchronous preparation hooks before dialing.
    ///
    /// Candidate attempts can call these methods concurrently on runtime worker
    /// threads. No calling-thread affinity is guaranteed. Creation and preparation
    /// must finish promptly; async deadlines cannot interrupt them.
    ///
    /// Socket handles can be borrowed with `std::os::fd::AsFd` or `AsRawFd` on Unix,
    /// and `std::os::windows::io::AsSocket` or `AsRawSocket` on Windows. The engine
    /// owns the borrowed socket and handle. Do not close them or retain a raw
    /// handle after the hook returns. The host owns and closes any duplicates it creates.
    /// Complete routing-loop protection before returning `Ok(())`; a failed
    /// protection must return an error, such as `EngineError::EgressDenied`.
    pub trait SocketFactory: Send + Sync {
        /// Return a fresh, unconnected socket for `address`'s IP family.
        /// The engine takes ownership. Local binding may be done in `prepare_tcp`.
        fn create_tcp(&self, address: SocketAddr) -> Result<TcpSocket, EngineError>;

        /// Runs synchronously in the caller's task before connect. The hook
        /// must finish promptly. An error closes the socket without connecting.
        /// `address` selects the route; `endpoint.identity_hostname` selects TLS identity.
        fn prepare_tcp(
            &self,
            _socket: &TcpSocket,
            _endpoint: &EndpointDescriptor,
            _address: SocketAddr,
        ) -> Result<(), EngineError> {
            Ok(())
        }

        #[cfg(feature = "h3")]
        /// Return a fresh, unbound datagram socket for `address`'s IP family.
        /// The engine takes ownership.
        fn create_udp(&self, address: SocketAddr) -> Result<socket2::Socket, EngineError> {
            let domain = if address.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                .map_err(|_| EngineError::TransportUnavailable)
        }

        #[cfg(feature = "h3")]
        /// Runs before bind in the caller's task. The host may protect and then
        /// bind the borrowed socket. The engine binds a socket left unbound.
        /// An error closes the socket before QUIC sends. The hook must finish promptly.
        /// `address` selects the route; `endpoint.identity_hostname` selects TLS identity.
        fn prepare_udp(
            &self,
            _socket: &socket2::Socket,
            _endpoint: &EndpointDescriptor,
            _address: SocketAddr,
        ) -> Result<(), EngineError> {
            Ok(())
        }
    }

    /// Creates sockets for the destination's IP family with no preparation hook.
    #[derive(Debug, Default)]
    pub struct DefaultSocketFactory;

    impl SocketFactory for DefaultSocketFactory {
        fn create_tcp(&self, address: SocketAddr) -> Result<TcpSocket, EngineError> {
            let result = if address.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            };
            result.map_err(|_| EngineError::TransportUnavailable)
        }
    }
}

#[cfg(feature = "h2")]
pub use sockets::{DefaultSocketFactory, SocketFactory};

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
mod services {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ariad_core::{BindingId, DeadlineKind, EndpointDescriptor, EngineError, lab_cap};
    use tokio::net::TcpStream;
    use tokio::time::timeout_at;

    use super::SocketFactory;
    use crate::Deadline;
    #[cfg(feature = "h3")]
    use crate::h3_tunnel::{H3Config, H3Session, require_safe_logging};
    #[cfg(feature = "tls-boring")]
    use crate::native_tls::{NativeTlsConnector, NativeVerifiedTlsChannel};
    use crate::resolver::{BootstrapResolver, constrain_addresses, validate_address};
    #[cfg(feature = "tls-rustls")]
    use crate::tls::{VerifiedTlsChannel, VerifiedTlsConnector};
    use crate::trust::TrustPolicy;

    /// Host-owned bootstrap DNS, socket preparation, and endpoint trust policies.
    ///
    /// Network methods require a Tokio runtime with I/O and time enabled. The host
    /// owns that runtime and keeps it running through engine shutdown. A custom
    /// resolver controls bootstrap DNS routing; a socket factory controls transport
    /// routing and protection. These are separate host responsibilities.
    /// Sharing services does not share engine transport resource quotas.
    pub struct HostServices {
        resolver: Arc<dyn BootstrapResolver>,
        sockets: Arc<dyn SocketFactory>,
        trust_groups: BTreeSet<u64>,
        #[cfg(feature = "tls-rustls")]
        rustls_connectors: BTreeMap<u64, VerifiedTlsConnector>,
        #[cfg(feature = "tls-boring")]
        boring_connectors: BTreeMap<u64, NativeTlsConnector>,
        max_resolved_addresses: usize,
    }

    impl HostServices {
        /// Prepares trust policies without starting network work.
        ///
        /// Requires a nonempty policy list, distinct trust groups, and a nonzero
        /// resolver answer limit. TLS policy construction failures are returned.
        /// Policies without DER roots do not provide a native TLS connector.
        pub fn new(
            resolver: Arc<dyn BootstrapResolver>,
            sockets: Arc<dyn SocketFactory>,
            policies: Vec<TrustPolicy>,
            max_resolved_addresses: usize,
        ) -> Result<Self, EngineError> {
            if policies.is_empty() || max_resolved_addresses == 0 {
                return Err(EngineError::InvalidConfig);
            }
            let mut trust_groups = BTreeSet::new();
            #[cfg(feature = "tls-rustls")]
            let mut rustls_connectors = BTreeMap::new();
            #[cfg(feature = "tls-boring")]
            let mut boring_connectors = BTreeMap::new();
            for policy in policies {
                let group = policy.trust_group();
                if !trust_groups.insert(group) {
                    return Err(EngineError::InvalidConfig);
                }
                #[cfg(feature = "tls-rustls")]
                rustls_connectors.insert(group, VerifiedTlsConnector::new(policy.clone())?);
                #[cfg(feature = "tls-boring")]
                if policy.certificate_roots_der().is_some() {
                    boring_connectors.insert(group, NativeTlsConnector::new(policy.clone())?);
                }
            }
            Ok(Self {
                resolver,
                sockets,
                trust_groups,
                #[cfg(feature = "tls-rustls")]
                rustls_connectors,
                #[cfg(feature = "tls-boring")]
                boring_connectors,
                max_resolved_addresses,
            })
        }

        /// Checks descriptor validity and configured binding support without I/O.
        ///
        /// Rejects required ECH, unknown trust groups, and endpoints with no usable
        /// binding. Success establishes configuration support, not peer readiness.
        pub fn supports_endpoint(&self, endpoint: &EndpointDescriptor) -> Result<(), EngineError> {
            endpoint.validate()?;
            if endpoint.ech_required {
                return Err(EngineError::UnsupportedCapability);
            }
            if !self.trust_groups.contains(&endpoint.trust_group) {
                return Err(EngineError::PeerIdentityFailed);
            }
            let h2_available = endpoint.permits_binding(BindingId::H2)
                && self.h2_policy_available(endpoint.trust_group);
            #[cfg(not(feature = "h3"))]
            let h3_available = false;
            #[cfg(feature = "h3")]
            let h3_available = endpoint.permits_binding(BindingId::H3)
                && self.boring_connectors.contains_key(&endpoint.trust_group)
                && require_safe_logging().is_ok();
            if !h2_available && !h3_available {
                return Err(EngineError::UnsupportedCapability);
            }
            Ok(())
        }

        fn h2_policy_available(&self, group: u64) -> bool {
            #[cfg(feature = "tls-rustls")]
            if self.rustls_connectors.contains_key(&group) {
                return true;
            }
            #[cfg(feature = "tls-boring")]
            if self.boring_connectors.contains_key(&group) {
                return true;
            }
            false
        }

        /// Checks that the descriptor advertises a binding this host can use.
        /// H3 requires a compiled log ceiling no more verbose than `Info`.
        pub fn supports_binding(
            &self,
            endpoint: &EndpointDescriptor,
            binding: BindingId,
        ) -> Result<(), EngineError> {
            self.supports_endpoint(endpoint)?;
            if !endpoint.permits_binding(binding) {
                return Err(EngineError::UnsupportedCapability);
            }
            match binding {
                BindingId::H2 if self.h2_policy_available(endpoint.trust_group) => Ok(()),
                #[cfg(feature = "h3")]
                BindingId::H3 if self.boring_connectors.contains_key(&endpoint.trust_group) => {
                    require_safe_logging()
                }
                _ => Err(EngineError::UnsupportedCapability),
            }
        }

        #[cfg(feature = "tls-boring")]
        /// Checks endpoint support and availability of its native TLS policy.
        /// Binding support must still be checked for the requested transport.
        pub fn supports_boring_endpoint(
            &self,
            endpoint: &EndpointDescriptor,
        ) -> Result<(), EngineError> {
            self.supports_endpoint(endpoint)?;
            if !self.boring_connectors.contains_key(&endpoint.trust_group) {
                return Err(EngineError::UnsupportedCapability);
            }
            Ok(())
        }

        /// Resolves the endpoint identity hostname to addresses at `port`.
        ///
        /// Rejects port zero and empty, oversized, invalid, or wrong-port answers.
        /// Duplicate addresses are removed. The deadline is capped by the lab
        /// `BootstrapDns` limit. System resolver workers can outlive timeout.
        ///
        /// Attach the answer with `EndpointDescriptor::with_addresses` and build an
        /// `EndpointPolicy::from_address_hints` for the current network epoch. Pass
        /// the same absolute deadline to the later connect call to bound both steps.
        pub async fn resolve_endpoint(
            &self,
            endpoint: &EndpointDescriptor,
            port: u16,
            deadline: Deadline,
        ) -> Result<Vec<SocketAddr>, EngineError> {
            self.supports_endpoint(endpoint)?;
            if port == 0 {
                return Err(EngineError::InvalidConfig);
            }
            let deadline = deadline.cap(lab_cap(DeadlineKind::BootstrapDns))?;
            let addresses = timeout_at(
                deadline.expires_at(),
                self.resolver.resolve(
                    &endpoint.identity_hostname,
                    port,
                    self.max_resolved_addresses,
                ),
            )
            .await
            .map_err(|_| EngineError::DeadlineExceeded)??;
            deadline.remaining()?;
            constrain_addresses(addresses, port, self.max_resolved_addresses)
        }

        #[cfg(feature = "tls-rustls")]
        /// Connects to `address` and verifies TLS for the descriptor's identity.
        ///
        /// The address chooses the route; the identity hostname governs peer checks.
        /// Socket preparation runs before connect. The deadline is capped by the
        /// lab `TransportHandshake` limit. Binding readiness is a later H2 step.
        pub async fn connect_verified(
            &self,
            endpoint: &EndpointDescriptor,
            address: SocketAddr,
            deadline: Deadline,
        ) -> Result<VerifiedTlsChannel, EngineError> {
            self.supports_binding(endpoint, BindingId::H2)?;
            validate_address(address)?;
            let deadline = deadline.cap(lab_cap(DeadlineKind::TransportHandshake))?;
            let connector = self
                .rustls_connectors
                .get(&endpoint.trust_group)
                .ok_or(EngineError::PeerIdentityFailed)?;
            let stream = self.connect_tcp(endpoint, address, deadline).await?;
            connector.connect(stream, endpoint, address, deadline).await
        }

        #[cfg(feature = "tls-boring")]
        /// Connects with native TLS and verifies the descriptor's identity.
        ///
        /// Uses the supplied route address and the descriptor's identity hostname.
        /// Socket preparation runs before connect. The deadline is capped by the
        /// lab `TransportHandshake` limit. Binding readiness is a later H2 step.
        pub async fn connect_boring_verified(
            &self,
            endpoint: &EndpointDescriptor,
            address: SocketAddr,
            deadline: Deadline,
        ) -> Result<NativeVerifiedTlsChannel, EngineError> {
            self.supports_boring_endpoint(endpoint)?;
            self.supports_binding(endpoint, BindingId::H2)?;
            validate_address(address)?;
            let deadline = deadline.cap(lab_cap(DeadlineKind::TransportHandshake))?;
            let connector = self
                .boring_connectors
                .get(&endpoint.trust_group)
                .ok_or(EngineError::UnsupportedCapability)?;
            let stream = self.connect_tcp(endpoint, address, deadline).await?;
            connector.connect(endpoint, stream, address, deadline).await
        }

        async fn connect_tcp(
            &self,
            endpoint: &EndpointDescriptor,
            address: SocketAddr,
            deadline: Deadline,
        ) -> Result<TcpStream, EngineError> {
            let socket = self.sockets.create_tcp(address)?;
            deadline.remaining()?;
            self.sockets.prepare_tcp(&socket, endpoint, address)?;
            deadline.remaining()?;
            timeout_at(deadline.expires_at(), socket.connect(address))
                .await
                .map_err(|_| EngineError::DeadlineExceeded)?
                .map_err(|_| EngineError::TransportUnavailable)
        }

        #[cfg(feature = "h3")]
        /// Connects a verified QUIC transport and waits for H3 readiness.
        ///
        /// Socket preparation runs before bind and can bind the borrowed socket.
        /// The deadline is capped by the lab `TransportHandshake` limit. A compiled
        /// log ceiling no more verbose than `Info` is required; runtime filters do
        /// not satisfy that requirement.
        pub async fn connect_h3_verified(
            &self,
            endpoint: &EndpointDescriptor,
            address: SocketAddr,
            config: H3Config,
            deadline: Deadline,
        ) -> Result<H3Session, EngineError> {
            self.supports_boring_endpoint(endpoint)?;
            self.supports_binding(endpoint, BindingId::H3)?;
            config.validate()?;
            validate_address(address)?;
            let deadline = deadline.cap(lab_cap(DeadlineKind::TransportHandshake))?;
            let connector = self
                .boring_connectors
                .get(&endpoint.trust_group)
                .ok_or(EngineError::UnsupportedCapability)?;
            let socket = self.sockets.create_udp(address)?;
            deadline.remaining()?;
            if udp_socket_is_bound(&socket) {
                return Err(EngineError::InvalidConfig);
            }
            self.sockets.prepare_udp(&socket, endpoint, address)?;
            deadline.remaining()?;
            socket
                .set_nonblocking(true)
                .map_err(|_| EngineError::TransportUnavailable)?;
            if !udp_socket_is_bound(&socket) {
                let bind_address = if address.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                } else {
                    SocketAddr::from(([0u16; 8], 0))
                };
                socket
                    .bind(&socket2::SockAddr::from(bind_address))
                    .map_err(|_| EngineError::TransportUnavailable)?;
            }
            let socket: std::net::UdpSocket = socket.into();
            let socket = tokio::net::UdpSocket::from_std(socket)
                .map_err(|_| EngineError::TransportUnavailable)?;
            deadline.remaining()?;
            H3Session::connect(socket, endpoint, address, connector, config, deadline).await
        }
    }

    #[cfg(feature = "h3")]
    fn udp_socket_is_bound(socket: &socket2::Socket) -> bool {
        socket
            .local_addr()
            .ok()
            .and_then(|address| address.as_socket())
            .is_some_and(|address| address.port() != 0)
    }

    #[cfg(all(test, feature = "tls-rustls"))]
    mod tests {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use tokio::net::{TcpListener, TcpSocket};

        use super::*;
        use crate::host::DefaultSocketFactory;
        use crate::resolver::BootstrapResolution;

        const IDENTITY_HOSTNAME: &str = "endpoint.test";
        const TRUST_GROUP: u64 = 9;

        struct FixedResolver {
            calls: Arc<AtomicUsize>,
            addresses: Vec<SocketAddr>,
        }

        impl BootstrapResolver for FixedResolver {
            fn resolve<'a>(
                &'a self,
                hostname: &'a str,
                port: u16,
                max_addresses: usize,
            ) -> BootstrapResolution<'a> {
                assert_eq!(hostname, IDENTITY_HOSTNAME);
                assert_eq!(port, 443);
                assert_eq!(max_addresses, 2);
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(self.addresses.clone()) })
            }
        }

        struct RejectedProtection {
            created: Arc<AtomicUsize>,
            prepared: Arc<AtomicUsize>,
        }

        impl SocketFactory for RejectedProtection {
            fn create_tcp(&self, address: SocketAddr) -> Result<TcpSocket, EngineError> {
                self.created.fetch_add(1, Ordering::SeqCst);
                DefaultSocketFactory.create_tcp(address)
            }

            fn prepare_tcp(
                &self,
                socket: &TcpSocket,
                endpoint: &EndpointDescriptor,
                _address: SocketAddr,
            ) -> Result<(), EngineError> {
                assert_eq!(endpoint.identity_hostname, IDENTITY_HOSTNAME);
                if let Ok(address) = socket.local_addr() {
                    assert_eq!(address.port(), 0);
                }
                self.prepared.fetch_add(1, Ordering::SeqCst);
                Err(EngineError::EgressDenied)
            }
        }

        fn endpoint() -> EndpointDescriptor {
            EndpointDescriptor {
                id: 1,
                generation: 1,
                identity_hostname: IDENTITY_HOSTNAME.into(),
                trust_group: TRUST_GROUP,
                bindings: vec![BindingId::H2],
                ech_required: false,
            }
        }

        fn policy() -> TrustPolicy {
            let certificate =
                rcgen::generate_simple_self_signed(vec![IDENTITY_HOSTNAME.into()]).unwrap();
            TrustPolicy::from_der_roots(TRUST_GROUP, vec![certificate.cert.der().to_vec()]).unwrap()
        }

        fn services(
            resolver_calls: Arc<AtomicUsize>,
            socket_calls: Arc<AtomicUsize>,
            prepare_calls: Arc<AtomicUsize>,
        ) -> HostServices {
            HostServices::new(
                Arc::new(FixedResolver {
                    calls: resolver_calls,
                    addresses: vec!["127.0.0.1:443".parse().unwrap()],
                }),
                Arc::new(RejectedProtection {
                    created: socket_calls,
                    prepared: prepare_calls,
                }),
                vec![policy()],
                2,
            )
            .unwrap()
        }

        #[tokio::test]
        async fn supplied_addresses_preserve_the_identity_hostname() {
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let host = services(
                Arc::clone(&resolver_calls),
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
            );
            let endpoint = endpoint();
            let addresses = host
                .resolve_endpoint(
                    &endpoint,
                    443,
                    Deadline::after(Duration::from_secs(1)).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(addresses, vec!["127.0.0.1:443".parse().unwrap()]);
            assert_eq!(endpoint.identity_hostname, IDENTITY_HOSTNAME);
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn required_ech_and_unknown_trust_do_not_resolve_or_create_sockets() {
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let socket_calls = Arc::new(AtomicUsize::new(0));
            let prepare_calls = Arc::new(AtomicUsize::new(0));
            let host = services(
                Arc::clone(&resolver_calls),
                Arc::clone(&socket_calls),
                Arc::clone(&prepare_calls),
            );
            for (ech_required, trust_group, expected) in [
                (true, TRUST_GROUP, EngineError::UnsupportedCapability),
                (false, 10, EngineError::PeerIdentityFailed),
            ] {
                let mut endpoint = endpoint();
                endpoint.ech_required = ech_required;
                endpoint.trust_group = trust_group;
                let deadline = Deadline::after(Duration::from_secs(1)).unwrap();
                assert_eq!(
                    host.resolve_endpoint(&endpoint, 443, deadline).await,
                    Err(expected)
                );
                assert_eq!(
                    host.connect_verified(&endpoint, "127.0.0.1:443".parse().unwrap(), deadline,)
                        .await
                        .unwrap_err(),
                    expected
                );
            }
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
            assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn failed_socket_protection_prevents_connect() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socket_calls = Arc::new(AtomicUsize::new(0));
            let prepare_calls = Arc::new(AtomicUsize::new(0));
            let host = services(
                Arc::new(AtomicUsize::new(0)),
                Arc::clone(&socket_calls),
                Arc::clone(&prepare_calls),
            );
            assert_eq!(
                host.connect_verified(
                    &endpoint(),
                    listener.local_addr().unwrap(),
                    Deadline::after(Duration::from_secs(1)).unwrap(),
                )
                .await
                .unwrap_err(),
                EngineError::EgressDenied
            );
            assert_eq!(socket_calls.load(Ordering::SeqCst), 1);
            assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn exhausted_parent_prevents_resolver_and_socket_calls() {
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let socket_calls = Arc::new(AtomicUsize::new(0));
            let host = services(
                Arc::clone(&resolver_calls),
                Arc::clone(&socket_calls),
                Arc::new(AtomicUsize::new(0)),
            );
            let deadline = Deadline::at(tokio::time::Instant::now());
            assert_eq!(
                host.resolve_endpoint(&endpoint(), 443, deadline).await,
                Err(EngineError::DeadlineExceeded)
            );
            assert_eq!(
                host.connect_verified(&endpoint(), "127.0.0.1:443".parse().unwrap(), deadline,)
                    .await
                    .unwrap_err(),
                EngineError::DeadlineExceeded
            );
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
        }

        #[cfg(feature = "h3-log-info")]
        struct RejectedUdpProtection {
            prepared: Arc<AtomicUsize>,
        }

        #[cfg(feature = "h3-log-info")]
        impl SocketFactory for RejectedUdpProtection {
            fn create_tcp(&self, address: SocketAddr) -> Result<TcpSocket, EngineError> {
                DefaultSocketFactory.create_tcp(address)
            }

            fn prepare_udp(
                &self,
                socket: &socket2::Socket,
                _endpoint: &EndpointDescriptor,
                _address: SocketAddr,
            ) -> Result<(), EngineError> {
                if let Ok(address) = socket.local_addr() {
                    assert_eq!(address.as_socket().unwrap().port(), 0);
                }
                self.prepared.fetch_add(1, Ordering::SeqCst);
                Err(EngineError::EgressDenied)
            }
        }

        #[cfg(feature = "h3-log-info")]
        #[tokio::test]
        async fn failed_udp_protection_runs_before_bind_and_prevents_quic_send() {
            let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let prepared = Arc::new(AtomicUsize::new(0));
            let host = HostServices::new(
                Arc::new(FixedResolver {
                    calls: Arc::new(AtomicUsize::new(0)),
                    addresses: Vec::new(),
                }),
                Arc::new(RejectedUdpProtection {
                    prepared: Arc::clone(&prepared),
                }),
                vec![policy()],
                2,
            )
            .unwrap();
            let mut endpoint = endpoint();
            endpoint.bindings.push(BindingId::H3);
            let config = H3Config::from_h2_config(&crate::h2_tunnel::H2Config::default()).unwrap();
            let result = host
                .connect_h3_verified(
                    &endpoint,
                    listener.local_addr().unwrap(),
                    config,
                    Deadline::after(Duration::from_secs(1)).unwrap(),
                )
                .await;
            assert!(matches!(result, Err(EngineError::EgressDenied)));
            assert_eq!(prepared.load(Ordering::SeqCst), 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.recv(&mut [0; 1200]))
                    .await
                    .is_err()
            );
        }
    }
}

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
pub use services::HostServices;

#[cfg(test)]
mod tests {
    use super::{Authorizer, StaticAuthorizer};
    use ariad_core::{Credential, EngineError};

    #[test]
    fn wrong_credential_is_authentication_denied() {
        let authorizer =
            StaticAuthorizer::new(Credential::from_bytes([0x11; Credential::BYTE_LEN]), 7);
        let error = authorizer
            .authorize(&Credential::from_bytes([0x22; Credential::BYTE_LEN]))
            .unwrap_err();
        assert_eq!(error, EngineError::AuthenticationDenied);
    }

    #[test]
    fn right_credential_returns_the_principal() {
        let authorizer =
            StaticAuthorizer::new(Credential::from_bytes([0x11; Credential::BYTE_LEN]), 42);
        let decision = authorizer
            .authorize(&Credential::from_bytes([0x11; Credential::BYTE_LEN]))
            .expect("matching credential");
        assert_eq!(decision.principal, 42);
    }
}
