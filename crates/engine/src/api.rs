#![forbid(unsafe_code)]

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use std::sync::Arc;

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use ariad_core::Credential;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use ariad_core::NetworkEpoch;
use ariad_core::{BudgetLimits, EngineError, SessionPhase};

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use crate::Deadline;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use crate::connector::{ConnectRequest, EndpointConnector, EndpointPolicy, SelectedTransport};
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use crate::host::HostServices;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use crate::session_api::Session;
#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
use crate::session_api::{CloseMode, CloseOutcome, EngineResources, EngineRuntime};

/// Resource limits for transport sessions owned by an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// Limits validated when the engine is created.
    pub limits: BudgetLimits,
}

/// Outcomes observed by one engine shutdown call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// `Cancelled` for synchronous shutdown, or `Closed` for an awaited call.
    /// Per-session outcomes and unfinished connects are reported separately.
    pub phase: SessionPhase,
    /// Session close calls that completed with `CloseOutcome::Graceful`.
    pub closed_sessions: usize,
    /// Sessions cancelled synchronously or closed with `CloseOutcome::Forced`.
    pub forced_sessions: usize,
    /// Session close calls that returned an error.
    pub failed_sessions: usize,
    /// Pending connects still holding this engine's handshake reservations.
    /// Connects in other engines sharing a resource pool are excluded.
    pub pending_connects: usize,
}

/// Owns transport admission and connection lifecycle.
///
/// Transport quotas belong to this engine unless an `EngineResources` pool is
/// supplied. Dropping the engine requests session cancellation without waiting.
/// Async transport methods need a Tokio runtime with I/O and time enabled. The
/// caller owns that runtime and keeps it running until awaited cleanup finishes.
pub struct Engine {
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    runtime: std::sync::Arc<EngineRuntime>,
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    connector: Option<EndpointConnector>,
    config: EngineConfig,
}

impl Engine {
    /// Validates limits and creates an engine.
    ///
    /// With a TLS feature, the engine owns a transport resource pool; connecting
    /// requires a constructor with host services. Without TLS, configuration
    /// inspection and synchronous shutdown are available. Invalid limits return
    /// `InvalidConfig`.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.limits.validate()?;
        Ok(Self {
            #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
            runtime: EngineRuntime::new(config)?,
            #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
            connector: None,
            config,
        })
    }

    /// Uses host services with a transport resource pool owned by this engine.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub fn with_host_services(
        config: EngineConfig,
        host_services: Arc<HostServices>,
    ) -> Result<Self, EngineError> {
        let mut engine = Self::new(config)?;
        engine.connector = Some(EndpointConnector::with_limits(
            host_services,
            config.limits,
        )?);
        Ok(engine)
    }

    /// Shares transport quotas with engines that receive the same pool.
    ///
    /// Application memory, active session and pending handshake limits must match
    /// the pool. Per-session limits may differ.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub fn with_host_services_and_resources(
        config: EngineConfig,
        host_services: Arc<HostServices>,
        resources: Arc<EngineResources>,
    ) -> Result<Self, EngineError> {
        config.limits.validate()?;
        Ok(Self {
            runtime: EngineRuntime::new_with_resources(config, resources)?,
            connector: Some(EndpointConnector::with_limits(
                host_services,
                config.limits,
            )?),
            config,
        })
    }

    /// Returns the validated configuration, including after shutdown.
    pub fn config(&self) -> EngineConfig {
        self.config
    }

    /// Returns a handle to this engine's transport resource pool.
    ///
    /// Engines with the same pool observe the same quota usage. Keeping this
    /// handle does not keep sessions alive. Usage can remain nonzero until
    /// cancelled transports and pending connects release their reservations.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub fn resources(&self) -> Arc<EngineResources> {
        self.runtime.resources()
    }

    /// Returns the currently observed network epoch for connection policies.
    /// Concurrent network changes can advance the epoch after this call.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub fn network_epoch(&self) -> NetworkEpoch {
        self.runtime.epoch()
    }

    /// Connects a verified transport and waits for binding readiness.
    ///
    /// Retains the credential for later target opens; those opens have separate
    /// authorization and connection outcomes. The total connect deadline is also
    /// capped by the lab `ConnectTotal` limit. Shutdown or an epoch change cancels
    /// the connect. Dropping a pending connect releases its admission reservations,
    /// but network traffic already emitted remains an external effect.
    ///
    /// Returns `InvalidConfig` when host services were not supplied.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub async fn connect(
        &self,
        policy: &EndpointPolicy,
        credential: Credential,
        deadline: Deadline,
    ) -> Result<Session, EngineError> {
        let deadline = deadline.cap(ariad_core::lab_cap(ariad_core::DeadlineKind::ConnectTotal))?;
        let connector = self.connector.as_ref().ok_or(EngineError::InvalidConfig)?;
        let mut permit = self.runtime.begin_connect()?;
        let h2_config = self.runtime.h2_config()?;
        let selected = tokio::select! {
            biased;
            _ = self.runtime.wait_cancelled(permit.epoch) => return Err(EngineError::Cancelled),
            selected = connector.connect_with_config(policy, ConnectRequest { deadline, network_epoch: permit.epoch }, &h2_config) => selected?,
        };
        let channel_checks = (|| {
            deadline.remaining()?;
            if !selected
                .endpoint
                .permits_credential_group(policy.credential_trust_group)
                || !selected
                    .channel
                    .endpoint()
                    .permits_credential_group(policy.credential_trust_group)
                || selected.channel.endpoint() != &selected.endpoint
            {
                return Err(EngineError::PeerIdentityFailed);
            }
            if selected.binding != selected.channel.binding() {
                return Err(EngineError::UnsupportedCapability);
            }
            Ok(())
        })();
        let proxy = format!(
            "{}:{}",
            selected.endpoint.identity_hostname,
            selected.channel.address().port()
        );
        let session = match selected.channel {
            #[cfg(feature = "tls-rustls")]
            SelectedTransport::RustlsH2(channel) => {
                let session = channel.into_session();
                Session::from_h2(
                    session,
                    credential,
                    selected.endpoint.id,
                    selected.network_epoch,
                    proxy,
                    self.config.limits,
                    permit.take_slot()?,
                )
            }
            #[cfg(feature = "tls-boring")]
            SelectedTransport::BoringH2(channel) => {
                let session = channel.into_session();
                Session::from_h2(
                    session,
                    credential,
                    selected.endpoint.id,
                    selected.network_epoch,
                    proxy,
                    self.config.limits,
                    permit.take_slot()?,
                )
            }
            #[cfg(feature = "h3")]
            SelectedTransport::H3(session) => Session::from_h3(
                session,
                credential,
                selected.endpoint.id,
                selected.network_epoch,
                proxy,
                self.config.limits,
                permit.take_slot()?,
            ),
        };
        if let Err(error) = channel_checks
            .and_then(|()| self.runtime.register(&session))
            .and_then(|()| session.ensure_ready())
        {
            let _ = session.close(CloseMode::Immediate, deadline).await;
            return Err(error);
        }
        Ok(session)
    }

    /// Cancels work without waiting for transport cleanup.
    ///
    /// Permanently stops new connects. Sessions and pending connects may still
    /// hold reservations when the report is returned.
    pub fn shutdown(&mut self) -> ShutdownReport {
        #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
        let sessions = self.runtime.stop();
        #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
        for session in &sessions {
            session.cancel();
        }
        ShutdownReport {
            phase: SessionPhase::Cancelled,
            closed_sessions: 0,
            #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
            forced_sessions: sessions.len(),
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-boring")))]
            forced_sessions: 0,
            failed_sessions: 0,
            #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
            pending_connects: self.runtime.pending_connects(),
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-boring")))]
            pending_connects: 0,
        }
    }

    /// Observes the same or a newer network epoch; rejects a lower epoch.
    ///
    /// A newer epoch cancels pending connects and stops new opens on old sessions.
    /// Existing flows drain in background tasks under the lab `GracefulDrain` cap.
    /// This call does not wait for those tasks. An error after epoch advancement
    /// does not undo the new epoch or drains already started.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub fn on_network_change(&self, network_epoch: NetworkEpoch) -> Result<(), EngineError> {
        if network_epoch.get() < self.runtime.epoch().get() {
            return Err(EngineError::InvalidConfig);
        }
        if let Some(connector) = &self.connector {
            connector.on_network_change(network_epoch)?;
        }
        self.runtime.on_network_change(network_epoch)
    }

    /// Stops admission and drains sessions using one absolute deadline.
    ///
    /// Unfinished sessions are cancelled at the effective drain deadline. Transport
    /// cleanup is then awaited and can continue after the supplied expiration.
    /// Once shutdown starts, dropping its future leaves admission stopped and
    /// cancels the sessions captured by this call.
    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    pub async fn shutdown_with_deadline(&self, deadline: Deadline) -> ShutdownReport {
        let mut shutdown = ShutdownOperation {
            sessions: self.runtime.stop(),
            complete: false,
        };
        for session in &shutdown.sessions {
            session.inner.drain();
        }
        let mut closed_sessions = 0;
        let mut forced_sessions = 0;
        let mut failed_sessions = 0;
        for session in &shutdown.sessions {
            match session.close(CloseMode::Graceful, deadline).await {
                Ok(CloseOutcome::Graceful) => closed_sessions += 1,
                Ok(CloseOutcome::Forced) => forced_sessions += 1,
                Err(_) => {
                    failed_sessions += 1;
                    session.cancel();
                    // A concurrent close waiter can expire before transport cleanup.
                    let _ = session.inner.join_completion().await;
                }
            }
        }
        let _ = self.runtime.wait_pending(deadline).await;
        self.runtime.join_retired().await;
        let report = ShutdownReport {
            phase: SessionPhase::Closed,
            closed_sessions,
            forced_sessions,
            failed_sessions,
            pending_connects: self.runtime.pending_connects(),
        };
        shutdown.complete = true;
        report
    }
}

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
struct ShutdownOperation {
    sessions: Vec<Session>,
    complete: bool,
}

#[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
impl Drop for ShutdownOperation {
    fn drop(&mut self) {
        if !self.complete {
            for session in &self.sessions {
                session.cancel();
            }
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
        for session in self.runtime.stop() {
            session.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(EngineConfig {
            limits: BudgetLimits::lab_small(),
        })
        .expect("lab-small")
    }

    #[test]
    fn new_rejects_invalid_limits() {
        let mut limits = BudgetLimits::lab_small();
        limits.active_sessions = 0;
        assert!(matches!(
            Engine::new(EngineConfig { limits }),
            Err(EngineError::InvalidConfig)
        ));
    }

    #[test]
    fn configuration_is_retained_after_shutdown() {
        let config = EngineConfig {
            limits: BudgetLimits {
                active_sessions: 1,
                pending_handshakes: 1,
                ..BudgetLimits::lab_small()
            },
        };
        let mut engine = Engine::new(config).expect("engine");
        assert_eq!(engine.config(), config);
        engine.shutdown();
        assert_eq!(engine.config(), config);
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    #[test]
    fn default_resource_handles_observe_separate_engine_pools() {
        let first = engine();
        let second = engine();
        let first_resources = first.resources();
        let second_resources = second.resources();
        assert!(Arc::ptr_eq(&first_resources, &first.resources()));
        assert!(!Arc::ptr_eq(&first_resources, &second_resources));

        let pending = first.runtime.begin_connect().expect("pending connect");
        assert_eq!(first_resources.active_sessions(), 1);
        assert_eq!(first_resources.pending_handshakes(), 1);
        assert_eq!(second_resources.active_sessions(), 0);
        assert_eq!(second_resources.pending_handshakes(), 0);
        drop(first);
        assert_eq!(first_resources.pending_handshakes(), 1);
        drop(pending);
        assert_eq!(first_resources.active_sessions(), 0);
        assert_eq!(first_resources.pending_handshakes(), 0);
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    #[test]
    fn network_epoch_inspection_preserves_shutdown_state() {
        let mut engine = engine();
        let first_epoch = engine.network_epoch();
        assert_eq!(first_epoch, NetworkEpoch::start());
        let next_epoch = first_epoch.advance().expect("next epoch");
        engine
            .on_network_change(next_epoch)
            .expect("network change");
        assert_eq!(engine.network_epoch(), next_epoch);
        assert_eq!(
            engine.on_network_change(first_epoch),
            Err(EngineError::InvalidConfig)
        );
        engine.shutdown();
        assert_eq!(
            engine.on_network_change(next_epoch.advance().expect("later epoch")),
            Err(EngineError::Cancelled)
        );
        assert_eq!(engine.network_epoch(), next_epoch);
        assert!(matches!(
            engine.runtime.begin_connect(),
            Err(EngineError::Cancelled)
        ));
    }

    #[test]
    fn synchronous_shutdown_reports_cancellation_without_sessions() {
        let mut engine = engine();
        let expected = ShutdownReport {
            phase: SessionPhase::Cancelled,
            closed_sessions: 0,
            forced_sessions: 0,
            failed_sessions: 0,
            pending_connects: 0,
        };
        assert_eq!(engine.shutdown(), expected);
        assert_eq!(engine.shutdown(), expected);
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    #[test]
    fn synchronous_shutdown_stops_transport_admission() {
        let mut engine = engine();
        engine.shutdown();
        assert!(matches!(
            engine.runtime.begin_connect(),
            Err(EngineError::Cancelled)
        ));
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    #[tokio::test]
    async fn awaited_shutdown_closes_empty_runtime() {
        let engine = engine();
        let deadline = Deadline::after(std::time::Duration::from_secs(1)).expect("deadline");
        let expected = ShutdownReport {
            phase: SessionPhase::Closed,
            closed_sessions: 0,
            forced_sessions: 0,
            failed_sessions: 0,
            pending_connects: 0,
        };
        assert_eq!(engine.shutdown_with_deadline(deadline).await, expected);
        assert!(matches!(
            engine.runtime.begin_connect(),
            Err(EngineError::Cancelled)
        ));
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-boring"))]
    #[tokio::test]
    async fn shutdown_waits_for_cleanup_after_a_competing_close_wait_expires() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        use std::time::Duration;

        use ariad_core::Destination;

        use crate::h2_tunnel::{H2Config, H2Session, serve_h2_with_handler};
        use crate::session_api::StreamOptions;

        let deadline = Deadline::after(Duration::from_secs(2)).expect("deadline");
        let config = EngineConfig {
            limits: BudgetLimits::lab_small(),
        };
        let resources = Arc::new(EngineResources::new(config.limits).expect("resources"));
        let engine = Engine {
            runtime: EngineRuntime::new_with_resources(config, Arc::clone(&resources))
                .expect("runtime"),
            connector: None,
            config,
        };
        let (client, peer) = tokio::io::duplex(32 * 1024);
        let server = tokio::spawn(serve_h2_with_handler(
            peer,
            H2Config::default(),
            |request, mut respond, _| async move {
                let mut response = http::Response::new(());
                crate::connect::attach_h2_versions(response.headers_mut())?;
                let _sending = respond
                    .send_response(response, false)
                    .map_err(|_| EngineError::TransportUnavailable)?;
                let mut incoming = request.into_body();
                while let Some(chunk) = incoming.data().await {
                    let chunk = chunk.map_err(|_| EngineError::RemoteReset)?;
                    incoming
                        .flow_control()
                        .release_capacity(chunk.len())
                        .map_err(|_| EngineError::ProtocolViolation)?;
                }
                Ok(())
            },
            std::future::pending(),
        ));
        let mut permit = engine.runtime.begin_connect().expect("admit");
        let binding = H2Session::handshake_with_deadline(
            client,
            true,
            engine.runtime.h2_config().expect("config"),
            deadline,
        )
        .await
        .expect("handshake");
        let session = Session::from_h2(
            binding,
            Credential::from_bytes([0x11; Credential::BYTE_LEN]),
            1,
            permit.epoch,
            "example.test:443".to_owned(),
            config.limits,
            permit.take_slot().expect("session slot"),
        );
        engine.runtime.register(&session).expect("register");
        drop(permit);
        let stream = session
            .open_stream(
                &Destination::parse("1.1.1.1:9").expect("target"),
                StreamOptions::default(),
                deadline,
            )
            .await
            .expect("open");
        assert_eq!(resources.active_sessions(), 1);
        assert_eq!(resources.active_flows(), 1);
        let close_deadline = Deadline::after(Duration::from_secs(10)).expect("close deadline");
        let mut closing = Box::pin(session.close(CloseMode::Graceful, close_deadline));
        assert!(poll_fn(|context| Poll::Ready(closing.as_mut().poll(context).is_pending())).await);
        assert_eq!(session.phase(), SessionPhase::Draining);
        let report = tokio::time::timeout(
            Duration::from_secs(2),
            engine.shutdown_with_deadline(Deadline::at(tokio::time::Instant::now())),
        )
        .await
        .expect("shutdown cleanup watchdog");
        assert_eq!(
            report,
            ShutdownReport {
                phase: SessionPhase::Closed,
                closed_sessions: 0,
                forced_sessions: 0,
                failed_sessions: 1,
                pending_connects: 0,
            }
        );
        assert_eq!(resources.active_sessions(), 0);
        assert_eq!(resources.active_flows(), 0);
        assert_eq!(resources.pending_opens(), 0);
        assert_eq!(resources.pending_handshakes(), 0);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), closing)
                .await
                .expect("competing close watchdog")
                .expect("competing close cleanup"),
            CloseOutcome::Forced
        );
        drop(stream);
        drop(session);
        drop(engine);
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server cleanup watchdog")
            .expect("server task did not panic");
        assert!(matches!(
            result,
            Ok(()) | Err(EngineError::RemoteReset | EngineError::TransportUnavailable)
        ));
        assert_eq!(resources.application_memory_used(), 0);
    }
}
