#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use ariad_core::{BindingId, EndpointDescriptor, EngineError};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout_at;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::Deadline;
use crate::tls_policy::{H2_ALPN, RUSTLS_TLS_VERSION};
use crate::trust::{EchState, TrustPolicy};

/// A completed TLS 1.3 handshake with h2 ALPN, valid chain and expected name,
/// and all restrictions from the selected trust policy.
pub struct VerifiedTlsChannel {
    io: TlsStream<TcpStream>,
    endpoint: EndpointDescriptor,
    address: SocketAddr,
}

impl VerifiedTlsChannel {
    pub fn endpoint(&self) -> &EndpointDescriptor {
        &self.endpoint
    }

    pub const fn endpoint_id(&self) -> u64 {
        self.endpoint.id
    }

    pub const fn trust_group(&self) -> u64 {
        self.endpoint.trust_group
    }

    pub const fn binding(&self) -> BindingId {
        BindingId::H2
    }

    pub const fn ech(&self) -> EchState {
        EchState::Unsupported
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Transfer the TLS stream to the caller. H2 startup has not yet run.
    pub fn into_io(self) -> TlsStream<TcpStream> {
        self.io
    }
}

impl fmt::Debug for VerifiedTlsChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTlsChannel")
            .field("binding", &self.binding())
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifiedTlsConnector {
    connector: TlsConnector,
}

impl VerifiedTlsConnector {
    pub(crate) fn new(policy: TrustPolicy) -> Result<Self, EngineError> {
        Ok(Self {
            connector: TlsConnector::from(Arc::new(policy.client_config()?)),
        })
    }

    pub(crate) async fn connect(
        &self,
        stream: TcpStream,
        endpoint: &EndpointDescriptor,
        address: SocketAddr,
        deadline: Deadline,
    ) -> Result<VerifiedTlsChannel, EngineError> {
        deadline.remaining()?;
        let server_name = ServerName::try_from(endpoint.identity_hostname.clone())
            .map_err(|_| EngineError::InvalidConfig)?;
        let tls = timeout_at(
            deadline.expires_at(),
            self.connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| EngineError::DeadlineExceeded)?
        .map_err(classify_tls_error)?;
        deadline.remaining()?;
        let (_, connection) = tls.get_ref();
        if connection.protocol_version() != Some(RUSTLS_TLS_VERSION.version)
            || connection.alpn_protocol() != Some(H2_ALPN)
        {
            return Err(EngineError::UnsupportedCapability);
        }
        Ok(VerifiedTlsChannel {
            io: tls,
            endpoint: endpoint.clone(),
            address,
        })
    }
}

fn classify_tls_error(error: std::io::Error) -> EngineError {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_))
        | Some(rustls::Error::NoCertificatesPresented) => EngineError::PeerIdentityFailed,
        Some(rustls::Error::NoApplicationProtocol)
        | Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::NoApplicationProtocol
            | rustls::AlertDescription::ProtocolVersion,
        )) => EngineError::UnsupportedCapability,
        _ => EngineError::TransportUnavailable,
    }
}
