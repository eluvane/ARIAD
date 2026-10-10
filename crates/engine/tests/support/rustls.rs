use std::sync::Arc;
use std::time::Duration;

use ariad_engine::Deadline;
use rustls::ServerConfig;

use crate::support::CertificateFixture;

pub const IO_TIMEOUT: Duration = Duration::from_secs(3);

pub fn deadline() -> Deadline {
    Deadline::after(IO_TIMEOUT).expect("deadline")
}

impl CertificateFixture {
    pub fn server_config(&self, alpn: &[u8]) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (chain, key) = self.identity();
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        config.alpn_protocols = vec![alpn.to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        Arc::new(config)
    }
}
