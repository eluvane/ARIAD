use crate::support::CertificateFixture;

impl CertificateFixture {
    pub fn native_server(&self) -> ariad_engine::NativeTlsServer {
        let (chain, key) = self.identity();
        ariad_engine::NativeTlsServer::from_der(
            &chain
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect::<Vec<_>>(),
            key.secret_der(),
        )
        .expect("native TLS server")
    }
}
