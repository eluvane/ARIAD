use std::net::SocketAddr;

use ariad_engine::{BootstrapResolution, BootstrapResolver};

pub struct FixedResolver {
    address: SocketAddr,
    expected_hostname: Option<&'static str>,
}

impl FixedResolver {
    pub fn new(address: SocketAddr, expected_hostname: Option<&'static str>) -> Self {
        Self {
            address,
            expected_hostname,
        }
    }
}

impl BootstrapResolver for FixedResolver {
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
        max_addresses: usize,
    ) -> BootstrapResolution<'a> {
        Box::pin(async move {
            if let Some(expected) = self.expected_hostname {
                assert_eq!(hostname, expected);
            }
            assert_eq!(port, self.address.port());
            assert!(max_addresses > 0);
            Ok(vec![self.address])
        })
    }
}
