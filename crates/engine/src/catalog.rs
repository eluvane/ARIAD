#![forbid(unsafe_code)]

use ariad_core::{EndpointDescriptor, EngineError};

/// Bounded endpoint metadata supplied by a trusted host.
///
/// The host is responsible for the catalog's authority and credential trust
/// groups. Descriptor validation checks metadata shape, not peer identity.
pub struct TrustedEndpoints {
    items: Vec<EndpointDescriptor>,
    cap: usize,
}

impl TrustedEndpoints {
    /// Sets the maximum endpoint count. Zero returns `InvalidConfig`.
    pub fn new(cap: usize) -> Result<Self, EngineError> {
        if cap == 0 {
            return Err(EngineError::InvalidConfig);
        }
        Ok(Self {
            items: Vec::new(),
            cap,
        })
    }

    /// Validates and appends an endpoint in insertion order.
    ///
    /// Validation errors take precedence over a full catalog, which returns
    /// `ResourceLimitExceeded`.
    pub fn push(&mut self, endpoint: EndpointDescriptor) -> Result<(), EngineError> {
        endpoint.validate()?;
        if self.items.len() == self.cap {
            return Err(EngineError::ResourceLimitExceeded);
        }
        self.items.push(endpoint);
        Ok(())
    }

    pub fn endpoints(&self) -> &[EndpointDescriptor] {
        &self.items
    }
}

impl crate::host::EndpointProvider for TrustedEndpoints {
    fn endpoints(&self) -> &[EndpointDescriptor] {
        TrustedEndpoints::endpoints(self)
    }
}

/// Rejects all peer header data with `InvalidConfig`.
///
/// Trusted endpoints must come from the host's `EndpointProvider`.
pub fn endpoint_from_header(_header: &[u8]) -> Result<EndpointDescriptor, EngineError> {
    Err(EngineError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ariad_core::BindingId;

    fn endpoint() -> EndpointDescriptor {
        EndpointDescriptor {
            id: 1,
            generation: 1,
            identity_hostname: "example.com".to_string(),
            trust_group: 1,
            bindings: vec![BindingId::H2],
            ech_required: false,
        }
    }

    #[test]
    fn host_list_is_bounded_and_headers_are_not_a_source() {
        let mut catalog = TrustedEndpoints::new(1).unwrap();
        catalog.push(endpoint()).unwrap();
        assert_eq!(
            catalog.push(endpoint()),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(catalog.endpoints().len(), 1);
        let header = b"x-forwarded-for: example.com";
        assert_eq!(
            endpoint_from_header(header),
            Err(EngineError::InvalidConfig)
        );
    }

    #[test]
    fn empty_hostname_is_not_trusted() {
        let mut catalog = TrustedEndpoints::new(2).unwrap();
        let mut bad = endpoint();
        bad.identity_hostname.clear();
        assert_eq!(catalog.push(bad), Err(EngineError::InvalidConfig));
        assert!(catalog.endpoints().is_empty());
    }
}
