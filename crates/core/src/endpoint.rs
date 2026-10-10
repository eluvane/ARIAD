#![forbid(unsafe_code)]

use std::net::SocketAddr;

use crate::address::validate_ascii_domain;
use crate::capability::BindingId;
use crate::error::EngineError;

pub const MAX_ENDPOINT_ADDRESS_HINTS: usize = 16;

/// Endpoint identity and policy, preserved when resolved addresses are attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub id: u64,
    /// Configuration generation used to separate endpoint cooldown entries.
    pub generation: u64,
    /// Hostname used for peer identity, independent of the dial address.
    pub identity_hostname: String,
    /// Credential group allowed to authenticate to this endpoint.
    pub trust_group: u64,
    pub bindings: Vec<BindingId>,
    pub ech_required: bool,
}

impl EndpointDescriptor {
    /// Checks hostname syntax and one or two distinct bindings.
    /// Invalid syntax, empty bindings, or duplicates return `InvalidConfig`;
    /// more than two bindings return `ResourceLimitExceeded`.
    pub fn validate(&self) -> Result<(), EngineError> {
        validate_ascii_domain(&self.identity_hostname)?;
        if self.bindings.is_empty() {
            return Err(EngineError::InvalidConfig);
        }
        if self.bindings.len() > 2 {
            return Err(EngineError::ResourceLimitExceeded);
        }
        if self.bindings.len() == 2 && self.bindings[0] == self.bindings[1] {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }

    pub fn permits_binding(&self, binding: BindingId) -> bool {
        self.bindings.contains(&binding)
    }

    pub fn permits_credential_group(&self, trust_group: u64) -> bool {
        self.trust_group == trust_group
    }

    /// Attaches validated dial addresses while retaining this identity and policy.
    pub fn with_addresses(
        self,
        addresses: Vec<SocketAddr>,
    ) -> Result<EndpointAddressHints, EngineError> {
        let hints = EndpointAddressHints {
            endpoint: self,
            addresses,
        };
        hints.validate()?;
        Ok(hints)
    }
}

/// Dial addresses associated with an endpoint's separate identity and policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAddressHints {
    pub endpoint: EndpointDescriptor,
    pub addresses: Vec<SocketAddr>,
}

impl EndpointAddressHints {
    /// Validates the endpoint and a bounded, nonempty list of addresses with
    /// nonzero ports. Empty lists return `EndpointResolutionFailed`, too many
    /// addresses return `ResourceLimitExceeded`, and zero ports return `InvalidConfig`.
    pub fn validate(&self) -> Result<(), EngineError> {
        self.endpoint.validate()?;
        if self.addresses.is_empty() {
            return Err(EngineError::EndpointResolutionFailed);
        }
        if self.addresses.len() > MAX_ENDPOINT_ADDRESS_HINTS {
            return Err(EngineError::ResourceLimitExceeded);
        }
        if self.addresses.iter().any(|address| address.port() == 0) {
            return Err(EngineError::InvalidConfig);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(hostname: &str, bindings: Vec<BindingId>) -> EndpointDescriptor {
        EndpointDescriptor {
            id: 1,
            generation: 1,
            identity_hostname: hostname.to_string(),
            trust_group: 1,
            bindings,
            ech_required: false,
        }
    }

    #[test]
    fn empty_hostname_fails() {
        let endpoint = descriptor("", vec![BindingId::H2]);
        assert_eq!(endpoint.validate(), Err(EngineError::InvalidConfig));
    }

    #[test]
    fn example_com_with_h2_passes() {
        let endpoint = descriptor("example.com", vec![BindingId::H2]);
        assert_eq!(endpoint.validate(), Ok(()));
    }

    #[test]
    fn dns_label_bounds_precede_binding_and_address_errors() {
        let valid_hostname = format!("{}.test", "A".repeat(63));
        let endpoint = descriptor(&valid_hostname, vec![BindingId::H2]);
        assert_eq!(endpoint.validate(), Ok(()));

        let too_long_label = "a".repeat(64);
        for hostname in [
            format!("{too_long_label}.test"),
            format!("first.{too_long_label}.test"),
            format!("first.{too_long_label}"),
        ] {
            let endpoint = descriptor(&hostname, vec![BindingId::H2]);
            assert_eq!(endpoint.validate(), Err(EngineError::InvalidConfig));
            assert_eq!(
                endpoint
                    .clone()
                    .with_addresses(vec!["127.0.0.1:443".parse().unwrap()]),
                Err(EngineError::InvalidConfig)
            );
            assert_eq!(
                endpoint.with_addresses(Vec::new()),
                Err(EngineError::InvalidConfig)
            );
            assert_eq!(
                descriptor(&hostname, vec![BindingId::H2; 3]).validate(),
                Err(EngineError::InvalidConfig)
            );
        }
    }

    #[test]
    fn address_hints_keep_identity_and_credential_scope() {
        let endpoint = descriptor("example.com", vec![BindingId::H2]);
        let hints = endpoint
            .clone()
            .with_addresses(vec!["127.0.0.1:443".parse().unwrap()])
            .unwrap();
        assert_eq!(hints.endpoint, endpoint);
        assert!(hints.endpoint.permits_credential_group(1));
        assert!(!hints.endpoint.permits_credential_group(2));
        assert!(hints.endpoint.permits_binding(BindingId::H2));
        assert!(!hints.endpoint.permits_binding(BindingId::H3));
    }

    #[test]
    fn address_hints_are_bounded_and_have_nonzero_ports() {
        let endpoint = descriptor("example.com", vec![BindingId::H2]);
        assert_eq!(
            endpoint.clone().with_addresses(Vec::new()),
            Err(EngineError::EndpointResolutionFailed)
        );
        assert_eq!(
            endpoint
                .clone()
                .with_addresses(vec!["127.0.0.1:0".parse().unwrap()]),
            Err(EngineError::InvalidConfig)
        );
        assert_eq!(
            endpoint.with_addresses(vec![
                "127.0.0.1:443".parse().unwrap();
                MAX_ENDPOINT_ADDRESS_HINTS + 1
            ]),
            Err(EngineError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn binding_metadata_cannot_expand_duplicate_dials() {
        assert_eq!(
            descriptor("example.com", vec![BindingId::H2; 3]).validate(),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(
            descriptor("example.com", vec![BindingId::H2; 2]).validate(),
            Err(EngineError::InvalidConfig)
        );
        assert_eq!(
            descriptor("example.com", vec![BindingId::H2, BindingId::H3]).validate(),
            Ok(())
        );
    }
}
