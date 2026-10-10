#![forbid(unsafe_code)]

use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::OnceLock;

use ariad_core::{EngineError, ResourceBudget, normalize_ip};

/// A lookup future that may borrow the resolver and hostname for its lifetime.
pub type BootstrapResolution<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, EngineError>> + Send + 'a>>;

/// Resolves hostnames under the host's DNS policy.
///
/// Return at most the requested address count with the requested port. The
/// caller checks the answer before dialing. Endpoint connection callers retain
/// the original hostname for TLS verification. Resolved addresses do not
/// establish peer identity.
///
/// Implementations choose the network and routing for DNS independently of
/// transport socket preparation. A tunnel host must keep bootstrap lookups on a
/// route that can reach the endpoint before the tunnel is established.
pub trait BootstrapResolver: Send + Sync {
    /// Resolve with a nonzero `port` and `max_addresses`.
    ///
    /// Calls and lookup futures can run concurrently on runtime workers,
    /// with no calling-thread affinity. Return the future promptly and avoid
    /// blocking its polls; the caller's async deadline cannot interrupt blocking
    /// host code. Callers may drop the future on timeout or cancellation.
    /// Cancellation of underlying work depends on the implementation.
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
        max_addresses: usize,
    ) -> BootstrapResolution<'a>;
}

/// Uses OS DNS with a shared process limit of 64 queries.
/// OS queries require a Tokio runtime.
///
/// A running OS query can outlive cancellation. Its worker keeps the reservation
/// until it exits. Oversized answers are rejected before removing duplicates.
/// OS DNS follows system routing; use a custom resolver for host network selection.
#[derive(Debug, Default)]
pub struct SystemBootstrapResolver;

impl BootstrapResolver for SystemBootstrapResolver {
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
        max_addresses: usize,
    ) -> BootstrapResolution<'a> {
        Box::pin(async move {
            if port == 0 || max_addresses == 0 {
                return Err(EngineError::InvalidConfig);
            }
            // Probe one extra answer so overflow is rejected rather than silently truncated.
            let answer_probe_limit = max_addresses
                .checked_add(1)
                .ok_or(EngineError::InvalidConfig)?;
            let hostname = hostname.to_owned();
            run_blocking_query(process_dns_budget()?, move || {
                let resolved_addresses = (hostname.as_str(), port)
                    .to_socket_addrs()
                    .map_err(|_| EngineError::EndpointResolutionFailed)?;
                let addresses = resolved_addresses.take(answer_probe_limit).collect();
                constrain_addresses(addresses, port, max_addresses)
            })
            .await
        })
    }
}

fn process_dns_budget() -> Result<&'static ResourceBudget, EngineError> {
    static PROCESS_DNS_BUDGET: OnceLock<Result<ResourceBudget, EngineError>> = OnceLock::new();
    PROCESS_DNS_BUDGET
        .get_or_init(|| ResourceBudget::new(64))
        .as_ref()
        .map_err(|error| *error)
}

async fn run_blocking_query<F>(
    budget: &ResourceBudget,
    query: F,
) -> Result<Vec<SocketAddr>, EngineError>
where
    F: FnOnce() -> Result<Vec<SocketAddr>, EngineError> + Send + 'static,
{
    let reservation = budget.try_acquire()?;
    // The worker owns the reservation because cancelling its await does not stop OS DNS.
    tokio::task::spawn_blocking(move || {
        let result = query();
        drop(reservation);
        result
    })
    .await
    .map_err(|_| EngineError::EndpointResolutionFailed)?
}

pub(crate) fn validate_address(address: SocketAddr) -> Result<(), EngineError> {
    let ip = normalize_ip(address.ip());
    if address.port() == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(EngineError::EndpointResolutionFailed);
    }
    Ok(())
}

/// Check the answer count and requested port, then preserve first-seen address order.
/// Duplicate entries count toward the limit before they are removed.
pub(crate) fn constrain_addresses(
    addresses: Vec<SocketAddr>,
    port: u16,
    max_addresses: usize,
) -> Result<Vec<SocketAddr>, EngineError> {
    if port == 0 || max_addresses == 0 {
        return Err(EngineError::InvalidConfig);
    }
    if addresses.len() > max_addresses {
        return Err(EngineError::ResourceLimitExceeded);
    }
    if addresses.is_empty() {
        return Err(EngineError::EndpointResolutionFailed);
    }
    let mut unique_addresses = Vec::new();
    for address in addresses {
        validate_address(address)?;
        if address.port() != port {
            return Err(EngineError::EndpointResolutionFailed);
        }
        if !unique_addresses.contains(&address) {
            unique_addresses.push(address);
        }
    }
    Ok(unique_addresses)
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, SocketAddrV6};
    use std::time::Duration;

    use super::{constrain_addresses, run_blocking_query};
    use ariad_core::{EngineError, ResourceBudget};

    #[test]
    fn oversized_or_empty_resolver_answers_are_rejected() {
        let first = "127.0.0.1:443".parse().unwrap();
        let second = "127.0.0.2:443".parse().unwrap();
        assert_eq!(
            constrain_addresses(vec![first, second], 443, 1),
            Err(EngineError::ResourceLimitExceeded)
        );
        assert_eq!(
            constrain_addresses(Vec::new(), 443, 1),
            Err(EngineError::EndpointResolutionFailed)
        );
    }

    #[test]
    fn invalid_addresses_or_changed_ports_are_rejected() {
        for address in [
            "127.0.0.1:0",
            "127.0.0.1:8443",
            "0.0.0.0:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[::]:443",
            "[ff02::1]:443",
            "[::ffff:0.0.0.0]:443",
            "[::ffff:224.0.0.1]:443",
            "[::ffff:255.255.255.255]:443",
        ] {
            assert_eq!(
                constrain_addresses(vec![address.parse().unwrap()], 443, 8),
                Err(EngineError::EndpointResolutionFailed)
            );
        }
    }

    #[test]
    fn mapped_unicast_and_scoped_answers_keep_the_original_routes() {
        let addresses = vec![
            "127.0.0.1:443".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(
                "::ffff:127.0.0.1".parse().unwrap(),
                443,
                17,
                3,
            )),
            "[::ffff:10.0.0.1]:443".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 443, 29, 7)),
        ];
        assert_eq!(
            constrain_addresses(addresses.clone(), 443, addresses.len()),
            Ok(addresses)
        );
    }

    #[test]
    fn duplicates_keep_the_original_order() {
        let first = "127.0.0.1:443".parse().unwrap();
        let second = "[::1]:443".parse().unwrap();
        assert_eq!(
            constrain_addresses(vec![first, second, first], 443, 3),
            Ok(vec![first, second])
        );
    }

    #[tokio::test]
    async fn cancelled_lookup_keeps_the_running_worker_charged() {
        let budget = ResourceBudget::new(1).unwrap();
        let worker_budget = budget.clone();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let operation = tokio::spawn(async move {
            run_blocking_query(&worker_budget, move || {
                started.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(Vec::new())
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .unwrap()
            .unwrap();
        operation.abort();
        assert!(operation.await.unwrap_err().is_cancelled());
        assert_eq!(budget.used(), 1);
        assert_eq!(
            budget.try_acquire().unwrap_err(),
            EngineError::ResourceLimitExceeded
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.used() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(budget.used(), 0);
    }
}
