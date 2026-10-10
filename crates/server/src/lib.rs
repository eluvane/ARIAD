#![forbid(unsafe_code)]

//! TLS/H2 listener services.
//! `run_with_options` authenticates before target DNS and connects checked IPs.

mod admission;
mod config;
mod gate;
mod listen;

pub use config::{LoadedConfig, Reject, load, validate};
pub use listen::{
    OpenedUdpSocket, ServerOptions, UdpConnection, UdpConnector, destination_allowed, run,
    run_with_options, run_with_udp_connector, serve_tls,
};
