//! Verifies an echo target through a pinned H2/TLS engine.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

use ariad_embed::{
    Credential, Deadline, Destination, EngineError, PinnedH2Builder, echo_once,
    shutdown_after_operation,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let usage_message = format!(
        "usage: ariad-client-stream <endpoint-ip:port> <tls-name> <ca.der> <echo-destination>; set ARIAD_CREDENTIAL_HEX to {} hex digits",
        Credential::HEX_LEN
    );
    let usage = usage_message.as_str();
    let address: SocketAddr = arguments
        .next()
        .ok_or(usage)?
        .into_string()
        .map_err(|_| usage)?
        .parse()?;
    let identity = arguments
        .next()
        .ok_or(usage)?
        .into_string()
        .map_err(|_| usage)?;
    let trust_root_path = arguments.next().ok_or(usage)?;
    let destination = arguments
        .next()
        .ok_or(usage)?
        .into_string()
        .map_err(|_| usage)?;
    if arguments.next().is_some() {
        return Err(usage.into());
    }
    let mut trust_root_der = Vec::new();
    File::open(trust_root_path)?
        .take((PinnedH2Builder::MAX_TRUST_ROOT_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut trust_root_der)?;
    let destination = Destination::parse(&destination)?;
    let credential = credential_from_hex(
        &std::env::var("ARIAD_CREDENTIAL_HEX").map_err(|_| EngineError::InvalidConfig)?,
    )?;
    let payload: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
    let (engine, policy) = PinnedH2Builder::new(address, identity, trust_root_der).build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let deadline = Deadline::after(Duration::from_secs(30))?;
        let exchange_result = echo_once(
            &engine,
            &policy,
            credential,
            &destination,
            &payload,
            deadline,
        )
        .await;
        let count = shutdown_after_operation(&engine, exchange_result, deadline).await?;
        println!("h2_echo=ok bytes={count}");
        Ok(())
    })
}

fn credential_from_hex(value: &str) -> Result<Credential, EngineError> {
    let mut decoded = [0u8; Credential::BYTE_LEN];
    Credential::decode_hex(value.as_bytes(), &mut decoded)?;
    let credential = Credential::from_bytes(decoded);
    decoded.fill(0);
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_parser_checks_width_and_ascii() {
        let expected = Credential::from_bytes([0xab; Credential::BYTE_LEN]);
        assert!(
            credential_from_hex(&"aB".repeat(Credential::BYTE_LEN))
                .unwrap()
                .verify(&expected)
        );
        for value in [
            "a".repeat(Credential::HEX_LEN - 1),
            "a".repeat(Credential::HEX_LEN + 1),
            "é".repeat(Credential::BYTE_LEN),
            "g".repeat(Credential::HEX_LEN),
        ] {
            assert_eq!(
                credential_from_hex(&value).map(|_| ()),
                Err(EngineError::InvalidConfig)
            );
        }
    }
}
