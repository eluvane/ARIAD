//! Runs a loopback H2/TLS tunnel with an in-memory echo target.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ariad_embed::{
    Credential, Deadline, Destination, EngineError, PinnedH2Builder, ReadOutcome, StreamOptions,
    close_after_operation, shutdown_after_operation,
};
use ariad_engine::{StaticAuthorizer, serve_one};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ECHO_CREDENTIAL: [u8; Credential::BYTE_LEN] = [0x11; Credential::BYTE_LEN];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let signed_certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let certificate = CertificateDer::from(signed_certificate.cert);
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        signed_certificate.key_pair.serialize_der(),
    ));
    let mut server_config =
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let public = Destination::parse("1.1.1.1:9")?;
    let payload: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
    let deadline = Deadline::after(Duration::from_secs(10))?;
    let (engine, policy) =
        PinnedH2Builder::new(address, "localhost", certificate.as_ref().to_vec()).build()?;
    let dial_count = Arc::new(AtomicUsize::new(0));
    let (echo_task_sender, echo_task_receiver) = tokio::sync::oneshot::channel();

    let server_dial_count = Arc::clone(&dial_count);
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        let tls = acceptor
            .accept(tcp)
            .await
            .map_err(|_| EngineError::TransportUnavailable)?;
        let authorizer = StaticAuthorizer::new(Credential::from_bytes(ECHO_CREDENTIAL), 7);
        serve_one(tls, authorizer, false, move |destination| {
            let server_dial_count = Arc::clone(&server_dial_count);
            async move {
                server_dial_count.fetch_add(1, Ordering::SeqCst);
                if destination.as_ip().is_none() || destination.port() != 9 {
                    return Err(EngineError::EgressDenied);
                }
                let (tunnel_side, echo_side) = tokio::io::duplex(4096);
                let echo_task = tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(echo_side);
                    let mut buffer = [0u8; 2048];
                    let mut echoed_bytes = 0;
                    loop {
                        let received = read
                            .read(&mut buffer)
                            .await
                            .map_err(|_| EngineError::TransportUnavailable)?;
                        if received == 0 {
                            break;
                        }
                        write
                            .write_all(&buffer[..received])
                            .await
                            .map_err(|_| EngineError::TransportUnavailable)?;
                        echoed_bytes += received;
                    }
                    write
                        .shutdown()
                        .await
                        .map_err(|_| EngineError::TransportUnavailable)?;
                    Ok::<usize, EngineError>(echoed_bytes)
                });
                if let Err(echo_task) = echo_task_sender.send(echo_task) {
                    abort_and_join_task(echo_task).await;
                    return Err(EngineError::TransportUnavailable);
                }
                Ok(tunnel_side)
            }
        })
        .await
    });

    let exchange_result = async {
        let session = engine
            .connect(&policy, Credential::from_bytes(ECHO_CREDENTIAL), deadline)
            .await
            .inspect_err(|error| eprintln!("H2 connect failed: {error}"))?;
        let result = async {
            let stream = session
                .open_stream(&public, StreamOptions::default(), deadline)
                .await?;
            let (mut reader, mut writer) = stream.into_split();
            let upload = &payload;
            let send = async move {
                writer.write_all(upload, deadline).await?;
                writer.end_write(deadline).await
            };
            let download = &payload;
            let receive = async move {
                let mut received = 0;
                let mut buffer = [0; 16 * 1024];
                while received < download.len() {
                    let count = buffer.len().min(download.len() - received);
                    reader.read_exact(&mut buffer[..count], deadline).await?;
                    if buffer[..count] != download[received..received + count] {
                        return Err(EngineError::ProtocolViolation);
                    }
                    received += count;
                }
                match reader.read(&mut buffer[..1], deadline).await? {
                    ReadOutcome::Eof => Ok(received),
                    ReadOutcome::Cancelled => Err(EngineError::Cancelled),
                    ReadOutcome::Reset => Err(EngineError::RemoteReset),
                    ReadOutcome::Truncated => Err(EngineError::TruncatedStream),
                    ReadOutcome::Data(_) | ReadOutcome::Waiting => {
                        Err(EngineError::ProtocolViolation)
                    }
                }
            };
            let ((), exchanged) = tokio::try_join!(send, receive)?;
            Ok::<usize, EngineError>(exchanged)
        }
        .await
        .inspect_err(|error| eprintln!("H2 stream exchange failed: {error}"));
        close_after_operation(&session, result, deadline)
            .await
            .inspect_err(|error| eprintln!("H2 exchange or session close failed: {error}"))
    }
    .await;
    let client_result = shutdown_after_operation(&engine, exchange_result, deadline)
        .await
        .inspect_err(|error| eprintln!("H2 client failed: {error}"));
    let server_result = finish_task(server_task, deadline, client_result.is_err()).await;
    if let Err(error) = server_result {
        eprintln!("H2 server failed: {error}");
    }
    let echo_result = match echo_task_receiver.await {
        Ok(echo_task) => {
            finish_task(
                echo_task,
                deadline,
                client_result.is_err() || server_result.is_err(),
            )
            .await
        }
        Err(_) => Err(EngineError::TransportUnavailable),
    };
    let exchanged = client_result?;
    server_result?;
    let echoed = echo_result?;
    if echoed != payload.len() || dial_count.load(Ordering::SeqCst) != 1 {
        return Err(EngineError::ProtocolViolation.into());
    }
    println!("h2_engine_echo=ok bytes={exchanged}");
    Ok(())
}

async fn abort_and_join_task<T>(task: JoinHandle<T>) {
    task.abort();
    let _ = task.await;
}

async fn finish_task<T>(
    mut task: JoinHandle<Result<T, EngineError>>,
    deadline: Deadline,
    abort: bool,
) -> Result<T, EngineError> {
    if abort {
        abort_and_join_task(task).await;
        return Err(EngineError::Cancelled);
    }
    // A completed JoinHandle must not be polled again after a deadline error.
    let mut joined = false;
    let result = deadline
        .run(async {
            let result = (&mut task).await;
            joined = true;
            result.map_err(|_| EngineError::TransportUnavailable)?
        })
        .await;
    if !joined {
        abort_and_join_task(task).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_task_join_waits_for_cancellation_cleanup() {
        let task = tokio::spawn(std::future::pending::<Result<(), EngineError>>());
        let abort_handle = task.abort_handle();
        assert_eq!(
            finish_task(task, Deadline::at(tokio::time::Instant::now()), false).await,
            Err(EngineError::DeadlineExceeded)
        );
        assert!(abort_handle.is_finished());
    }

    #[tokio::test]
    async fn completed_task_error_is_returned_without_a_second_join() {
        let task = tokio::spawn(async { Err::<(), EngineError>(EngineError::EgressDenied) });
        assert_eq!(
            finish_task(
                task,
                Deadline::after(Duration::from_secs(1)).unwrap(),
                false
            )
            .await,
            Err(EngineError::EgressDenied)
        );
    }
}
