#![forbid(unsafe_code)]

#[path = "support/auth.rs"]
mod auth_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ariad_core::{Credential, Destination, EngineError, MemoryBudget, ResourceBudget};
use ariad_engine::{
    ClientRoundtrip, H2Config, H2Session, ReadOutcome, StaticAuthorizer, client_roundtrip,
    client_roundtrip_with_limit, open_h2, serve_h2, serve_h2_with_handler, serve_one,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use auth_support::credential;

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const PREAUTH_TIMEOUT: Duration = Duration::from_millis(500);

fn target_destination() -> Destination {
    Destination::parse("1.1.1.1:9").expect("destination")
}

fn pre_auth_config() -> H2Config {
    H2Config {
        open_timeout: PREAUTH_TIMEOUT,
        ..H2Config::default()
    }
}

#[tokio::test]
async fn streaming_roundtrip_transfers_512_kib_in_both_directions() {
    let (client, server_io) = tokio::io::duplex(128);
    let payload = vec![b'q'; 512 * 1024];
    let server = tokio::spawn(async move {
        serve_one(
            server_io,
            StaticAuthorizer::new(credential(), 7),
            false,
            move |_| async move {
                let (target, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = peer.read(&mut buf).await.expect("target read");
                        if n == 0 {
                            peer.shutdown().await.expect("target shutdown");
                            break;
                        }
                        peer.write_all(&buf[..n]).await.expect("target echo");
                    }
                });
                Ok::<_, EngineError>(target)
            },
        )
        .await
    });
    let destination = target_destination();
    let round = timeout(
        IO_TIMEOUT,
        client_roundtrip_with_limit(
            client,
            &destination,
            &credential(),
            true,
            &payload,
            payload.len(),
        ),
    )
    .await
    .expect("stream progress")
    .expect("roundtrip");
    assert_eq!(round.reply, payload);
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn stream_write_can_deliver_more_than_one_receive_window() {
    let (client, server_io) = tokio::io::duplex(128);
    let server = tokio::spawn(async move {
        serve_one(
            server_io,
            StaticAuthorizer::new(credential(), 7),
            false,
            move |_| async move {
                let (target, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut bytes = 0usize;
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = peer.read(&mut buf).await.expect("request");
                        if n == 0 {
                            break;
                        }
                        bytes += n;
                        assert!(buf[..n].iter().all(|byte| *byte == b'q'));
                    }
                    assert_eq!(bytes, 512 * 1024);
                    peer.write_all(b"done").await.expect("reply");
                    peer.shutdown().await.expect("shutdown");
                });
                Ok::<_, EngineError>(target)
            },
        )
        .await
    });
    timeout(IO_TIMEOUT, async {
        let destination = target_destination();
        let mut stream = open_h2(client, &destination, &credential(), true)
            .await
            .expect("open");
        let mut rest = vec![b'q'; 512 * 1024];
        let mut offset = 0;
        while offset < rest.len() {
            offset += stream.write(&rest[offset..]).await.expect("write");
        }
        rest.clear();
        stream.end_write().await.expect("end write");
        let mut reply = [0u8; 4];
        assert_eq!(
            stream.read(&mut reply).await.expect("reply"),
            ReadOutcome::Data(4)
        );
        assert_eq!(reply, *b"done");
        assert_eq!(
            stream.read(&mut reply).await.expect("eof"),
            ReadOutcome::Eof
        );
        server.await.expect("join").expect("serve");
    })
    .await
    .expect("stream progress");
}

#[tokio::test]
async fn concurrent_closes_drain_an_existing_stream_and_join_the_driver() {
    let (client, server_io) = tokio::io::duplex(128);
    let memory = MemoryBudget::new(1024 * 1024).expect("memory");
    let server = tokio::spawn(async move {
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            H2Config::default(),
            move |_| async move {
                let (target, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    peer.read_to_end(&mut bytes).await.expect("request");
                    assert_eq!(bytes, b"ping");
                    peer.write_all(b"pong").await.expect("reply");
                    peer.shutdown().await.expect("shutdown");
                });
                Ok::<_, EngineError>(target)
            },
            std::future::pending(),
        )
        .await
    });
    let config = H2Config {
        process_budget: memory.clone(),
        session_budget: MemoryBudget::new(1024 * 1024).expect("session memory"),
        ..H2Config::default()
    };
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("session");
    let destination = target_destination();
    let mut stream = session
        .open_stream(&destination, &credential())
        .await
        .expect("stream");
    let exchange = async {
        stream.write(b"ping").await.expect("write");
        stream.end_write().await.expect("end write");
        let mut reply = [0u8; 4];
        assert_eq!(
            stream.read(&mut reply).await.expect("reply"),
            ReadOutcome::Data(4)
        );
        assert_eq!(reply, *b"pong");
        assert_eq!(
            stream.read(&mut reply).await.expect("eof"),
            ReadOutcome::Eof
        );
    };
    let (_, first, second) = timeout(IO_TIMEOUT, async {
        tokio::join!(
            exchange,
            session.close(IO_TIMEOUT),
            session.close(IO_TIMEOUT)
        )
    })
    .await
    .expect("drain completion");
    assert_eq!(first, Ok(()));
    assert_eq!(second, Ok(()));
    assert!(
        memory.used() > 0,
        "retained stream metadata remains charged"
    );
    drop(stream);
    let owner_charge = memory.used();
    assert!(
        owner_charge > 0,
        "retained session metadata remains charged"
    );
    let retained_session = session.clone();
    drop(session);
    assert_eq!(memory.used(), owner_charge);
    drop(retained_session);
    assert_eq!(memory.used(), 0);
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn remote_orderly_shutdown_is_visible_and_an_idle_close_is_clean() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        tokio::select! {
            _ = shutdown_rx => connection.graceful_shutdown(),
            _ = connection.accept() => panic!("no request expected"),
        }
        while let Some(incoming) = connection.accept().await {
            if let Err(error) = incoming {
                assert!(
                    error
                        .get_io()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe),
                    "{error:?}"
                );
                break;
            }
        }
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    shutdown_tx.send(()).expect("shutdown signal");
    assert_eq!(
        timeout(IO_TIMEOUT, session.wait_closed())
            .await
            .expect("driver completion"),
        Ok(())
    );
    assert_eq!(
        session.driver_error(),
        Some(EngineError::TransportUnavailable)
    );
    assert!(!session.extended_connect_enabled());
    session.close(IO_TIMEOUT).await.expect("idle close");
    assert_eq!(session.driver_error(), None);
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join");
}

#[tokio::test]
async fn decoded_header_field_limit_rejects_before_dial() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let server_dials = Arc::clone(&dials);
    let server = tokio::spawn(async move {
        let config = H2Config {
            max_header_count: 8,
            ..H2Config::default()
        };
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            config,
            move |_| {
                server_dials.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<tokio::io::DuplexStream, EngineError>(EngineError::TargetConnectFailed)
                }
            },
            std::future::pending(),
        )
        .await
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    let destination = target_destination();
    let mut request = ariad_engine::connect_template(&destination).expect("request");
    for name in ["x-a", "x-b", "x-c", "x-d"] {
        request
            .headers_mut()
            .insert(name, http::HeaderValue::from_static("value"));
    }
    assert!(matches!(
        session.open_request(request, &credential()).await,
        Err(EngineError::RemoteReset)
    ));
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    let allowed = session
        .open_stream(&destination, &credential())
        .await
        .expect("allowed headers");
    assert_eq!(allowed.status(), http::StatusCode::BAD_GATEWAY);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    drop(allowed);
    session.close(IO_TIMEOUT).await.expect("close");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn peer_transport_close_bounds_and_joins_an_idle_handler() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (target, mut peer) = tokio::io::duplex(64);
    let target = Arc::new(std::sync::Mutex::new(Some(target)));
    let server = tokio::spawn(async move {
        serve_h2_with_handler(
            server_io,
            H2Config {
                drain_timeout: Duration::from_millis(50),
                ..H2Config::default()
            },
            move |request, mut respond, _| {
                let target = target
                    .lock()
                    .expect("target lock")
                    .take()
                    .expect("one target");
                async move {
                    let _target = target;
                    let _request = request;
                    let response = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(())
                        .expect("response");
                    let _send = respond
                        .send_response(response, false)
                        .expect("response send");
                    std::future::pending::<Result<(), EngineError>>().await
                }
            },
            std::future::pending(),
        )
        .await
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    let destination = target_destination();
    let _stream = session
        .open_stream(&destination, &credential())
        .await
        .expect("stream");
    session.cancel();
    assert_eq!(session.close(IO_TIMEOUT).await, Err(EngineError::Cancelled));
    assert_eq!(
        timeout(IO_TIMEOUT, server)
            .await
            .expect("server cleanup")
            .expect("join"),
        Err(EngineError::DeadlineExceeded)
    );
    peer.write_all(b"still open")
        .await
        .expect_err("target released before server returned");
}

#[tokio::test]
async fn default_roundtrip_collector_remains_bounded() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let server = tokio::spawn(async move {
        serve_one(
            server_io,
            StaticAuthorizer::new(credential(), 7),
            false,
            move |_| async move {
                let (target, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let _ = peer.write_all(&[b'r'; 16 * 1024 + 1]).await;
                    let _ = peer.shutdown().await;
                });
                Ok::<_, EngineError>(target)
            },
        )
        .await
    });
    let destination = target_destination();
    let result = timeout(
        IO_TIMEOUT,
        client_roundtrip(client, &destination, &credential(), true, b""),
    )
    .await
    .expect("collector completion");
    assert_eq!(
        result.expect_err("collector limit"),
        EngineError::ResourceLimitExceeded
    );
    let _ = timeout(IO_TIMEOUT, server)
        .await
        .expect("server cleanup")
        .expect("join");
}

#[tokio::test]
async fn session_reuses_the_connection_and_authenticates_every_stream() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let server_dials = Arc::clone(&dials);
    let server = tokio::spawn(async move {
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            H2Config::default(),
            move |_| {
                server_dials.fetch_add(1, Ordering::SeqCst);
                async {
                    let (target, mut peer) = tokio::io::duplex(64);
                    tokio::spawn(async move {
                        let mut bytes = Vec::new();
                        peer.read_to_end(&mut bytes).await.expect("request");
                        peer.write_all(&bytes).await.expect("reply");
                        peer.shutdown().await.expect("shutdown");
                    });
                    Ok::<_, EngineError>(target)
                }
            },
            std::future::pending(),
        )
        .await
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    assert!(session.extended_connect_enabled());
    let destination = target_destination();
    let mut first = session
        .open_stream(&destination, &credential())
        .await
        .expect("first");
    let denied = session
        .open_stream(&destination, &Credential::from_bytes([0x22; 32]))
        .await
        .expect("denied response");
    assert_eq!(denied.status(), http::StatusCode::FORBIDDEN);
    drop(denied);
    let mut second = session
        .open_stream(&destination, &credential())
        .await
        .expect("second");
    for opened in [&mut first, &mut second] {
        assert_eq!(opened.write(b"ping").await.expect("write"), 4);
        opened.end_write().await.expect("end write");
        let mut reply = [0u8; 4];
        assert_eq!(
            opened.read(&mut reply).await.expect("reply"),
            ReadOutcome::Data(4)
        );
        assert_eq!(reply, *b"ping");
        assert_eq!(
            opened.read(&mut reply).await.expect("eof"),
            ReadOutcome::Eof
        );
    }
    assert_eq!(dials.load(Ordering::SeqCst), 2);
    session.close(IO_TIMEOUT).await.expect("session close");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn unread_bytes_keep_their_memory_reservation_and_receive_credit() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (capacity_tx, mut capacity_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        let (request, mut respond) = connection.accept().await.expect("request").expect("accept");
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response");
        send.send_data(bytes::Bytes::from_static(b"12345678"), false)
            .expect("reply");
        send.reserve_capacity(8);
        tokio::select! {
            _ = async {
                let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx)).await.expect("stream capacity").expect("capacity");
                assert!(capacity > 0);
                capacity_tx.send(capacity).expect("capacity signal");
                std::future::pending::<()>().await;
            } => {}
            _ = connection.accept() => {}
        }
        drop(request);
    });
    let process_memory = MemoryBudget::new(64 * 1024).expect("process budget");
    let session_memory = MemoryBudget::new(64 * 1024).expect("session budget");
    let config = H2Config {
        direction_buffer_bytes: 8,
        control_reserve_bytes: 1024,
        process_budget: process_memory.clone(),
        session_budget: session_memory.clone(),
        ..H2Config::default()
    };
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("session");
    let destination = target_destination();
    let mut opened = session
        .open_stream(&destination, &credential())
        .await
        .expect("open");
    let baseline = session_memory.used();
    let mut one = [0u8; 1];
    assert_eq!(
        opened.read(&mut one).await.expect("prefix"),
        ReadOutcome::Data(1)
    );
    assert_eq!(one, *b"1");
    let retained_charge = session_memory
        .used()
        .checked_sub(baseline)
        .expect("stream metadata retained");
    assert!(retained_charge >= 8);
    assert_eq!(process_memory.used(), session_memory.used());
    assert_eq!(
        timeout(IO_TIMEOUT, &mut capacity_rx)
            .await
            .expect("released credit")
            .expect("signal"),
        1
    );
    let mut rest = [0u8; 7];
    assert_eq!(
        opened.read(&mut rest).await.expect("rest"),
        ReadOutcome::Data(7)
    );
    assert_eq!(rest, *b"2345678");
    assert_eq!(session_memory.used(), baseline);
    opened.cancel().expect("cancel stream");
    session.cancel();
    assert_eq!(session.close(IO_TIMEOUT).await, Err(EngineError::Cancelled));
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join");
}

#[tokio::test]
async fn spontaneous_transport_loss_preserves_already_received_bytes() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        let (request, mut respond) = connection.accept().await.expect("request").expect("accept");
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response");
        let mut send = respond
            .send_response(response, false)
            .expect("send response");
        send.send_data(bytes::Bytes::from_static(b"12345678"), false)
            .expect("reply");
        tokio::select! {
            _ = stop_rx => {}
            _ = connection.accept() => panic!("no extra request expected"),
        }
        drop((send, request, connection));
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    let destination = target_destination();
    let mut stream = session
        .open_stream(&destination, &credential())
        .await
        .expect("stream");
    let mut prefix = [0u8; 1];
    assert_eq!(
        stream.read(&mut prefix).await.expect("prefix"),
        ReadOutcome::Data(1)
    );
    assert_eq!(prefix, *b"1");
    stop_tx.send(()).expect("stop peer");
    assert_eq!(
        timeout(IO_TIMEOUT, session.wait_closed())
            .await
            .expect("driver completion"),
        Ok(())
    );
    assert_eq!(
        session.driver_error(),
        Some(EngineError::TransportUnavailable)
    );
    let mut retained = [0u8; 7];
    assert_eq!(
        stream.read(&mut retained).await.expect("retained bytes"),
        ReadOutcome::Data(7)
    );
    assert_eq!(retained, *b"2345678");
    assert!(!matches!(
        stream.read(&mut prefix).await,
        Ok(ReadOutcome::Eof)
    ));
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join");
}

#[tokio::test]
async fn expired_session_close_drops_io_before_returning() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (dropped, drop_event) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        let (request, mut respond) = connection.accept().await.expect("request").expect("accept");
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response");
        let send = respond
            .send_response(response, false)
            .expect("send response");
        let _ = connection.accept().await;
        drop((request, send));
    });
    let session = H2Session::handshake(
        PendingShutdown {
            inner: client,
            dropped: Some(dropped),
        },
        true,
    )
    .await
    .expect("session");
    let destination = target_destination();
    let _opened = session
        .open_stream(&destination, &credential())
        .await
        .expect("open");
    assert_eq!(
        session.close(Duration::ZERO).await,
        Err(EngineError::DeadlineExceeded)
    );
    drop_event.await.expect("IO already released");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join");
}

#[tokio::test]
async fn session_flow_limit_rejects_an_open_without_a_second_dial() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let server_dials = Arc::clone(&dials);
    let server = tokio::spawn(async move {
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            H2Config::default(),
            move |_| {
                server_dials.fetch_add(1, Ordering::SeqCst);
                async {
                    let (target, peer) = tokio::io::duplex(64);
                    tokio::spawn(async move {
                        let mut peer = peer;
                        let mut byte = [0u8; 1];
                        let _ = peer.read(&mut byte).await;
                    });
                    Ok::<_, EngineError>(target)
                }
            },
            std::future::pending(),
        )
        .await
    });
    let config = H2Config {
        max_concurrent_streams: 1,
        max_pending_opens: 1,
        session_flows: ResourceBudget::new(1).expect("flows"),
        session_opens: ResourceBudget::new(1).expect("opens"),
        ..H2Config::default()
    };
    let flow_budget = config.session_flows.clone();
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("session");
    let destination = target_destination();
    let opened = session
        .open_stream(&destination, &credential())
        .await
        .expect("first");
    let result = session.open_stream(&destination, &credential()).await;
    assert!(matches!(result, Err(EngineError::ResourceLimitExceeded)));
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(flow_budget.used(), 1);
    drop(opened);
    assert_eq!(flow_budget.used(), 0);
    session.close(IO_TIMEOUT).await.expect("close");
    let _ = timeout(IO_TIMEOUT, server)
        .await
        .expect("server cleanup")
        .expect("join");
}

#[tokio::test]
async fn unverified_peer_sends_no_preface() {
    let (client, mut server) = tokio::io::duplex(1024);
    let destination = target_destination();
    let error = client_roundtrip(client, &destination, &credential(), false, b"ping")
        .await
        .expect_err("unverified");
    assert_eq!(error, ariad_core::EngineError::PeerIdentityFailed);
    let mut buf = [0u8; 24];
    let n = server.read(&mut buf).await.expect("eof");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn cancelled_open_drops_a_client_with_pending_shutdown() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (dropped, drop_event) = tokio::sync::oneshot::channel();
    let opening = tokio::spawn(async move {
        let destination = target_destination();
        open_h2(
            PendingShutdown {
                inner: client,
                dropped: Some(dropped),
            },
            &destination,
            &credential(),
            true,
        )
        .await
    });
    let mut connection = timeout(IO_TIMEOUT, h2::server::handshake(server_io))
        .await
        .expect("handshake completion")
        .expect("handshake");
    let (request, respond) = timeout(IO_TIMEOUT, connection.accept())
        .await
        .expect("request completion")
        .expect("request present")
        .expect("request");
    opening.abort();
    assert!(matches!(opening.await, Err(error) if error.is_cancelled()));
    timeout(IO_TIMEOUT, drop_event)
        .await
        .expect("client released")
        .expect("drop notification");
    drop((request, respond, connection));
}

#[tokio::test]
async fn dropped_tunnel_drops_a_client_with_pending_shutdown() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (dropped, drop_event) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        let (request, mut respond) = connection
            .accept()
            .await
            .expect("request present")
            .expect("request");
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("response");
        let send = respond
            .send_response(response, false)
            .expect("send response");
        let _ = connection.accept().await;
        drop((request, send));
    });
    let destination = target_destination();
    let opened = timeout(
        IO_TIMEOUT,
        open_h2(
            PendingShutdown {
                inner: client,
                dropped: Some(dropped),
            },
            &destination,
            &credential(),
            true,
        ),
    )
    .await
    .expect("open completion")
    .expect("open");
    assert_eq!(opened.status(), http::StatusCode::OK);
    drop(opened);
    timeout(IO_TIMEOUT, drop_event)
        .await
        .expect("client released")
        .expect("drop notification");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join");
}

#[tokio::test]
async fn handler_panic_releases_server_io_before_serve_one_returns() {
    let (client_io, server_io) = tokio::io::duplex(8 * 1024);
    let (dropped, mut drop_event) = tokio::sync::oneshot::channel();
    let client = tokio::spawn(async move {
        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let driver = tokio::spawn(connection);
        let request = ariad_engine::assemble_connect(&target_destination(), &credential(), true)
            .expect("request");
        let (response, send) = client.send_request(request, false).expect("send");
        response
            .await
            .expect_err("handler panic closes the response");
        drop((send, client));
        let _ = driver.await.expect("driver join");
    });
    let result = timeout(
        IO_TIMEOUT,
        serve_one(
            PendingShutdown {
                inner: server_io,
                dropped: Some(dropped),
            },
            StaticAuthorizer::new(credential(), 7),
            false,
            |_| {
                std::future::poll_fn(
                    |_| -> std::task::Poll<Result<tokio::io::DuplexStream, EngineError>> {
                        panic!("target dial panic");
                    },
                )
            },
        ),
    )
    .await
    .expect("server completion");
    assert_eq!(result, Err(EngineError::TransportUnavailable));
    assert_eq!(drop_event.try_recv(), Ok(()));
    timeout(IO_TIMEOUT, client)
        .await
        .expect("client completion")
        .expect("client assertions");
}

#[tokio::test]
async fn failed_response_write_returns_transport_error() {
    for fail_response_writes in [false, true] {
        let (client_io, server_io) = tokio::io::duplex(8 * 1024);
        let fail_writes = Arc::new(AtomicBool::new(false));
        let server_fail_writes = Arc::clone(&fail_writes);
        let server = tokio::spawn(async move {
            let authorizer = StaticAuthorizer::new(credential(), 7);
            serve_one(
                FailingWrites {
                    inner: server_io,
                    fail_writes,
                },
                authorizer,
                false,
                move |_| async move {
                    server_fail_writes.store(fail_response_writes, Ordering::SeqCst);
                    Err::<tokio::io::DuplexStream, ariad_core::EngineError>(
                        ariad_core::EngineError::TargetConnectFailed,
                    )
                },
            )
            .await
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let driver = tokio::spawn(connection);
        let destination = target_destination();
        let request =
            ariad_engine::assemble_connect(&destination, &credential(), true).expect("request");
        let (response, _) = client.send_request(request, true).expect("send");
        let result = timeout(IO_TIMEOUT, server)
            .await
            .expect("server completion")
            .expect("server join");
        let response = timeout(IO_TIMEOUT, response)
            .await
            .expect("response completion");
        if fail_response_writes {
            assert_eq!(result, Err(ariad_core::EngineError::TransportUnavailable));
            response.expect_err("response write failed");
        } else {
            assert_final_goaway_result(result);
            assert_eq!(
                response.expect("response").status(),
                http::StatusCode::BAD_GATEWAY
            );
        }
        let _ = timeout(IO_TIMEOUT, driver)
            .await
            .expect("driver completion")
            .expect("driver join");
    }
}

#[tokio::test]
async fn public_target_carries_ping_and_pong() {
    let (client, server) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let dials_server = Arc::clone(&dials);
    let destination = target_destination();
    let server_dest = destination.clone();
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server, authorizer, false, move |got| {
            ping_pong_target(got, server_dest, Arc::clone(&dials_server))
        })
        .await
    });

    let ClientRoundtrip { status, reply } =
        client_roundtrip(client, &destination, &credential(), true, b"ping")
            .await
            .expect("roundtrip");
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reply.as_ref(), b"pong");
    server.await.expect("join").expect("serve");
    assert_eq!(dials.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn loopback_and_bad_credential_do_not_dial() {
    let destination = Destination::parse("127.0.0.1:9").expect("loop");
    let round = denied_roundtrip(destination, credential()).await;
    assert_eq!(round.status, http::StatusCode::BAD_GATEWAY);
    assert_eq!(round.dials, 0);

    let destination = target_destination();
    let round = denied_roundtrip(destination, Credential::from_bytes([0x22; 32])).await;
    assert_eq!(round.status, http::StatusCode::FORBIDDEN);
    assert_eq!(round.dials, 0);
}

#[tokio::test]
async fn domain_target_does_not_dial() {
    let destination = Destination::parse("example.com:443").expect("domain");
    let round = denied_roundtrip(destination, credential()).await;
    assert_eq!(round.status, http::StatusCode::BAD_GATEWAY);
    assert_eq!(round.dials, 0);
}

#[tokio::test]
async fn tls_handshake_then_ping_pong() {
    let TlsFixture {
        server,
        client,
        name,
    } = tls_fixture();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let connector = TlsConnector::from(Arc::new(client));
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let destination = target_destination();
    let server_dest = destination.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let dials_server = Arc::clone(&dials);

    let server = tokio::spawn(async move {
        let tls = acceptor.accept(server_io).await.expect("accept");
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(tls, authorizer, false, move |got| {
            ping_pong_target(got, server_dest, Arc::clone(&dials_server))
        })
        .await
    });

    let tls = connector.connect(name, client_io).await.expect("connect");
    let ClientRoundtrip { status, reply } =
        client_roundtrip(tls, &destination, &credential(), true, b"ping")
            .await
            .expect("roundtrip");
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reply.as_ref(), b"pong");
    server.await.expect("join").expect("serve");
    assert_eq!(dials.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn tcp_listener_then_ping_pong() {
    let TlsFixture {
        server,
        client,
        name,
    } = tls_fixture();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let connector = TlsConnector::from(Arc::new(client));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let destination = target_destination();
    let server_dest = destination.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let dials_server = Arc::clone(&dials);

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls");
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(tls, authorizer, false, move |got| {
            ping_pong_target(got, server_dest, Arc::clone(&dials_server))
        })
        .await
    });

    let tcp = TcpStream::connect(address).await.expect("connect");
    let tls = connector.connect(name, tcp).await.expect("tls");
    let ClientRoundtrip { status, reply } =
        client_roundtrip(tls, &destination, &credential(), true, b"ping")
            .await
            .expect("roundtrip");
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reply.as_ref(), b"pong");
    server.await.expect("join").expect("serve");
    assert_eq!(dials.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn half_close_still_reads_the_reply() {
    let run = duplex_server();
    let client = run.client;
    let server = run.server;
    let dials = run.dials;
    let shutdown_polled = run.shutdown_polled;
    let destination = target_destination();
    let mut opened = open_h2(client, &destination, &credential(), true)
        .await
        .expect("open");
    assert_eq!(opened.status(), http::StatusCode::OK);
    assert_eq!(opened.write(b"ping").await.expect("write"), 4);
    opened.end_write().await.expect("end");
    let mut pong = [0u8; 4];
    assert_eq!(
        opened.read(&mut pong).await.expect("read"),
        ReadOutcome::Data(4)
    );
    assert_eq!(&pong, b"pong");
    let mut tail = [0u8; 1];
    assert_eq!(opened.read(&mut tail).await.expect("eof"), ReadOutcome::Eof);
    server.await.expect("join").expect("serve");
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert!(shutdown_polled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn target_reply_progresses_while_request_write_is_blocked() {
    let (client, server_io) = tokio::io::duplex(128);
    let (target, peer) = tokio::io::duplex(64);
    let destination = target_destination();
    let target_task = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(peer);
        let mut first = [0u8; 1];
        read.read_exact(&mut first).await.expect("first byte");
        write.write_all(&[b'r'; 16 * 1024]).await.expect("reply");
        let mut rest = Vec::new();
        read.read_to_end(&mut rest).await.expect("request");
        assert_eq!(first, [b'q']);
        assert_eq!(rest, vec![b'q'; 4095]);
        write.shutdown().await.expect("shutdown");
    });
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_| async move {
            Ok::<_, ariad_core::EngineError>(target)
        })
        .await
    });
    let round = timeout(
        IO_TIMEOUT,
        client_roundtrip(client, &destination, &credential(), true, &[b'q'; 4096]),
    )
    .await
    .expect("bidirectional progress")
    .expect("roundtrip");
    assert_eq!(round.status, http::StatusCode::OK);
    assert_eq!(round.reply, vec![b'r'; 16 * 1024]);
    timeout(IO_TIMEOUT, target_task)
        .await
        .expect("target completion")
        .expect("target join");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join")
        .expect("serve");
}

#[tokio::test]
async fn reset_after_half_close_aborts_an_idle_target() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (target, mut peer) = tokio::io::duplex(64);
    let destination = target_destination();
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_| async move {
            Ok::<_, ariad_core::EngineError>(target)
        })
        .await
    });
    let mut opened = timeout(
        IO_TIMEOUT,
        open_h2(client, &destination, &credential(), true),
    )
    .await
    .expect("open completion")
    .expect("open");
    opened.end_write().await.expect("end");
    let mut buf = [0u8; 1];
    assert_eq!(
        timeout(IO_TIMEOUT, peer.read(&mut buf))
            .await
            .expect("target half-close")
            .expect("target eof"),
        0
    );
    opened.reset().expect("reset");
    let error = timeout(IO_TIMEOUT, server)
        .await
        .expect("reset completion")
        .expect("join")
        .expect_err("reset");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
    peer.write_all(b"reply").await.expect_err("target dropped");
}

#[tokio::test]
async fn reset_interrupts_a_blocked_target_write() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (target, mut peer) = tokio::io::duplex(64);
    let shutdown_polled = Arc::new(AtomicBool::new(false));
    let server_shutdown_polled = Arc::clone(&shutdown_polled);
    let destination = target_destination();
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_| async move {
            Ok::<_, ariad_core::EngineError>(ShutdownProbe {
                inner: target,
                shutdown_polled: server_shutdown_polled,
            })
        })
        .await
    });
    let mut opened = timeout(
        IO_TIMEOUT,
        open_h2(client, &destination, &credential(), true),
    )
    .await
    .expect("open completion")
    .expect("open");
    assert_eq!(opened.write(&[b'q'; 4096]).await.expect("write"), 4096);
    let mut prefix = [0u8; 64];
    timeout(IO_TIMEOUT, peer.read_exact(&mut prefix))
        .await
        .expect("target write started")
        .expect("prefix");
    assert_eq!(prefix, [b'q'; 64]);
    opened.reset().expect("reset");
    let error = timeout(IO_TIMEOUT, server)
        .await
        .expect("reset completion")
        .expect("join")
        .expect_err("reset");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
    assert!(!shutdown_polled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn reset_cancels_a_pending_target_dial() {
    let (client_io, server_io) = tokio::io::duplex(8 * 1024);
    let (dial_started, started) = tokio::sync::oneshot::channel();
    let (complete_dial, pending_dial) = tokio::sync::oneshot::channel::<tokio::io::DuplexStream>();
    let destination = target_destination();
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_| async move {
            dial_started.send(()).expect("dial started");
            pending_dial
                .await
                .map_err(|_| ariad_core::EngineError::TargetConnectFailed)
        })
        .await
    });
    let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
    let driver = tokio::spawn(connection);
    let request =
        ariad_engine::assemble_connect(&destination, &credential(), true).expect("request");
    let (response, mut send) = client.send_request(request, false).expect("send");
    timeout(IO_TIMEOUT, started)
        .await
        .expect("dial progress")
        .expect("dial notification");
    send.send_reset(h2::Reason::CANCEL);
    let error = timeout(IO_TIMEOUT, server)
        .await
        .expect("reset completion")
        .expect("join")
        .expect_err("reset");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
    assert!(complete_dial.is_closed());
    timeout(IO_TIMEOUT, response)
        .await
        .expect("response completion")
        .expect_err("reset response");
    timeout(IO_TIMEOUT, driver)
        .await
        .expect("driver completion")
        .expect("driver join")
        .expect("connection");
    drop(client);
}

#[tokio::test]
async fn client_reset_aborts_tcp_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let destination = target_destination();
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_got| async move {
            TcpStream::connect(address)
                .await
                .map_err(|_| ariad_core::EngineError::TargetConnectFailed)
        })
        .await
    });
    let accept = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
    let mut opened = open_h2(client, &destination, &credential(), true)
        .await
        .expect("open");
    let mut peer = accept.await.expect("join");
    opened.reset().expect("reset");
    let mut buf = [0u8; 8];
    peer.read(&mut buf).await.expect_err("rst");
    let error = server.await.expect("join").expect_err("reset");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
}

#[tokio::test]
async fn reset_is_not_a_clean_shutdown() {
    let run = duplex_server();
    let client = run.client;
    let server = run.server;
    let dials = run.dials;
    let shutdown_polled = run.shutdown_polled;
    let destination = target_destination();
    let mut opened = open_h2(client, &destination, &credential(), true)
        .await
        .expect("open");
    assert_eq!(opened.status(), http::StatusCode::OK);
    opened.reset().expect("reset");
    let mut buf = [0u8; 1];
    assert_eq!(
        opened.read(&mut buf).await.expect("read"),
        ReadOutcome::Reset
    );
    let error = server.await.expect("join").expect_err("reset");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert!(!shutdown_polled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancel_does_not_replay_on_the_next_connect() {
    let first = capture_server(true).await;
    let mut opened = open_h2(first.client, &first.destination, &credential(), true)
        .await
        .expect("open");
    assert_eq!(opened.write(b"ping").await.expect("write"), 4);
    opened.cancel().expect("cancel");
    let mut buf = [0u8; 4];
    assert_eq!(
        opened.read(&mut buf).await.expect("read"),
        ReadOutcome::Cancelled
    );
    assert_ne!(buf, *b"ping");
    let error = first.server.await.expect("join").expect_err("cancel");
    assert_eq!(error, ariad_core::EngineError::RemoteReset);
    assert!(!first.shutdown_polled.load(Ordering::SeqCst));

    let second = capture_server(true).await;
    let mut opened = open_h2(second.client, &second.destination, &credential(), true)
        .await
        .expect("open");
    opened.end_write().await.expect("end");
    let mut tail = [0u8; 4];
    assert_eq!(opened.read(&mut tail).await.expect("eof"), ReadOutcome::Eof);
    second.server.await.expect("join").expect("serve");
    let received_prefix = second.received_prefix.lock().expect("seen");
    assert!(received_prefix.is_empty());
    assert_eq!(second.dials.load(Ordering::SeqCst), 1);
}

struct CaptureRun {
    client: tokio::io::DuplexStream,
    server: tokio::task::JoinHandle<Result<(), ariad_core::EngineError>>,
    destination: Destination,
    dials: Arc<AtomicUsize>,
    shutdown_polled: Arc<AtomicBool>,
    received_prefix: Arc<std::sync::Mutex<Vec<u8>>>,
}

async fn capture_server(record_prefix: bool) -> CaptureRun {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let destination = target_destination();
    let server_dest = destination.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let shutdown_polled = Arc::new(AtomicBool::new(false));
    let received_prefix = Arc::new(std::sync::Mutex::new(Vec::new()));
    let dials_server = Arc::clone(&dials);
    let server_shutdown_polled = Arc::clone(&shutdown_polled);
    let server_received_prefix = Arc::clone(&received_prefix);
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |got| {
            let dials_server = Arc::clone(&dials_server);
            let server_shutdown_polled = Arc::clone(&server_shutdown_polled);
            let server_received_prefix = Arc::clone(&server_received_prefix);
            async move {
                assert_eq!(got, server_dest);
                dials_server.fetch_add(1, Ordering::SeqCst);
                let (local, remote) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(remote);
                    let mut buf = [0u8; 32];
                    let n = read.read(&mut buf).await.unwrap_or(0);
                    if record_prefix {
                        server_received_prefix
                            .lock()
                            .expect("seen")
                            .extend_from_slice(&buf[..n]);
                    }
                    let _ = write.shutdown().await;
                });
                Ok::<_, ariad_core::EngineError>(ShutdownProbe {
                    inner: local,
                    shutdown_polled: server_shutdown_polled,
                })
            }
        })
        .await
    });
    CaptureRun {
        client,
        server,
        destination,
        dials,
        shutdown_polled,
        received_prefix,
    }
}

struct DuplexRun {
    client: tokio::io::DuplexStream,
    server: tokio::task::JoinHandle<Result<(), ariad_core::EngineError>>,
    dials: Arc<AtomicUsize>,
    shutdown_polled: Arc<AtomicBool>,
}

fn duplex_server() -> DuplexRun {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let destination = target_destination();
    let dials = Arc::new(AtomicUsize::new(0));
    let shutdown_polled = Arc::new(AtomicBool::new(false));
    let dials_server = Arc::clone(&dials);
    let server_shutdown_polled = Arc::clone(&shutdown_polled);
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |got| {
            let dials_server = Arc::clone(&dials_server);
            let server_shutdown_polled = Arc::clone(&server_shutdown_polled);
            async move {
                assert_eq!(got, destination);
                dials_server.fetch_add(1, Ordering::SeqCst);
                let (local, remote) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(remote);
                    let mut buf = [0u8; 4];
                    if read.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                        let _ = write.write_all(b"pong").await;
                    }
                    let _ = write.shutdown().await;
                    let mut rest = [0u8; 8];
                    let _ = read.read(&mut rest).await;
                });
                Ok::<_, ariad_core::EngineError>(ShutdownProbe {
                    inner: local,
                    shutdown_polled: server_shutdown_polled,
                })
            }
        })
        .await
    });
    DuplexRun {
        client,
        server,
        dials,
        shutdown_polled,
    }
}

struct ShutdownProbe {
    inner: tokio::io::DuplexStream,
    shutdown_polled: Arc<AtomicBool>,
}

struct PendingShutdown {
    inner: tokio::io::DuplexStream,
    dropped: Option<tokio::sync::oneshot::Sender<()>>,
}

struct FailingWrites {
    inner: tokio::io::DuplexStream,
    fail_writes: Arc<AtomicBool>,
}

impl tokio::io::AsyncRead for FailingWrites {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for FailingWrites {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Err(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl tokio::io::AsyncRead for PendingShutdown {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PendingShutdown {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl Drop for PendingShutdown {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl tokio::io::AsyncRead for ShutdownProbe {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ShutdownProbe {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.shutdown_polled.store(true, Ordering::SeqCst);
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn get_root_ignores_forwarded_headers_and_does_not_dial() {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let dials_server = Arc::clone(&dials);
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server_io, authorizer, false, move |_| {
            let dials_server = Arc::clone(&dials_server);
            async move {
                dials_server.fetch_add(1, Ordering::SeqCst);
                Err::<tokio::io::DuplexStream, ariad_core::EngineError>(
                    ariad_core::EngineError::EgressDenied,
                )
            }
        })
        .await
    });
    let (mut client, connection) = h2::client::handshake(client).await.expect("handshake");
    let driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method("GET")
        .uri("/")
        .header("x-forwarded-for", "1.1.1.1")
        .header("host", "evil.example")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send");
    let mut response = response.await.expect("response");
    assert_eq!(response.status().as_u16(), 200);
    let body = response.body_mut();
    let chunk = body.data().await.expect("body").expect("bytes");
    assert_eq!(&chunk[..], b"Service available.\n");
    let result = timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("join");
    assert_final_goaway_result(result);
    timeout(IO_TIMEOUT, driver)
        .await
        .expect("driver completion")
        .expect("driver join")
        .expect("connection");
    drop(client);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

async fn ping_pong_target(
    destination: Destination,
    expected: Destination,
    dials: Arc<AtomicUsize>,
) -> Result<tokio::io::DuplexStream, EngineError> {
    assert_eq!(destination, expected);
    dials.fetch_add(1, Ordering::SeqCst);
    let (local, remote) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(remote);
        let mut buf = [0u8; 4];
        read.read_exact(&mut buf).await.expect("ping");
        assert_eq!(&buf, b"ping");
        write.write_all(b"pong").await.expect("pong");
        write.shutdown().await.expect("shutdown");
    });
    Ok(local)
}

fn assert_final_goaway_result(result: Result<(), EngineError>) {
    // Peer completion can race with the server's final GOAWAY write.
    assert!(
        matches!(result, Ok(()) | Err(EngineError::TransportUnavailable)),
        "{result:?}"
    );
}

struct DeniedRoundtrip {
    status: http::StatusCode,
    dials: usize,
}

async fn denied_roundtrip(destination: Destination, secret: Credential) -> DeniedRoundtrip {
    let (client, server) = tokio::io::duplex(8 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let dials_server = Arc::clone(&dials);
    let server = tokio::spawn(async move {
        let authorizer = StaticAuthorizer::new(credential(), 7);
        serve_one(server, authorizer, true, move |_got| {
            let dials_server = Arc::clone(&dials_server);
            async move {
                dials_server.fetch_add(1, Ordering::SeqCst);
                let (local, _remote) = tokio::io::duplex(64);
                Ok::<_, ariad_core::EngineError>(local)
            }
        })
        .await
    });
    let ClientRoundtrip { status, reply } =
        client_roundtrip(client, &destination, &secret, true, b"ping")
            .await
            .expect("roundtrip");
    assert!(reply.is_empty());
    let result = server.await.expect("join");
    assert_final_goaway_result(result);
    DeniedRoundtrip {
        status,
        dials: dials.load(Ordering::SeqCst),
    }
}

struct TlsFixture {
    server: ServerConfig,
    client: rustls::ClientConfig,
    name: ServerName<'static>,
}

fn tls_fixture() -> TlsFixture {
    let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert = CertificateDer::from(signed.cert);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der()));
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("server config");
    server.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let name = ServerName::try_from("localhost").expect("name");
    TlsFixture {
        server,
        client,
        name,
    }
}

#[tokio::test]
async fn h2_association_checks_payload_limits_for_every_zero_context_width() {
    const MAX_PAYLOAD: usize = 64;
    for context_width in [1, 2, 4, 8] {
        for payload_len in [MAX_PAYLOAD, MAX_PAYLOAD + 1] {
            for frame_bytes in [1, usize::MAX] {
                let payload: Vec<u8> = (0..payload_len).map(|n| n as u8).collect();
                let mut wire = vec![0];
                wire.extend_from_slice(
                    ariad_core::VarInt::encode((context_width + payload_len) as u64)
                        .expect("capsule length")
                        .as_slice(),
                );
                let mut context = vec![0; context_width];
                context[0] = match context_width {
                    1 => 0,
                    2 => 0x40,
                    4 => 0x80,
                    8 => 0xc0,
                    _ => unreachable!(),
                };
                wire.extend_from_slice(&context);
                wire.extend_from_slice(&payload);
                let (client, server_io) = tokio::io::duplex(8 * 1024);
                let server = tokio::spawn(async move {
                    let mut builder = h2::server::Builder::new();
                    builder.enable_connect_protocol();
                    let mut connection = builder
                        .handshake::<_, bytes::Bytes>(server_io)
                        .await
                        .expect("handshake");
                    let (_request, mut respond) =
                        connection.accept().await.expect("request").expect("accept");
                    let mut response = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header(ariad_engine::CAPSULE_PROTOCOL, "?1")
                        .header(ariad_engine::MAX_DATAGRAM_PAYLOAD, MAX_PAYLOAD.to_string())
                        .body(())
                        .expect("response");
                    ariad_engine::attach_h2_versions(response.headers_mut()).expect("versions");
                    let mut send = respond
                        .send_response(response, false)
                        .expect("response send");
                    for chunk in wire.chunks(frame_bytes) {
                        send.send_data(bytes::Bytes::copy_from_slice(chunk), false)
                            .expect("capsule fragment");
                    }
                    send.send_data(bytes::Bytes::new(), true)
                        .expect("response end");
                    if let Some(incoming) = connection.accept().await {
                        incoming.expect("connection close");
                        panic!("one association expected");
                    }
                });
                let session = H2Session::handshake(client, true).await.expect("session");
                let mut association = ariad_engine::DatagramAssociation::open_h2(
                    &session,
                    "proxy.example:443",
                    &target_destination(),
                    &credential(),
                    ariad_engine::DatagramOptions::from_h2_config(session.config(), 7, false),
                    ariad_engine::Deadline::after(IO_TIMEOUT).expect("deadline"),
                )
                .await
                .expect("association");
                assert_eq!(association.max_payload(), MAX_PAYLOAD);
                let received = association
                    .recv(ariad_engine::Deadline::after(IO_TIMEOUT).expect("deadline"))
                    .await;
                if payload_len == MAX_PAYLOAD {
                    assert_eq!(received.expect("maximum payload").as_bytes(), payload);
                } else {
                    assert_eq!(
                        received.expect_err("oversized payload"),
                        EngineError::MessageTooLarge,
                        "context width {context_width}, frame bytes {frame_bytes}"
                    );
                }
                drop(association);
                session.close(IO_TIMEOUT).await.expect("session close");
                timeout(IO_TIMEOUT, server)
                    .await
                    .expect("server completion")
                    .expect("server join");
            }
        }
    }
}

struct CapacityWake {
    notified: tokio::sync::Notify,
}

impl std::task::Wake for CapacityWake {
    fn wake(self: Arc<Self>) {
        self.notified.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notified.notify_one();
    }
}

#[tokio::test]
async fn dropped_direct_write_returns_connection_credit_with_its_stream_retained() {
    use std::future::Future;

    const WINDOW: usize = 65_535;
    for drop_after_credit_assignment in [false, true] {
        let (client, server_io) = tokio::io::duplex(8 * 1024);
        let (filled, window_filled) = tokio::sync::oneshot::channel();
        let (release, release_window) = tokio::sync::oneshot::channel();
        let (received, second_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(WINDOW as u32);
            builder.initial_connection_window_size(WINDOW as u32);
            let mut connection = builder
                .handshake::<_, bytes::Bytes>(server_io)
                .await
                .expect("handshake");
            let (first, mut respond) = connection
                .accept()
                .await
                .expect("first request")
                .expect("accept");
            let mut first_send = respond
                .send_response(http::Response::new(()), false)
                .expect("first response");
            let (second, mut respond) = connection
                .accept()
                .await
                .expect("second request")
                .expect("accept");
            let mut second_send = respond
                .send_response(http::Response::new(()), false)
                .expect("second response");
            let exchange = async move {
                let mut first = first.into_body();
                let mut total = 0;
                while total < WINDOW {
                    let chunk = first
                        .data()
                        .await
                        .expect("first data")
                        .expect("first bytes");
                    assert!(chunk.iter().all(|byte| *byte == b'a'));
                    total += chunk.len();
                }
                assert_eq!(total, WINDOW);
                filled.send(()).expect("filled signal");
                release_window.await.expect("release signal");
                first
                    .flow_control()
                    .release_capacity(WINDOW)
                    .expect("return connection credit");
                let mut second = second.into_body();
                let mut total = 0;
                while total < WINDOW {
                    let chunk = second
                        .data()
                        .await
                        .expect("second data")
                        .expect("second bytes");
                    assert!(chunk.iter().all(|byte| *byte == b'b'));
                    total += chunk.len();
                }
                assert_eq!(total, WINDOW);
                received.send(()).expect("second receipt");
                while let Some(chunk) = first.data().await {
                    assert!(
                        chunk.expect("first request FIN").is_empty(),
                        "dropped write did not queue extra data"
                    );
                }
                while let Some(chunk) = second.data().await {
                    assert!(chunk.expect("second request FIN").is_empty());
                }
                first_send
                    .send_data(bytes::Bytes::new(), true)
                    .expect("first response FIN");
                second_send
                    .send_data(bytes::Bytes::new(), true)
                    .expect("second response FIN");
            };
            tokio::select! {
                () = exchange => {}
                _ = connection.accept() => panic!("no third request expected"),
            }
            if let Some(incoming) = connection.accept().await {
                incoming.expect("connection close");
                panic!("no extra request expected");
            }
        });
        let config = H2Config {
            direction_buffer_bytes: 16 * 1024,
            ..H2Config::default()
        };
        let session = H2Session::handshake_with_config(client, true, config)
            .await
            .expect("session");
        let destination = target_destination();
        let mut first = session
            .open_stream(&destination, &credential())
            .await
            .expect("first stream");
        let mut second = session
            .open_stream(&destination, &credential())
            .await
            .expect("second stream");
        let payload = vec![b'a'; WINDOW];
        let mut offset = 0;
        while offset < payload.len() {
            offset += first
                .write(&payload[offset..])
                .await
                .expect("fill connection window");
        }
        timeout(IO_TIMEOUT, window_filled)
            .await
            .expect("window depletion")
            .expect("filled");
        let wake = Arc::new(CapacityWake {
            notified: tokio::sync::Notify::new(),
        });
        let waker = std::task::Waker::from(Arc::clone(&wake));
        let mut pending = Box::pin(first.write(&payload[..16 * 1024]));
        assert!(
            pending
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        if drop_after_credit_assignment {
            release.send(()).expect("release window");
            timeout(IO_TIMEOUT, wake.notified.notified())
                .await
                .expect("credit assigned before repoll");
            drop(pending);
        } else {
            drop(pending);
            release.send(()).expect("release window");
        }
        // A short write can pass while the first stream still holds part of the credit.
        let payload = vec![b'b'; WINDOW];
        timeout(IO_TIMEOUT, async {
            let mut offset = 0;
            while offset < payload.len() {
                offset += second
                    .write(&payload[offset..])
                    .await
                    .expect("second write");
            }
            second_received
                .await
                .expect("entire released window reached the second stream");
        })
        .await
        .expect("second stream progresses without touching the first stream");
        first
            .end_write()
            .await
            .expect("retained first stream remains open");
        second.end_write().await.expect("second request FIN");
        let mut sentinel = [0x5a];
        assert_eq!(
            first.read(&mut sentinel).await.expect("first response EOF"),
            ReadOutcome::Eof
        );
        assert_eq!(
            second
                .read(&mut sentinel)
                .await
                .expect("second response EOF"),
            ReadOutcome::Eof
        );
        assert_eq!(sentinel, [0x5a]);
        drop((first, second));
        session.close(IO_TIMEOUT).await.expect("session close");
        timeout(IO_TIMEOUT, server)
            .await
            .expect("server completion")
            .expect("server join");
    }
}

async fn request_site(client: &mut h2::client::SendRequest<bytes::Bytes>) -> Result<(), h2::Error> {
    std::future::poll_fn(|cx| client.poll_ready(cx)).await?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .body(())
        .expect("GET request");
    let (response, _) = client.send_request(request, true)?;
    let mut response = response.await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(chunk) = response.body_mut().data().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
        assert!(body.len() <= b"Service available.\n".len());
        response
            .body_mut()
            .flow_control()
            .release_capacity(chunk.len())?;
    }
    assert_eq!(body, b"Service available.\n");
    Ok(())
}

#[tokio::test]
async fn unauthenticated_site_requests_release_scoped_connection_admission() {
    for periodic_gets in [false, true] {
        let admission = ResourceBudget::new(2).expect("connection admission");
        let first_slot = admission.try_acquire().expect("first connection slot");
        let second_slot = admission.try_acquire().expect("second connection slot");
        assert_eq!(
            admission.try_acquire().expect_err("pool full"),
            EngineError::ResourceLimitExceeded
        );
        let dials = Arc::new(AtomicUsize::new(0));
        let mut servers = Vec::new();
        let mut clients = Vec::new();
        let mut drivers = Vec::new();
        let mut requesters = Vec::new();
        for slot in [first_slot, second_slot] {
            let (client_io, server_io) = tokio::io::duplex(8 * 1024);
            let server_dials = Arc::clone(&dials);
            servers.push(tokio::spawn(async move {
                let _connection_slot = slot;
                serve_h2(
                    server_io,
                    Arc::new(StaticAuthorizer::new(credential(), 7)),
                    false,
                    pre_auth_config(),
                    move |_| {
                        server_dials.fetch_add(1, Ordering::SeqCst);
                        async {
                            Err::<tokio::io::DuplexStream, EngineError>(EngineError::EgressDenied)
                        }
                    },
                    std::future::pending(),
                )
                .await
            }));
            let (mut client, connection) =
                h2::client::handshake(client_io).await.expect("handshake");
            drivers.push(tokio::spawn(connection));
            request_site(&mut client)
                .await
                .expect("initial site response");
            if periodic_gets {
                let (repeated, repeat_observed) = tokio::sync::oneshot::channel();
                requesters.push(tokio::spawn(async move {
                    request_site(&mut client)
                        .await
                        .expect("repeated site response");
                    repeated.send(()).expect("repeat observation");
                    loop {
                        tokio::time::sleep(PREAUTH_TIMEOUT / 5).await;
                        if let Err(error) = request_site(&mut client).await {
                            return error;
                        }
                    }
                }));
                timeout(IO_TIMEOUT, repeat_observed)
                    .await
                    .expect("repeat completion")
                    .expect("repeat signal");
            } else {
                clients.push(client);
            }
        }
        for server in servers {
            assert_eq!(
                timeout(IO_TIMEOUT, server)
                    .await
                    .expect("fixed pre-auth deadline")
                    .expect("server join"),
                Err(EngineError::DeadlineExceeded),
                "periodic GETs: {periodic_gets}"
            );
        }
        assert_eq!(dials.load(Ordering::SeqCst), 0);
        assert_eq!(admission.used(), 0);
        let replacement = admission
            .try_acquire()
            .expect("replacement connection admitted");
        assert_eq!(admission.used(), 1);
        exchange_after_pre_auth_deadline(replacement).await;
        assert_eq!(admission.used(), 0);
        for requester in requesters {
            let error = timeout(IO_TIMEOUT, requester)
                .await
                .expect("requester completion")
                .expect("requester assertions");
            assert!(
                error.is_io() || error.is_go_away() || error.is_reset(),
                "{error}"
            );
        }
        for driver in drivers {
            let result = timeout(IO_TIMEOUT, driver)
                .await
                .expect("driver completion")
                .expect("driver join");
            if let Err(error) = result {
                assert!(
                    error.is_io()
                        || (error.is_go_away() && error.reason() == Some(h2::Reason::CANCEL)),
                    "{error}"
                );
            }
        }
        drop(clients);
    }
}

#[tokio::test]
async fn authenticated_tunnel_remains_usable_past_the_pre_auth_deadline() {
    let admission = ResourceBudget::new(1).expect("connection admission");
    exchange_after_pre_auth_deadline(admission.try_acquire().expect("connection slot")).await;
    assert_eq!(admission.used(), 0);
}

async fn exchange_after_pre_auth_deadline(slot: ariad_core::ResourceReservation) {
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (target, mut peer) = tokio::io::duplex(64);
    let target = Arc::new(std::sync::Mutex::new(Some(target)));
    let target_task = tokio::spawn(async move {
        let mut payload = [0; 4];
        peer.read_exact(&mut payload).await.expect("late request");
        assert_eq!(payload, *b"late");
        peer.write_all(&payload).await.expect("late reply");
        assert_eq!(peer.read(&mut payload).await.expect("request FIN"), 0);
        peer.shutdown().await.expect("response FIN");
    });
    let server = tokio::spawn(async move {
        let _connection_slot = slot;
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            pre_auth_config(),
            move |_| {
                let target = target
                    .lock()
                    .expect("target lock")
                    .take()
                    .expect("one dial");
                async move { Ok::<_, EngineError>(target) }
            },
            std::future::pending(),
        )
        .await
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    let mut stream = session
        .open_stream(&target_destination(), &credential())
        .await
        .expect("authenticated stream");
    tokio::time::sleep(PREAUTH_TIMEOUT * 2).await;
    assert_eq!(stream.write(b"late").await.expect("late write"), 4);
    stream.end_write().await.expect("request FIN");
    let mut reply = [0; 4];
    assert_eq!(
        stream.read(&mut reply).await.expect("late reply"),
        ReadOutcome::Data(4)
    );
    assert_eq!(reply, *b"late");
    assert_eq!(
        stream.read(&mut reply).await.expect("response FIN"),
        ReadOutcome::Eof
    );
    session.close(IO_TIMEOUT).await.expect("session close");
    timeout(IO_TIMEOUT, target_task)
        .await
        .expect("target completion")
        .expect("target assertions");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join")
        .expect("serve");
}

#[tokio::test]
async fn public_h2_halves_transfer_independent_payloads_before_request_fin() {
    use std::future::Future;

    let upload: Vec<u8> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let download: Vec<u8> = (0..384 * 1024)
        .map(|n| ((n * 7 + 11) % 251) as u8)
        .collect();
    let (client, server_io) = tokio::io::duplex(128);
    let (target, peer) = tokio::io::duplex(64);
    let expected_upload = upload.clone();
    let response_payload = download.clone();
    let target_task = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(peer);
        let (request_started, request_start) = tokio::sync::oneshot::channel();
        let receive = async {
            let mut prefix = [0];
            read.read_exact(&mut prefix).await.expect("request prefix");
            assert_eq!(prefix[0], expected_upload[0]);
            request_started.send(()).expect("request start");
            let mut received = vec![prefix[0]];
            let mut buffer = [0; 1024];
            loop {
                let n = read.read(&mut buffer).await.expect("request data");
                if n == 0 {
                    break;
                }
                assert!(received.len() + n <= expected_upload.len());
                received.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(received, expected_upload);
        };
        let respond = async {
            request_start.await.expect("request start signal");
            write
                .write_all(&response_payload)
                .await
                .expect("independent response");
            write.shutdown().await.expect("response FIN");
        };
        tokio::join!(receive, respond);
    });
    let target = Arc::new(std::sync::Mutex::new(Some(target)));
    let server = tokio::spawn(async move {
        serve_h2(
            server_io,
            Arc::new(StaticAuthorizer::new(credential(), 7)),
            false,
            H2Config {
                direction_buffer_bytes: 1024,
                initial_connection_window: 65_535,
                ..H2Config::default()
            },
            move |_| {
                let target = target
                    .lock()
                    .expect("target lock")
                    .take()
                    .expect("one target");
                async move { Ok::<_, EngineError>(target) }
            },
            std::future::pending(),
        )
        .await
    });
    let flows = ResourceBudget::new(1).expect("flow budget");
    let opens = ResourceBudget::new(1).expect("open budget");
    let config = H2Config {
        direction_buffer_bytes: 1024,
        initial_connection_window: 65_535,
        max_concurrent_streams: 1,
        max_pending_opens: 1,
        process_flows: flows.clone(),
        session_flows: ResourceBudget::new(1).expect("session flow budget"),
        process_opens: opens.clone(),
        session_opens: ResourceBudget::new(1).expect("session open budget"),
        ..H2Config::default()
    };
    let session = H2Session::handshake_with_config(client, true, config)
        .await
        .expect("session");
    let opened = session
        .open_stream(&target_destination(), &credential())
        .await
        .expect("stream");
    assert_eq!(flows.used(), 1);
    assert_eq!(opens.used(), 0);
    let (mut reader, mut writer) = opened.into_split();
    let mut first_reply = [0];
    let mut pending_read = Box::pin(reader.read(&mut first_reply));
    std::future::poll_fn(|cx| {
        assert!(pending_read.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        writer
            .write(&upload[..1])
            .await
            .expect("write while read is pending"),
        1
    );
    assert_eq!(
        pending_read.await.expect("first response byte"),
        ReadOutcome::Data(1)
    );
    assert_eq!(first_reply[0], download[0]);
    let (response_finished, response_fin) = tokio::sync::oneshot::channel();
    let retained_flows = flows.clone();
    let write_request = tokio::spawn(async move {
        timeout(IO_TIMEOUT, async move {
            let mut offset = 1;
            while offset < upload.len() {
                let n = writer.write(&upload[offset..]).await.expect("upload");
                assert!(n > 0 && n <= upload.len() - offset);
                offset += n;
            }
            response_fin
                .await
                .expect("response ended before request FIN");
            assert_eq!(
                retained_flows.used(),
                1,
                "read EOF retains the open write direction"
            );
            writer.end_write().await.expect("request FIN");
            writer
        })
        .await
        .expect("independent writer progress")
    });
    let read_response = tokio::spawn(async move {
        timeout(IO_TIMEOUT, async move {
            let mut received = vec![first_reply[0]];
            let mut buffer = [0; 1024];
            loop {
                match reader.read(&mut buffer).await.expect("download") {
                    ReadOutcome::Data(n) => {
                        assert!(n > 0 && received.len() + n <= download.len());
                        received.extend_from_slice(&buffer[..n]);
                    }
                    ReadOutcome::Eof => break,
                    outcome => panic!("unexpected response outcome: {outcome:?}"),
                }
            }
            assert_eq!(received, download);
            response_finished.send(()).expect("response FIN signal");
            reader
        })
        .await
        .expect("independent reader progress")
    });
    let (written, read) = tokio::join!(write_request, read_response);
    let writer = written.expect("writer task assertions");
    let mut reader = read.expect("reader task assertions");
    drop(writer);
    let mut sentinel = [0x5a];
    assert_eq!(
        reader
            .read(&mut sentinel)
            .await
            .expect("EOF after writer drop"),
        ReadOutcome::Eof
    );
    assert_eq!(sentinel, [0x5a]);
    assert_eq!(flows.used(), 0);
    assert_eq!(opens.used(), 0);
    drop(reader);
    session.close(IO_TIMEOUT).await.expect("session close");
    timeout(IO_TIMEOUT, target_task)
        .await
        .expect("target completion")
        .expect("target assertions");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server join")
        .expect("serve");
}

#[tokio::test]
async fn dropping_reader_returns_connection_credit_while_its_writer_survives() {
    const WINDOW: usize = 65_535;
    let (client, server_io) = tokio::io::duplex(8 * 1024);
    let (filled, window_filled) = tokio::sync::oneshot::channel();
    let (prefix_returned, prefix_credit) = tokio::sync::oneshot::channel();
    let (finished, requests_finished) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        let (first, mut respond) = connection
            .accept()
            .await
            .expect("first request")
            .expect("first accept");
        let mut first_send = respond
            .send_response(http::Response::new(()), false)
            .expect("first response");
        let (second, mut respond) = connection
            .accept()
            .await
            .expect("second request")
            .expect("second accept");
        let mut second_send = respond
            .send_response(http::Response::new(()), false)
            .expect("second response");
        first_send
            .send_data(bytes::Bytes::from(vec![b'a'; WINDOW]), false)
            .expect("fill receive window");
        second_send.reserve_capacity(WINDOW);
        assert_eq!(second_send.capacity(), 0);
        filled.send(()).expect("window filled signal");
        let exchange = async move {
            let mut capacity = std::future::poll_fn(|cx| second_send.poll_capacity(cx))
                .await
                .expect("prefix capacity")
                .expect("prefix credit");
            assert_eq!(capacity, 1);
            prefix_returned.send(()).expect("prefix credit signal");
            // The sibling needs the whole window. Queued h2 bytes exclude the retained tail.
            while capacity < WINDOW {
                let assigned = std::future::poll_fn(|cx| second_send.poll_capacity(cx))
                    .await
                    .expect("tail capacity")
                    .expect("tail credit");
                assert!(assigned > capacity && assigned <= WINDOW);
                capacity = assigned;
            }
            second_send
                .send_data(bytes::Bytes::from(vec![b'b'; WINDOW]), true)
                .expect("second response and FIN");
            first_send
                .send_data(bytes::Bytes::new(), true)
                .expect("first response FIN");
            let mut first = first.into_body();
            let mut received = Vec::new();
            while let Some(chunk) = first.data().await {
                let chunk = chunk.expect("retained writer data");
                assert!(received.len() + chunk.len() <= 4);
                received.extend_from_slice(&chunk);
                first
                    .flow_control()
                    .release_capacity(chunk.len())
                    .expect("request credit");
            }
            assert_eq!(received, b"ping");
            let mut second = second.into_body();
            while let Some(chunk) = second.data().await {
                assert!(chunk.expect("second request FIN").is_empty());
            }
            finished.send(()).expect("request completion signal");
        };
        tokio::select! {
            () = exchange => {}
            incoming = connection.accept() => panic!("connection ended before request FIN: {incoming:?}"),
        }
        if let Some(incoming) = connection.accept().await {
            incoming.expect("connection close");
            panic!("no third request expected");
        }
    });
    let session = H2Session::handshake_with_config(
        client,
        true,
        H2Config {
            direction_buffer_bytes: WINDOW,
            initial_connection_window: WINDOW as u32,
            ..H2Config::default()
        },
    )
    .await
    .expect("session");
    let destination = target_destination();
    let first = session
        .open_stream(&destination, &credential())
        .await
        .expect("first stream");
    let mut second = session
        .open_stream(&destination, &credential())
        .await
        .expect("second stream");
    let (mut reader, mut writer) = first.into_split();
    timeout(IO_TIMEOUT, window_filled)
        .await
        .expect("window depletion")
        .expect("filled signal");
    let mut prefix = [0];
    assert_eq!(
        timeout(IO_TIMEOUT, reader.read(&mut prefix))
            .await
            .expect("first response prefix")
            .expect("first read"),
        ReadOutcome::Data(1)
    );
    assert_eq!(prefix, [b'a']);
    timeout(IO_TIMEOUT, prefix_credit)
        .await
        .expect("copied prefix returned to the peer")
        .expect("prefix signal");
    drop(reader);
    timeout(IO_TIMEOUT, async {
        let mut received = 0;
        let mut buffer = [0; 1024];
        loop {
            match second.read(&mut buffer).await.expect("second response") {
                ReadOutcome::Data(n) => {
                    assert!(n > 0 && received + n <= WINDOW);
                    assert!(buffer[..n].iter().all(|byte| *byte == b'b'));
                    received += n;
                }
                ReadOutcome::Eof => break,
                outcome => panic!("unexpected response outcome: {outcome:?}"),
            }
        }
        assert_eq!(received, WINDOW);
    })
    .await
    .expect("sibling progresses before the retained writer is touched");
    assert_eq!(writer.write(b"ping").await.expect("retained writer"), 4);
    writer.end_write().await.expect("first request FIN");
    second.end_write().await.expect("second request FIN");
    timeout(IO_TIMEOUT, requests_finished)
        .await
        .expect("request completion")
        .expect("request signal");
    drop((writer, second));
    session.close(IO_TIMEOUT).await.expect("session close");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server assertions");
}

#[tokio::test]
async fn split_writer_wakes_for_credit_while_reader_is_pending() {
    use std::future::Future;

    let (client, server_io) = tokio::io::duplex(1024);
    let (filled, window_filled) = tokio::sync::oneshot::channel();
    let (release, release_window) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder.initial_window_size(1);
        let mut connection = builder
            .handshake::<_, bytes::Bytes>(server_io)
            .await
            .expect("handshake");
        let (request, mut respond) = connection.accept().await.expect("request").expect("accept");
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .expect("response");
        let exchange = async move {
            let mut body = request.into_body();
            let first = body.data().await.expect("first data").expect("first byte");
            assert_eq!(first.as_ref(), b"a");
            filled.send(()).expect("window filled signal");
            release_window.await.expect("release signal");
            body.flow_control()
                .release_capacity(1)
                .expect("return stream credit");
            let second = body
                .data()
                .await
                .expect("second data")
                .expect("second byte");
            assert_eq!(second.as_ref(), b"b");
            body.flow_control()
                .release_capacity(1)
                .expect("return second credit");
            while let Some(chunk) = body.data().await {
                assert!(chunk.expect("request FIN").is_empty());
            }
            send.send_data(bytes::Bytes::from_static(b"done"), true)
                .expect("response data and FIN");
        };
        tokio::select! {
            () = exchange => {}
            incoming = connection.accept() => panic!("connection ended before request FIN: {incoming:?}"),
        }
        if let Some(incoming) = connection.accept().await {
            incoming.expect("connection close");
            panic!("no second request expected");
        }
    });
    let session = H2Session::handshake(client, true).await.expect("session");
    let stream = session
        .open_stream(&target_destination(), &credential())
        .await
        .expect("stream");
    let (mut reader, mut writer) = stream.into_split();
    assert_eq!(writer.write(b"a").await.expect("fill stream window"), 1);
    timeout(IO_TIMEOUT, window_filled)
        .await
        .expect("window depletion")
        .expect("filled signal");
    let writer_wake = Arc::new(CapacityWake {
        notified: tokio::sync::Notify::new(),
    });
    let writer_waker = std::task::Waker::from(Arc::clone(&writer_wake));
    let mut pending_write = Box::pin(writer.write(b"b"));
    assert!(
        pending_write
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&writer_waker))
            .is_pending()
    );
    let reader_wake = Arc::new(CapacityWake {
        notified: tokio::sync::Notify::new(),
    });
    let reader_waker = std::task::Waker::from(reader_wake);
    let mut response = [0x5a; 4];
    let mut pending_read = Box::pin(reader.read(&mut response));
    // h2 reset and capacity polls share one send waker. Poll the reader last.
    assert!(
        pending_read
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&reader_waker))
            .is_pending()
    );
    release.send(()).expect("release window");
    timeout(IO_TIMEOUT, writer_wake.notified.notified())
        .await
        .expect("credit wakes the writer before the reader is polled again");
    assert_eq!(
        timeout(IO_TIMEOUT, pending_write)
            .await
            .expect("writer progress")
            .expect("second write"),
        1
    );
    writer.end_write().await.expect("request FIN");
    assert_eq!(
        timeout(IO_TIMEOUT, pending_read)
            .await
            .expect("response progress")
            .expect("response data"),
        ReadOutcome::Data(4)
    );
    assert_eq!(response, *b"done");
    let mut sentinel = [0x5a];
    assert_eq!(
        reader.read(&mut sentinel).await.expect("response EOF"),
        ReadOutcome::Eof
    );
    assert_eq!(sentinel, [0x5a]);
    drop((writer, reader));
    session.close(IO_TIMEOUT).await.expect("session close");
    timeout(IO_TIMEOUT, server)
        .await
        .expect("server completion")
        .expect("server assertions");
}
