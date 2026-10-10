#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ariad_core::{BudgetLimits, EngineError};
use ariad_server::{Reject, ServerOptions, load, run_with_options, validate};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ariad-server", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        control: Option<String>,
        #[arg(long, default_value_t = BudgetLimits::lab_small().active_sessions)]
        max_inflight: usize,
        #[arg(long, default_value_t = default_timeout_ms(ServerOptions::default().handshake_timeout))]
        handshake_timeout_ms: u64,
        #[arg(long, default_value_t = default_timeout_ms(ServerOptions::default().open_timeout))]
        open_timeout_ms: u64,
        #[arg(long, default_value_t = default_timeout_ms(ServerOptions::default().drain_timeout))]
        drain_timeout_ms: u64,
        #[arg(long, default_value_t = ServerOptions::default().max_resolved_addresses)]
        max_resolved_addresses: usize,
    },
}

fn default_timeout_ms(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).expect("default timeout fits u64 milliseconds")
}

fn report_config_reject(reject: Reject) -> ExitCode {
    let message = match reject {
        Reject::Invalid => "invalid config",
        Reject::EgressDenied => "egress denied",
    };
    eprintln!("{message}");
    ExitCode::FAILURE
}

fn run_and_shutdown(
    runtime: tokio::runtime::Runtime,
    serve: impl std::future::Future<Output = Result<(), EngineError>>,
    shutdown_timeout: Duration,
) -> Result<(), EngineError> {
    let result = runtime.block_on(serve);
    // Blocking workers can outlive drain. Cap the wait to avoid overflow from invalid CLI durations.
    runtime.shutdown_timeout(shutdown_timeout.min(ServerOptions::default().drain_timeout));
    result
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate { config } => match validate(&config) {
            Ok(()) => {
                println!("config ok");
                ExitCode::SUCCESS
            }
            Err(reject) => report_config_reject(reject),
        },
        Command::Serve {
            config,
            listen,
            cert,
            key,
            control,
            max_inflight,
            handshake_timeout_ms,
            open_timeout_ms,
            drain_timeout_ms,
            max_resolved_addresses,
        } => {
            let loaded = match load(&config) {
                Ok(loaded) => loaded,
                Err(reject) => return report_config_reject(reject),
            };
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("create server runtime: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let drain_timeout = Duration::from_millis(drain_timeout_ms);
            match run_and_shutdown(
                runtime,
                run_with_options(
                    &listen,
                    &cert,
                    &key,
                    loaded,
                    control.as_deref(),
                    max_inflight,
                    ServerOptions {
                        handshake_timeout: Duration::from_millis(handshake_timeout_ms),
                        open_timeout: Duration::from_millis(open_timeout_ms),
                        drain_timeout,
                        max_resolved_addresses,
                    },
                ),
                drain_timeout,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(EngineError::DeadlineExceeded) => {
                    eprintln!("drain deadline exceeded; connections were forced closed");
                    ExitCode::FAILURE
                }
                Err(error) => {
                    eprintln!("serve failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ariad_core::{BudgetLimits, EngineError, ResourceBudget};
    use clap::Parser;

    use super::{Cli, Command, ServerOptions, run_and_shutdown};

    const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn serve_cli_uses_server_defaults_and_keeps_explicit_overrides() {
        for (extra, options, inflight) in [
            (
                Vec::new(),
                ServerOptions::default(),
                BudgetLimits::lab_small().active_sessions,
            ),
            (
                vec![
                    "--max-inflight",
                    "3",
                    "--handshake-timeout-ms",
                    "17",
                    "--open-timeout-ms",
                    "23",
                    "--drain-timeout-ms",
                    "31",
                    "--max-resolved-addresses",
                    "2",
                ],
                ServerOptions {
                    handshake_timeout: Duration::from_millis(17),
                    open_timeout: Duration::from_millis(23),
                    drain_timeout: Duration::from_millis(31),
                    max_resolved_addresses: 2,
                },
                3,
            ),
        ] {
            let cli = Cli::try_parse_from(
                [
                    "ariad-server",
                    "serve",
                    "--config",
                    "server.toml",
                    "--cert",
                    "cert.pem",
                    "--key",
                    "key.pem",
                ]
                .into_iter()
                .chain(extra),
            )
            .expect("serve arguments");
            let Command::Serve {
                max_inflight,
                handshake_timeout_ms,
                open_timeout_ms,
                drain_timeout_ms,
                max_resolved_addresses,
                ..
            } = cli.command
            else {
                panic!("serve command");
            };
            assert_eq!(max_inflight, inflight);
            assert_eq!(
                Duration::from_millis(handshake_timeout_ms),
                options.handshake_timeout
            );
            assert_eq!(Duration::from_millis(open_timeout_ms), options.open_timeout);
            assert_eq!(
                Duration::from_millis(drain_timeout_ms),
                options.drain_timeout
            );
            assert_eq!(max_resolved_addresses, options.max_resolved_addresses);
        }
    }

    struct WorkerGuard {
        release: mpsc::Sender<()>,
        watchdog: Option<thread::JoinHandle<()>>,
        finished: mpsc::Receiver<()>,
    }

    impl WorkerGuard {
        fn finish(&mut self) -> Result<(), mpsc::RecvTimeoutError> {
            let _ = self.release.send(());
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
            self.finished.recv_timeout(WATCHDOG_TIMEOUT)
        }
    }

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            if self.watchdog.is_some() {
                let _ = self.finish();
            }
        }
    }

    #[test]
    fn runtime_shutdown_is_bounded_and_keeps_worker_reservation() {
        for expected in [
            Ok(()),
            Err(EngineError::DeadlineExceeded),
            Err(EngineError::TransportUnavailable),
        ] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let budget = ResourceBudget::new(1).expect("budget");
            let reservation = budget.try_acquire().expect("reservation");
            let (started, started_rx) = tokio::sync::oneshot::channel();
            let (release_worker, release_worker_rx) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let (finished, finished_rx) = mpsc::channel();
            let watchdog = thread::spawn(move || {
                let _ = release_rx.recv_timeout(WATCHDOG_TIMEOUT);
                let _ = release_worker.send(());
            });
            let mut worker_guard = WorkerGuard {
                release,
                watchdog: Some(watchdog),
                finished: finished_rx,
            };
            let shutdown_started = Instant::now();
            let actual = run_and_shutdown(
                runtime,
                async move {
                    let worker = tokio::task::spawn_blocking(move || {
                        let _ = started.send(());
                        let _ = release_worker_rx.recv();
                        drop(reservation);
                        let _ = finished.send(());
                    });
                    started_rx.await.expect("worker started");
                    drop(worker);
                    expected
                },
                Duration::from_millis(25),
            );

            assert!(shutdown_started.elapsed() < Duration::from_secs(1));
            assert_eq!(actual, expected);
            assert_eq!(budget.used(), 1);
            worker_guard.finish().expect("worker finished");
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn oversized_shutdown_timeout_keeps_the_server_error() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        assert_eq!(
            run_and_shutdown(
                runtime,
                async { Err(EngineError::InvalidConfig) },
                Duration::from_millis(u64::MAX),
            ),
            Err(EngineError::InvalidConfig)
        );
    }
}
