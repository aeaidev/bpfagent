mod common;
mod config;
mod kfree_skb;
mod metrics;

use std::sync::Arc;

use aya::{Ebpf, maps::MapData};
use aya_log::EbpfLogger;
use clap::Parser;
use common::BpfAgentArgs;
use daemonize::Daemonize;
use kfree_skb::{Metrics, display_drop_counts};
use log::{debug, warn};
use metrics::run_metrics_server;
use prometheus::Registry;
use tokio::signal;
use tokio_util::sync::CancellationToken;

fn main() -> anyhow::Result<()> {
    let args = BpfAgentArgs::parse();
    env_logger::init();

    // Load daemon config from config file or use defaults
    let daemon_config = config::DaemonConfig::load(args.config_file)?;

    // Handle daemon mode - detach from terminal
    if args.daemon && !args.verbose {
        use std::fs::File;

        debug!("Starting in daemon mode - detaching from terminal");
        let daemonize = Daemonize::new()
            .pid_file(&daemon_config.pid_file)
            .chown_pid_file(true)
            .working_directory(&daemon_config.working_directory)
            .user(daemon_config.user.as_str())
            .group(daemon_config.group.as_str())
            .stderr(File::create(&daemon_config.log_file).expect("failed to create log file"))
            .stdout(File::create(&daemon_config.log_file).expect("failed to create log file"));
        daemonize
            .start()
            .map_err(|e| anyhow::anyhow!("failed to daemonize: {}", e))?;
    }

    tokio::runtime::Runtime::new()?.block_on(async move {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // Initialize Prometheus registry
        let registry = Registry::new();
        let metrics = Metrics::new(&registry);

        // Load the BPF program
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/kfree_skb"
        )))?;

        // Initialize BPF logger
        match EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        // Get the BPF program and map
        let program: &mut aya::programs::TracePoint =
            ebpf.program_mut("kfree_skb").unwrap().try_into()?;
        program.load()?;
        program.attach("skb", "kfree_skb")?;

        // Get the DROP_COUNTS map
        let drop_counts = aya::maps::HashMap::<&mut MapData, u32, u64>::try_from(
            ebpf.map_mut("DROP_COUNTS").unwrap(),
        )?;
        let drop_counts = Arc::new(std::sync::Mutex::new(drop_counts));

        // Initialize cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();
        let cancel_token_metrics = cancel_token.clone();

        // Start metrics server
        tokio::task::spawn(async move {
            let metrics_addr = format!("{}:{}", args.metrics_ip, args.metrics_port);
            if let Err(e) = run_metrics_server(registry, cancel_token_metrics, metrics_addr).await {
                warn!("metrics server error: {e}");
            }
        });

        // Display drops and update metrics every 3 second until Ctrl-C
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    cancel_token.cancel();
                    println!("\nExiting...");
                    break;
                }
                _ = interval.tick() => {
                    // Fetch and display current counts, update Prometheus metrics
                    display_drop_counts(&mut drop_counts.lock().unwrap(), &metrics)?;
                }
            }
        }

        Ok(())
    })
}
