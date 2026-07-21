mod common;
mod config;
mod kfree_skb;
mod metrics;
mod program;

use std::{collections::HashMap, sync::Arc};

use aya_log::EbpfLogger;
use clap::Parser;
use common::BpfAgentArgs;
use daemonize::Daemonize;
use kfree_skb::{KfreeSkbProgram, Metrics, display_drop_counts};
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

        // Get enabled program names from config
        // If config has explicit programs, use those; otherwise use default set
        let enabled_program_names = if daemon_config.has_explicit_programs() {
            daemon_config.enabled_program_names()
        } else {
            // No explicit config - enable all known programs
            vec!["kfree_skb".to_string()]
        };

        if enabled_program_names.is_empty() {
            debug!("No programs enabled, exiting");
            return Ok(());
        }

        debug!("Enabled programs from config: {:?}", enabled_program_names);

        // Create program instances based on enabled names
        let mut programs: HashMap<String, Box<dyn program::EbpfProgram>> = HashMap::new();

        for program_name in &enabled_program_names {
            match program_name.as_str() {
                "kfree_skb" => {
                    debug!("Registering kfree_skb program");
                    programs.insert(program_name.clone(), Box::new(KfreeSkbProgram::new()));
                }
                _ => {
                    warn!("Unknown program in config: {}", program_name);
                }
            }
        }

        // Load all enabled programs
        for (name, program) in &mut programs {
            debug!("Loading program: {}", name);
            program.load()?;
        }

        // Initialize BPF logger (need to get ebpf from one of the programs)
        // For now, get it from kfree_skb
        if let Some(kfree_skb) = programs.get_mut("kfree_skb") {
            let kfree_skb_any = kfree_skb.as_any_mut();
            if let Some(kfree_skb) = kfree_skb_any.downcast_mut::<KfreeSkbProgram>() {
                if let Some(ebpf) = kfree_skb.ebpf.as_mut() {
                    match EbpfLogger::init(ebpf) {
                        Err(e) => {
                            warn!("failed to initialize eBPF logger: {e}");
                        }
                        Ok(logger) => {
                            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                                logger,
                                tokio::io::Interest::READABLE,
                            )?;
                            tokio::task::spawn(async move {
                                loop {
                                    let mut guard = logger.readable_mut().await.unwrap();
                                    guard.get_inner_mut().flush();
                                    guard.clear_ready();
                                }
                            });
                        }
                    }
                }
            }
        }

        // Start all enabled programs
        for (name, program) in &mut programs {
            debug!("Starting program: {}", name);
            program.start()?;
        }

        // Get the DROP_COUNTS map from kfree_skb
        let drop_counts = if programs.contains_key("kfree_skb") {
            let kfree_skb = programs.get_mut("kfree_skb").unwrap();
            // Since we only support kfree_skb, we can safely downcast
            let kfree_skb = kfree_skb
                .as_any_mut()
                .downcast_mut::<KfreeSkbProgram>()
                .ok_or_else(|| anyhow::anyhow!("failed to downcast kfree_skb"))?;
            kfree_skb
                .get_drop_counts_map()
                .ok_or_else(|| anyhow::anyhow!("kfree_skb DROP_COUNTS map not found"))?
        } else {
            return Err(anyhow::anyhow!("kfree_skb program not found"));
        };

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

        // Display drops and update metrics every 3 seconds until Ctrl-C
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
