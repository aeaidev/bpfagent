//! Application wiring: program registration, eBPF loading, Prometheus setup,
//! and the main event loop.

use std::{collections::HashMap, sync::Arc};

use log::{debug, error, info, warn};
use prometheus::Registry;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use aya_log::EbpfLogger;
use tokio::io::unix::AsyncFd;

use crate::cli::BpfAgentArgs;
use crate::config;
use crate::metrics::run_metrics_server;
use crate::programs::{EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Register all available EBPF programs
/// Each program module registers itself by calling `registry.register()`
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();

    // Initialize all program modules - each module registers itself
    // To add a new program, add its module and call its init function here
    crate::programs::kfree_skb::init(&mut registry);
    crate::programs::sca::init(&mut registry);

    registry
}

/// Bump the memlock rlimit. This is needed for older kernels that don't use the
/// new memcg based accounting.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("setrlimit failed, ret is: {}", ret);
    }
}

/// Load and instantiate programs configured by the user
fn load_programs(
    daemon_config: &config::DaemonConfig,
) -> anyhow::Result<HashMap<String, Box<dyn EbpfProgram>>> {
    // Register all available programs
    info!("Registering all available programs");
    let program_registry = register_programs();
    info!(
        "Available programs: {:?}",
        program_registry.available_programs()
    );

    // Get enabled programs from config
    let enabled_program_names: Vec<String> = daemon_config
        .ebpf_programs
        .iter()
        .filter(|p| p.enabled)
        .map(|p| p.name.clone())
        .collect();

    // If no programs specified in config, enable all registered programs
    let enabled_program_names = if enabled_program_names.is_empty() {
        info!("No programs in config, enabling all registered programs");
        program_registry.available_programs()
    } else {
        enabled_program_names
    };
    info!("Enabled programs: {:?}", enabled_program_names);

    if enabled_program_names.is_empty() {
        info!("No programs enabled, exiting");
        return Ok(HashMap::new());
    }

    // Create program instances based on enabled names
    let mut programs = HashMap::new();
    for program_name in &enabled_program_names {
        let program = program_registry
            .create_program(program_name)
            .ok_or_else(|| anyhow::anyhow!("failed to create program {}", program_name))?;

        programs.insert(program_name.clone(), program);
    }
    info!("Loaded {} programs", programs.len());
    Ok(programs)
}

/// Setup EbpfLogger to capture eBPF debug output
fn setup_ebpf_logger(name: &str, program: &mut Box<dyn EbpfProgram>) {
    debug!("Initializing EbpfLogger for program: {}", name);
    // Get the underlying Ebpf instance to initialize the logger
    if let Some(ebpf) = program.ebpf_mut() {
        match EbpfLogger::init(ebpf) {
            Ok(logger) => {
                debug!("EbpfLogger initialized for program {}", name);

                // Spawn a task to continuously flush the logger
                tokio::task::spawn(async move {
                    match AsyncFd::with_interest(logger, tokio::io::Interest::READABLE) {
                        Ok(mut logger) => loop {
                            match logger.readable_mut().await {
                                Ok(mut guard) => {
                                    guard.get_inner_mut().flush();
                                    guard.clear_ready();
                                }
                                Err(e) => {
                                    debug!("AsyncFd readable error: {}", e);
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                }
                            }
                        },
                        Err(e) => {
                            debug!("Failed to create AsyncFd for logger: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                debug!(
                    "Failed to initialize EbpfLogger for program {}: {}",
                    name, e
                );
            }
        }
    } else {
        debug!("No Ebpf instance for program {}", name);
    }
}

/// Load and start all configured eBPF programs
fn load_and_start_ebpf_programs(
    programs: &mut HashMap<String, Box<dyn EbpfProgram>>,
) -> anyhow::Result<()> {
    // Load all enabled programs
    for (name, program) in programs.iter_mut() {
        info!("Loading program: {}", name);
        program.load()?;
    }

    // Initialize EbpfLogger to capture eBPF debug output
    // This must be done after programs are loaded to have access to their maps
    for (name, program) in programs.iter_mut() {
        setup_ebpf_logger(name, program);
    }

    // Start all enabled programs
    for (name, program) in programs.iter_mut() {
        info!("Starting program: {}", name);
        program.start()?;
    }

    Ok(())
}

/// Register programs with the Prometheus metrics registry if they support metrics
fn setup_prometheus_metrics(
    programs: &mut HashMap<String, Box<dyn EbpfProgram>>,
    prometheus_registry: Arc<Registry>,
) -> anyhow::Result<()> {
    for (name, program) in programs.iter_mut() {
        debug!("Checking if program {} supports metrics", name);
        if program.supports_metrics() {
            debug!("Program {} supports metrics", name);
            if let Some(metrics_program) = program.as_metrics_mut() {
                debug!("Got metrics program for {}", name);
                info!("Initializing metrics for program: {}", name);
                metrics_program.set_metrics_registry(prometheus_registry.clone())?;
                info!("Metrics initialized for program: {}", name);
            } else {
                debug!("as_metrics_mut returned None for {}", name);
            }
        } else {
            debug!("Program {} does not support metrics", name);
        }
    }
    Ok(())
}

/// Core event loop: handles signal termination and periodically displays metrics if supported
async fn run_event_loop(
    programs: &mut HashMap<String, Box<dyn EbpfProgram>>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    // Create signal streams for graceful shutdown
    let mut term_stream = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to create SIGTERM stream: {}", e))?;
    let mut int_stream = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("failed to create SIGINT stream: {}", e))?;

    // Display metrics for all programs that support it
    let mut metrics_programs: Vec<&mut dyn MetricsDisplay> = programs
        .values_mut()
        .filter(|p| p.supports_metrics())
        .filter_map(|p| p.as_metrics_mut())
        .collect();

    if !metrics_programs.is_empty() {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    cancel_token.cancel();
                    println!("\nExiting...");
                    break;
                }
                _ = term_stream.recv() => {
                    info!("Received SIGTERM");
                    cancel_token.cancel();
                    break;
                }
                _ = int_stream.recv() => {
                    info!("Received SIGINT");
                    cancel_token.cancel();
                    break;
                }
                _ = interval.tick() => {
                    for program in &mut metrics_programs {
                        if let Err(e) = program.display_metrics() {
                            error!("failed to display metrics: {}", e);
                        }
                    }
                }
            }
        }
    } else {
        // No metrics programs - just wait for shutdown signal
        info!("No metrics programs to display, waiting for shutdown signal");
        tokio::select! {
            _ = term_stream.recv() => {
                info!("Received SIGTERM");
            }
            _ = int_stream.recv() => {
                info!("Received SIGINT");
            }
        }
        info!("Shutting down");
        cancel_token.cancel();
    }

    Ok(())
}

/// Run-time setup and asynchronous entry point
pub async fn run(args: BpfAgentArgs, daemon_config: config::DaemonConfig) -> anyhow::Result<()> {
    info!("Entered tokio runtime block_on");
    bump_memlock_rlimit();

    // Register all available programs
    let mut programs = load_programs(&daemon_config)?;
    if programs.is_empty() {
        return Ok(());
    }
    load_and_start_ebpf_programs(&mut programs)?;

    // Initialize Prometheus registry
    let prometheus_registry = Arc::new(Registry::new());
    setup_prometheus_metrics(&mut programs, prometheus_registry.clone())?;

    // Initialize cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_token_metrics = cancel_token.clone();

    // Start metrics server
    info!("About to start metrics server task");
    let metrics_addr = format!("{}:{}", args.metrics_ip, args.metrics_port);
    let _metrics_server = tokio::task::spawn({
        let prometheus_registry = prometheus_registry.clone();
        async move {
            info!("Metrics server task started");
            if let Err(e) =
                run_metrics_server(prometheus_registry, cancel_token_metrics, metrics_addr).await
            {
                warn!("metrics server error: {e}");
            }
            info!("Metrics server task completed");
        }
    });
    info!("Metrics server task spawned, waiting for it");

    run_event_loop(&mut programs, cancel_token).await?;

    info!("About to return from main runtime");
    Ok(())
}
