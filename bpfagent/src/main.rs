//! BPF Agent - Generic eBPF Program Manager with Prometheus Metrics Export
//!
//! This application manages multiple eBPF programs that collect kernel metrics.
//! It provides:
//! - Configuration-driven program loading
//! - Prometheus metrics export via HTTP
//! - Daemon mode with proper signal handling
//! - Support for both interactive and background operation
//!
//! # Programs
//!
//! - `kfree_skb`: Traces kernel packet drops by reason
//! - `sca`: Traces socket communication latency per process
//!
//! # Usage
//!
//! ```ignore
//! sudo cargo run --release -- --config-file /etc/bpfagent.conf --metrics-port 9101
//! ```
//!
//! # Architecture
//!
//! The application follows this flow:
//! 1. Parse CLI arguments and load config
//! 2. Daemonize if configured
//! 3. Load and start eBPF programs
//! 4. Initialize Prometheus metrics registry
//! 5. Start metrics HTTP server
//! 6. Enter event loop (periodically display/export metrics)
//! 7. Gracefully shutdown on signals

mod cli;
mod config;
mod metrics;
mod programs;

use std::{collections::HashMap, fs::File, os::unix::io::AsRawFd, sync::Arc};

use clap::Parser;
use cli::BpfAgentArgs;
use log::{debug, error, info, warn};
use metrics::run_metrics_server;
use prometheus::Registry;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use aya_log::EbpfLogger;
use tokio::io::unix::AsyncFd;

use crate::programs::{EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Register all available EBPF programs
/// Each program module registers itself by calling `registry.register()`
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();

    // Initialize all program modules - each module registers itself
    // To add a new program, add its module and call its init function here
    programs::kfree_skb::init(&mut registry);
    programs::sca::init(&mut registry);

    registry
}

/// Initialize logger based on execution mode (daemon vs foreground) before daemonizing
fn init_logger_initial(args: &BpfAgentArgs) {
    if args.daemon && !args.verbose {
        // In daemon mode, we'll initialize after daemonize to redirect to log file
        // Don't initialize logger yet
    } else {
        // In foreground/verbose mode, initialize logger to stderr
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
}

/// Detach the process from the terminal and run as a daemon if configured.
///
/// This function forks the process and sets up file descriptors to run in the background.
/// It must be called before the async runtime is created.
fn daemonize(
    args: &BpfAgentArgs,
    daemon_config: &config::DaemonConfig,
) -> anyhow::Result<Option<File>> {
    if !args.daemon || args.verbose {
        return Ok(None);
    }

    // Create log file before daemonize
    let log_file_path = &daemon_config.log_file;
    let file = File::create(log_file_path)
        .map_err(|e| anyhow::anyhow!("failed to create log file {}: {}", log_file_path, e))?;

    // Write to PID file
    std::fs::write(&daemon_config.pid_file, std::process::id().to_string()).map_err(|e| {
        anyhow::anyhow!("failed to write PID file {}: {}", daemon_config.pid_file, e)
    })?;

    // Fork and detach from terminal
    fork_and_detach(&file, &daemon_config.working_directory)?;

    Ok(Some(file))
}

/// Fork the process and set up file descriptors for daemon mode.
///
/// # Safety
/// This function uses unsafe libc calls to fork and manage file descriptors.
/// It must only be called from the main thread before creating any child threads.
fn fork_and_detach(log_file: &File, working_dir: &str) -> anyhow::Result<()> {
    // SAFETY: fork() is unsafe but safe to call here before tokio runtime
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow::anyhow!("fork() failed: cannot daemonize process"));
    }
    if pid > 0 {
        // Parent process - exit
        std::process::exit(0);
    }

    // Child process continues here
    redirect_stdio(log_file)?;
    create_new_session()?;
    change_working_directory(working_dir)?;

    Ok(())
}

/// Redirect stdin, stdout, and stderr for daemon mode.
///
/// # Safety
/// Uses unsafe libc dup2 calls. Must be called only in child process after fork.
fn redirect_stdio(log_file: &File) -> anyhow::Result<()> {
    let dev_null =
        File::open("/dev/null").map_err(|e| anyhow::anyhow!("failed to open /dev/null: {}", e))?;

    let dev_null_fd = dev_null.as_raw_fd();
    let log_fd = log_file.as_raw_fd();

    // Close stdin
    if unsafe { libc::dup2(dev_null_fd, libc::STDIN_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stdin: cannot redirect file descriptors"
        ));
    }

    // Redirect stdout to log file
    if unsafe { libc::dup2(log_fd, libc::STDOUT_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stdout: cannot redirect file descriptors"
        ));
    }

    // Redirect stderr to log file
    if unsafe { libc::dup2(log_fd, libc::STDERR_FILENO) } < 0 {
        return Err(anyhow::anyhow!(
            "dup2() failed for stderr: cannot redirect file descriptors"
        ));
    }

    Ok(())
}

/// Create a new session to fully detach from terminal.
///
/// # Safety
/// Uses unsafe libc setsid call. Must be called only in child process after fork.
fn create_new_session() -> anyhow::Result<()> {
    // SAFETY: setsid() is unsafe but must be called in child process to detach
    if unsafe { libc::setsid() } < 0 {
        return Err(anyhow::anyhow!(
            "setsid() failed: cannot create new session for daemon"
        ));
    }
    Ok(())
}

/// Change to the working directory specified in config.
fn change_working_directory(working_dir: &str) -> anyhow::Result<()> {
    std::env::set_current_dir(working_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to change working directory to {}: {}",
            working_dir,
            e
        )
    })
}

/// Re-initialize logger after daemonize to redirect logs to the new stdout/stderr log file
fn init_logger_after_daemonize(args: &BpfAgentArgs) {
    if args.daemon && !args.verbose {
        let _ = env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        info!("Logger initialized in daemon mode");
    } else if args.daemon && args.verbose {
        info!("Verbose mode overrides daemon mode - running in foreground");
    } else {
        info!("Running in foreground mode");
    }
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
async fn run(args: BpfAgentArgs, daemon_config: config::DaemonConfig) -> anyhow::Result<()> {
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

fn main() -> anyhow::Result<()> {
    let args = BpfAgentArgs::parse();

    // Load daemon config from config file or use defaults
    let daemon_config = config::DaemonConfig::load(args.config_file.clone())?;

    // Initialize logger based on mode
    init_logger_initial(&args);

    // Handle daemon mode - detach from terminal
    let _log_file = daemonize(&args, &daemon_config)?;

    // Re-initialize logger after daemonize to use the new stdout/stderr
    init_logger_after_daemonize(&args);

    info!("Starting main runtime");

    // Create tokio runtime
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        error!("Failed to create tokio runtime: {}", e);
        anyhow::anyhow!("Failed to create tokio runtime: {}", e)
    })?;
    info!("Tokio runtime created, about to enter block_on");

    let result = runtime.block_on(run(args, daemon_config));

    result.map_err(|e| {
        error!("Runtime error: {}", e);
        anyhow::anyhow!("Runtime error: {}", e)
    })?;
    info!("Exited runtime");
    Ok(())
}
