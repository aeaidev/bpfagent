mod common;
mod config;
mod kfree_skb;
mod metrics;
mod program;

use std::{collections::HashMap, fs::File, os::unix::io::AsRawFd, sync::Arc};

use clap::Parser;
use common::BpfAgentArgs;
use log::{debug, error, info, warn};
use metrics::run_metrics_server;
use prometheus::Registry;
use tokio::signal;
use tokio_util::sync::CancellationToken;

use crate::program::{EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Register all available EBPF programs
/// Each program module registers itself by calling `registry.register()`
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();

    // Initialize all program modules - each module registers itself
    // To add a new program, add its module and call its init function here
    kfree_skb::init(&mut registry);

    registry
}

fn main() -> anyhow::Result<()> {
    let args = BpfAgentArgs::parse();

    // Load daemon config from config file or use defaults
    let daemon_config = config::DaemonConfig::load(args.config_file)?;

    // Initialize logger based on mode
    if args.daemon && !args.verbose {
        // In daemon mode, we'll initialize after daemonize to redirect to log file
        // Don't initialize logger yet
    } else {
        // In foreground/verbose mode, initialize logger to stderr
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    // Handle daemon mode - detach from terminal
    let _log_file = if args.daemon && !args.verbose {
        // Create log file before daemonize
        let log_file_path = daemon_config.log_file.clone();
        let file = File::create(&log_file_path)
            .map_err(|e| anyhow::anyhow!("failed to create log file: {}", e))?;

        // Write to PID file
        std::fs::write(&daemon_config.pid_file, std::process::id().to_string())
            .map_err(|e| anyhow::anyhow!("failed to write PID file: {}", e))?;

        // Fork and exit parent
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(anyhow::anyhow!("fork failed"));
        }
        if pid > 0 {
            // Parent process - exit
            std::process::exit(0);
        }

        // Child process - continue
        // Close stdin
        let dev_null = File::open("/dev/null")?;
        unsafe {
            libc::dup2(dev_null.as_raw_fd(), libc::STDIN_FILENO);
        }

        // Redirect stdout and stderr to log file
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO);
        }
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
        }

        // Create new session
        unsafe {
            libc::setsid();
        }

        // Change working directory
        std::env::set_current_dir(&daemon_config.working_directory)
            .map_err(|e| anyhow::anyhow!("failed to change working directory: {}", e))?;

        Some(file)
    } else {
        None
    };

    // Re-initialize logger after daemonize to use the new stdout/stderr
    // Use RUST_LOG env var for logging level
    if args.daemon && !args.verbose {
        let _ = env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        // Explicitly flush stdout/stderr to ensure logs are written
        unsafe {
            libc::fflush(std::ptr::null_mut());
        }
        info!("Logger initialized in daemon mode");
    } else if args.daemon && args.verbose {
        info!("Verbose mode overrides daemon mode - running in foreground");
    } else {
        info!("Running in foreground mode");
    }

    info!("Starting main runtime");

    // Create tokio runtime
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        error!("Failed to create tokio runtime: {}", e);
        anyhow::anyhow!("Failed to create tokio runtime: {}", e)
    })?;
    info!("Tokio runtime created, about to enter block_on");

    let result = runtime.block_on(async move {
        info!("Entered tokio runtime block_on");
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("setrlimit failed, ret is: {}", ret);
        }

        // Initialize Prometheus registry with a new empty registry
        let prometheus_registry = Arc::new(Registry::new());

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
            return Ok::<(), anyhow::Error>(());
        }

        // Create program instances based on enabled names
        let mut programs: HashMap<String, Box<dyn EbpfProgram>> = HashMap::new();
        for program_name in &enabled_program_names {
            let program = program_registry
                .create_program(program_name)
                .ok_or_else(|| anyhow::anyhow!("failed to create program {}", program_name))?;

            programs.insert(program_name.clone(), program);
        }
        info!("Loaded {} programs", programs.len());

        // Load all enabled programs
        for (name, program) in &mut programs {
            info!("Loading program: {}", name);
            program.load()?;
        }

        // Start all enabled programs
        for (name, program) in &mut programs {
            info!("Starting program: {}", name);
            program.start()?;
        }

        // Initialize Prometheus metrics for all programs that support it
        for (name, program) in &mut programs {
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

        // Initialize cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();
        let cancel_token_metrics = cancel_token.clone();

        info!("About to start metrics server task");
        // Start metrics server
        let metrics_addr = format!("{}:{}", args.metrics_ip, args.metrics_port);
        let _metrics_server = tokio::task::spawn(async move {
            info!("Metrics server task started");
            if let Err(e) = run_metrics_server(
                prometheus_registry.clone(),
                cancel_token_metrics,
                metrics_addr,
            )
            .await
            {
                warn!("metrics server error: {e}");
            }
            info!("Metrics server task completed");
        });
        info!("Metrics server task spawned, waiting for it");

        // Create signal streams for graceful shutdown
        let mut term_stream = signal::unix::signal(signal::unix::SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("failed to create SIGTERM stream: {}", e))?;
        let mut int_stream = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .map_err(|e| anyhow::anyhow!("failed to create SIGINT stream: {}", e))?;

        // Display metrics for all programs that support it
        // Run in both interactive and daemon modes
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
                        // Fetch and display metrics for all programs that support it
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

        info!("About to return from main runtime");
        Ok(())
    });

    result.map_err(|e| {
        error!("Runtime error: {}", e);
        anyhow::anyhow!("Runtime error: {}", e)
    })?;
    info!("Exited runtime");
    Ok(())
}
