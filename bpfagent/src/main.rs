//! BPF Agent - Generic eBPF Program Manager with Prometheus Metrics Export
//!
//! Thin binary entry point over the `bpfagent` library crate:
//! 1. Parse CLI arguments and load config
//! 2. Daemonize if configured
//! 3. Run the async application (load eBPF programs, serve metrics, event loop)
//!
//! # Usage
//!
//! ```ignore
//! sudo cargo run --release -- --config-file /etc/bpfagent.conf --metrics-port 9101
//! ```

use clap::Parser;
use log::{error, info};

use bpfagent::{app, cli::BpfAgentArgs, config, daemon};

fn main() -> anyhow::Result<()> {
    let args = BpfAgentArgs::parse();

    // Load daemon config from config file or use defaults
    let daemon_config = config::DaemonConfig::load(args.config_file.clone())?;

    // Initialize logger based on mode
    daemon::init_logger_initial(&args);

    // Handle daemon mode - detach from terminal
    let _log_file = daemon::daemonize(&args, &daemon_config)?;

    // Re-initialize logger after daemonize to use the new stdout/stderr
    daemon::init_logger_after_daemonize(&args);

    info!("Starting main runtime");

    // Create tokio runtime
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        error!("Failed to create tokio runtime: {}", e);
        anyhow::anyhow!("Failed to create tokio runtime: {}", e)
    })?;
    info!("Tokio runtime created, about to enter block_on");

    let result = runtime.block_on(app::run(args, daemon_config));

    result.map_err(|e| {
        error!("Runtime error: {}", e);
        anyhow::anyhow!("Runtime error: {}", e)
    })?;
    info!("Exited runtime");
    Ok(())
}
