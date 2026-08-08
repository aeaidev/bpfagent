//! Common command-line argument definitions
//!
//! Provides shared CLI argument parsing for the bpfagent application,
//! supporting both daemon and interactive modes with configurable
//! metrics server settings.

use clap::Parser;

/// Common command-line arguments for bpfagent
#[derive(Parser, Debug)]
#[command(
    name = "bpfagent",
    author = "Katim LLC",
    version,
    about = "EBPF program manager and Prometheus metrics extractor\n     (only run as root user)",
    override_usage = "sudo bpfagent [OPTIONS]",
    long_about = None,
    after_help = "Config file:\n  Use -f/--config-file to specify a custom config file path\n  Otherwise, default paths are searched:\n    /etc/bpfagent.conf, /etc/bpfagent/bpfagent.conf\n    /usr/local/etc/bpfagent.conf, /usr/local/etc/bpfagent/bpfagent.conf\n    ~/.bpfagent.conf, ~/.config/bpfagent/config.toml (if HOME is set)\n\nExamples:\n  bpfagent                          # Run in interactive mode\n  bpfagent -d                     # Run in daemon mode\n  bpfagent -d -p 9102             # Run in daemon mode on port 9102\n  bpfagent -v                     # Run in verbose mode for debugging\n  bpfagent -f /path/to/config.toml  # Use custom config file\n\nMetrics endpoint: http://localhost:9101/metrics (default port)"
)]
pub struct BpfAgentArgs {
    /// Run in daemon mode (background, no stdout output)
    #[arg(short = 'd', long)]
    pub daemon: bool,

    /// Metrics server IP address
    #[arg(short = 'i', long, default_value = "0.0.0.0")]
    pub metrics_ip: String,

    /// Metrics server port
    #[arg(short = 'p', long, default_value = "9101")]
    pub metrics_port: u16,

    /// Enable verbose output (overrides daemon mode for interactive debugging)
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Path to config file
    #[arg(
        short = 'f',
        long,
        help = "Path to config file (overrides default config file paths)"
    )]
    pub config_file: Option<String>,
}
