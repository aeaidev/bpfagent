use clap::Parser;

/// Common command-line arguments for bpfagent
#[derive(Parser, Debug)]
#[command(
    name = "bpfagent",
    author = "Katim LLC",
    version,
    about = "EBPF program manager and Prometheus metrics extractor",
    long_about = None
)]
pub struct BpfAgentArgs {
    /// Metrics server IP address
    #[arg(short = 'i', long, default_value = "0.0.0.0")]
    pub metrics_ip: String,

    /// Metrics server port
    #[arg(short = 'p', long, default_value = "9101")]
    pub metrics_port: u16,
}
