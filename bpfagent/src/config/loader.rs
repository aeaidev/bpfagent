//! Configuration file parsing and daemon settings
//!
//! This module handles loading and parsing the TOML configuration file,
//! which controls daemon behavior and which eBPF programs to load.
//!
//! # Configuration File Format
//!
//! ```toml
//! # Daemon settings
//! pid_file = "/tmp/bpfagent.pid"
//! working_directory = "/"
//! log_file = "/tmp/bpfagent.log"
//!
//! # EBPF programs to load and run
//! [[ebpf_programs]]
//! name = "kfree_skb"
//! enabled = true
//!
//! [[ebpf_programs]]
//! name = "sca"
//! enabled = true
//!
//! # Program-specific settings (optional, interpreted by the program)
//! [[ebpf_programs]]
//! name = "irss"
//! enabled = true
//!
//! [ebpf_programs.settings]
//! raw_dest = "10.10.10.253"
//! ```
//!
//! # Search Paths
//!
//! If no config file is specified, the application searches these paths:
//! - `/etc/bpfagent.conf`
//! - `/etc/bpfagent/bpfagent.conf`
//! - `/usr/local/etc/bpfagent.conf`
//! - `/usr/local/etc/bpfagent/bpfagent.conf`
//! - `~/.bpfagent.conf`
//! - `~/.config/bpfagent/config.toml`
//! - `./bpfagent.conf` (current directory for development)

use std::path::{Path, PathBuf};

use anyhow::Context;
use log::debug;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct EbpfProgramConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional program-specific settings (free-form TOML table, interpreted
    /// by the program via `EbpfProgram::configure`)
    #[serde(default)]
    pub settings: Option<toml::Table>,
}

fn default_true() -> bool {
    true
}

fn default_programs() -> Vec<EbpfProgramConfig> {
    Vec::new() // Empty list means enable all registered programs
}

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    pub pid_file: String,
    pub working_directory: String,
    pub log_file: String,
    #[serde(default = "default_programs")]
    pub ebpf_programs: Vec<EbpfProgramConfig>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: "/tmp/bpfagent.pid".to_string(),
            working_directory: "/".to_string(),
            log_file: "/tmp/bpfagent.log".to_string(),
            ebpf_programs: default_programs(),
        }
    }
}

impl DaemonConfig {
    /// Load daemon configuration from file or use defaults
    ///
    /// Searches standard config paths if no custom path provided.
    ///
    /// # Errors
    /// Returns error if custom config is specified but doesn't exist or is invalid TOML
    pub fn load(custom_config: Option<String>) -> Result<Self, anyhow::Error> {
        // If custom config file is provided, use it
        if let Some(config_path) = custom_config {
            let path = Path::new(&config_path);
            if path.exists() {
                return Self::load_from_path(path);
            } else {
                return Err(anyhow::anyhow!(
                    "specified config file does not exist: {}",
                    config_path
                ));
            }
        }

        // Try to load from various config paths
        let mut config_paths: Vec<PathBuf> = vec![
            Path::new("/etc/bpfagent.conf").to_path_buf(),
            Path::new("/etc/bpfagent/bpfagent.conf").to_path_buf(),
            Path::new("/usr/local/etc/bpfagent.conf").to_path_buf(),
            Path::new("/usr/local/etc/bpfagent/bpfagent.conf").to_path_buf(),
        ];

        // Add user config paths if HOME is set
        if let Ok(home_dir) = std::env::var("HOME") {
            let home_path = Path::new(&home_dir);
            config_paths.push(home_path.join(".bpfagent.conf"));
            config_paths.push(home_path.join(".config/bpfagent/config.toml"));
        }

        // Also check the current directory (for development)
        if let Ok(cwd) = std::env::current_dir() {
            config_paths.push(cwd.join("bpfagent.conf"));
        }

        for config_path in &config_paths {
            if config_path.exists() {
                debug!("Loading config from: {}", config_path.display());
                return Self::load_from_path(config_path);
            }
        }

        debug!("No config file found in standard paths, using defaults");
        Ok(Self::default())
    }

    /// Load configuration from a specific file path
    ///
    /// # Errors
    /// Returns error if file cannot be read or contains invalid TOML
    fn load_from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)
            .context(format!("failed to read config file: {}", path.display()))?;

        debug!("Config file content length: {} bytes", content.len());

        toml::from_str(&content).context(format!(
            "failed to parse config file as TOML: {}",
            path.display()
        ))
    }
}
