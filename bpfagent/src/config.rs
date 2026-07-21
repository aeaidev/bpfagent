use std::path::{Path, PathBuf};

use anyhow::anyhow;
use log::debug;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct EbpfProgramConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    pub fn load(custom_config: Option<String>) -> Result<Self, anyhow::Error> {
        // If custom config file is provided, use it
        if let Some(config_path) = custom_config {
            let path = Path::new(&config_path);
            if path.exists() {
                return Self::load_from_path(path);
            } else {
                return Err(anyhow!("config file not found: {}", config_path));
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

        debug!("No config file found, using defaults");
        Ok(Self::default())
    }

    fn load_from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read config file {}: {}", path.display(), e))?;

        log::debug!("Config file content length: {}", content.len());
        log::debug!("Config file content bytes: {:?}", content.as_bytes());

        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow!("failed to parse config file {}: {}", path.display(), e))?;

        Ok(config)
    }
}
