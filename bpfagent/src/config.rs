use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    pub pid_file: String,
    pub working_directory: String,
    pub user: String,
    pub group: String,
    pub log_file: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: "/tmp/bpfagent.pid".to_string(),
            working_directory: "/".to_string(),
            user: "root".to_string(),
            group: "root".to_string(),
            log_file: "/tmp/bpfagent.log".to_string(),
        }
    }
}

impl DaemonConfig {
    pub fn load(custom_config: Option<String>) -> Result<Self, anyhow::Error> {
        let mut config = Self::default();

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

        for config_path in &config_paths {
            if config_path.exists() {
                config = Self::load_from_path(config_path)?;
                break;
            }
        }

        Ok(config)
    }

    fn load_from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read config file {}: {}", path.display(), e))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow!("failed to parse config file {}: {}", path.display(), e))?;

        Ok(config)
    }
}
