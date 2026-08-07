//! SCA (Socket Communication Analyzer) eBPF Program - Socket Latency Tracing
//!
//! This module provides a BPF program that traces socket communication latency
//! by measuring the timestamp difference between NNG protocol messages.
//!
//! The eBPF program attaches to various tracepoints (sendmsg, write, etc.) and
//! uses a combined key of Protocol (4B) + Message Type (2B) to match REQ/REP
//! message pairs on Unix domain sockets.
//!
//! # Latency Calculation
//!
//! - On receive: stores timestamp with key = Protocol + (MSG_Type + 1)
//! - On send: looks up timestamp with key = Protocol + MSG_Type
//! - Latency is calculated as the timestamp difference on match
//!
//! # Prometheus Metrics
//!
//! - `sca_max_latency_per_pname`: Maximum latency in microseconds per process name
//!
//! # Example Output
//!
//! ```text
//! --- Max Latency per Process Name ---
//!   INTERNAL_ROUTER: 150 us
//!   FRAGMENTER: 280 us
//! ```

use std::{any::Any, sync::Arc};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::{debug, info, warn};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::program::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Module re-exports for convenience
use sca_common;

/// Prometheus metrics for SCA program
pub struct ScaMetrics {
    pub max_latency_per_pname: IntGaugeVec,
}

impl ScaMetrics {
    /// Create new SCA Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let max_latency_per_pname = IntGaugeVec::new(
            Opts::new(
                "sca_max_latency_per_pname",
                "Maximum latency in microseconds per process name",
            ),
            &["pname"],
        )
        .map_err(|e| anyhow::anyhow!("failed to create max_latency_per_pname gauge: {}", e))?;

        registry
            .register(Box::new(max_latency_per_pname.clone()))
            .map_err(|e| {
                anyhow::anyhow!("failed to register max_latency_per_pname gauge: {}", e)
            })?;

        Ok(Self {
            max_latency_per_pname,
        })
    }
}

/// BPF program wrapper for SCA (tracing socket communication for latency analysis)
pub struct ScaProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<ScaMetrics>,
}

impl ScaProgram {
    /// Creates a new SCA BPF program
    pub fn new() -> Self {
        Self {
            name: "sca".to_string(),
            ebpf: None,
            metrics: None,
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: ScaMetrics) {
        self.metrics = Some(metrics);
    }
}

impl EbpfProgram for ScaProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "sys_enter_sendmsg"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/sca"
        )))?;

        debug!("Loaded BPF program, attaching tracepoints...");

        // Load and attach tracepoints
        for (name, category, event) in sca_common::TRACEPOINTS {
            let program: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program '{}' not found", name))?
                .try_into()?;
            program.load()?;
            program.attach(category, event)?;
            debug!("Attached tracepoint {}:{}:{}", name, category, event);
        }

        debug!("All tracepoints attached successfully");

        // Initialize process names map
        populate_process_names_map(&mut ebpf, sca_common::PROCESS_NAMES)?;

        // Populate socket fd map from running processes
        populate_socket_fd_map(&mut ebpf, sca_common::SOCKET_PATHS)?;

        // Populate LATENCY_PNAME_HASH with process names and value 0
        populate_latency_pname_hash(&mut ebpf)?;

        self.ebpf = Some(ebpf);

        Ok(())
    }

    fn start(&mut self) -> anyhow::Result<()> {
        debug!("Started BPF program: {}", self.name);
        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn supports_metrics(&self) -> bool {
        true
    }

    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        Some(self)
    }
}

impl MetricsDisplay for ScaProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = ScaMetrics::new(registry)?;
        self.set_metrics(metrics);
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        // Get metrics or return early if not set
        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metrics not set for sca program"))?;

        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;

        if let Some(map) = ebpf.map("LATENCY_PNAME_HASH") {
            let latency_map: HashMap<_, [u8; 16], u64> = map.try_into().unwrap();
            info!("--- Max Latency per Process Name ---");

            // Try to get all entries using the iter method
            for entry in latency_map.iter() {
                match entry {
                    Ok((pname, latency)) => {
                        // Convert process name from bytes to string, trimming null bytes
                        let pname_str = String::from_utf8_lossy(&pname)
                            .trim_end_matches('\0')
                            .to_string();
                        let latency_us = latency / 1000; // convert nano to micro
                        info!("  {}: {} us", pname_str, latency_us);

                        // Update Prometheus metrics with max latency in microseconds
                        metrics
                            .max_latency_per_pname
                            .with_label_values(&[&pname_str])
                            .set(latency_us as i64);
                    }
                    Err(e) => {
                        debug!("Failed to read entry: {}", e);
                    }
                }
            }

            debug!("Displaying max latency per process name");
        } else {
            warn!("LATENCY_PNAME_HASH not found");
        }

        Ok(())
    }
}

impl Default for ScaProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for ScaProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("sca", || Box::new(ScaProgram::new()));
}

/// Initialize PROCESS_NAMES_MAP
fn populate_process_names_map(ebpf: &mut Ebpf, process_names: &[&str]) -> anyhow::Result<()> {
    if let Some(map) = ebpf.map_mut("PROCESS_NAMES_MAP") {
        let mut process_names_map: aya::maps::HashMap<_, [u8; 16], u8> = map.try_into()?;
        process_names
            .iter()
            .map(|process_name| {
                let mut key: [u8; 16] = [0; 16];
                let bytes = process_name.as_bytes();
                let len = bytes.len().min(16);
                key[0..len].copy_from_slice(&bytes[0..len]);
                (key, process_name)
            })
            .for_each(|(key, process_name)| {
                process_names_map.insert(&key, &1, 0).unwrap();
                debug!(
                    "Inserted process name {} into PROCESS_NAMES_MAP",
                    process_name
                );
            });
    } else {
        warn!("PROCESS_NAMES_MAP not found");
    }

    Ok(())
}

/// Populate LATENCY_PNAME_HASH with process names and value 0
fn populate_latency_pname_hash(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    debug!("Populating LATENCY_PNAME_HASH with process names");

    if let Some(map) = ebpf.map_mut("LATENCY_PNAME_HASH") {
        let mut latency_pname_map: aya::maps::HashMap<_, [u8; 16], u64> = map
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to get LATENCY_PNAME_HASH"))?;

        for process_name in sca_common::PROCESS_NAMES {
            let mut key: [u8; 16] = [0; 16];
            let len = process_name.len().min(16);
            key[0..len].copy_from_slice(process_name.as_bytes());

            // Only insert if not already present
            match latency_pname_map.get(&key, 0) {
                Ok(_) => {
                    debug!(
                        "Process name {} already in LATENCY_PNAME_HASH, skipping",
                        process_name
                    );
                }
                Err(_) => {
                    latency_pname_map.insert(&key, &0, 0).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to insert process name {} into LATENCY_PNAME_HASH: {}",
                            process_name,
                            e
                        )
                    })?;
                    debug!(
                        "Inserted process name {} with value 0 into LATENCY_PNAME_HASH",
                        process_name
                    );
                }
            }
        }
    } else {
        warn!("LATENCY_PNAME_HASH not found");
    }

    Ok(())
}

/**
 * Populate SOCKET_FD_MAP with file descriptors from Unix sockets
 */
fn populate_socket_fd_map(ebpf: &mut Ebpf, _socket_paths: &[&str]) -> anyhow::Result<()> {
    debug!("Populating SOCKET_FD_MAP with all Unix socket fds from allowed processes");

    // Populate SOCKET_FD_MAP from process file descriptors
    for process_name in sca_common::PROCESS_NAMES {
        // Find PIDs for this process name
        let mut pids = Vec::new();

        for entry in procfs::process::all_processes()
            .map_err(|e| anyhow::anyhow!("Failed to get all processes: {}", e))?
        {
            let process = entry.map_err(|e| anyhow::anyhow!("Failed to get process: {}", e))?;
            let stat = process
                .stat()
                .map_err(|e| anyhow::anyhow!("Failed to get process stat: {}", e))?;
            if stat.comm == *process_name {
                pids.push(process.pid as u32);
            }
        }

        if pids.is_empty() {
            debug!("No processes found for name {}", process_name);
        } else {
            debug!("Found {} PIDs for process {}", pids.len(), process_name);
        }

        for pid in pids {
            let process = procfs::process::Process::new(pid as i32)
                .map_err(|e| anyhow::anyhow!("Failed to get process {}: {}", pid, e))?;
            let fds = process.fd().map_err(|e| {
                anyhow::anyhow!("Failed to get file descriptors for process {}: {}", pid, e)
            })?;

            let mut socket_count = 0;
            for fd_result in fds {
                let fd_info =
                    fd_result.map_err(|e| anyhow::anyhow!("Failed to read fd info: {}", e))?;

                // Only process Unix sockets
                let procfs::process::FDTarget::Socket(_inode) = fd_info.target else {
                    continue;
                };

                socket_count += 1;

                if let Some(map) = ebpf.map_mut("SOCKET_FD_MAP") {
                    let mut socket_fd_map: aya::maps::HashMap<_, u32, u8> = map
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Failed to get SOCKET_FD_MAP"))?;
                    socket_fd_map
                        .insert(&(fd_info.fd as u32), &1, 0)
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to insert fd {} into SOCKET_FD_MAP: {}",
                                fd_info.fd,
                                e
                            )
                        })?;
                    debug!(
                        "Inserted fd {} (process {}) into SOCKET_FD_MAP",
                        fd_info.fd, pid
                    );
                } else {
                    warn!("SOCKET_FD_MAP not found");
                }
            }

            if socket_count > 0 {
                debug!(
                    "Found {} Unix socket(s) in process {} (PID {})",
                    socket_count, process_name, pid
                );
            }
        }
    }

    Ok(())
}
