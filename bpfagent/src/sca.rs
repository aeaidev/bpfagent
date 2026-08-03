use std::{any::Any, collections::HashSet, sync::Arc};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::{debug, info, warn};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::program::{EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Prometheus metrics for SCA program
pub struct ScaMetrics {
    pub max_latency_per_pid: IntGaugeVec,
}

impl ScaMetrics {
    pub fn new(registry: Arc<Registry>) -> Self {
        let max_latency_per_pid = IntGaugeVec::new(
            Opts::new(
                "sca_max_latency_per_pid",
                "Maximum latency in microseconds per PID",
            ),
            &["pid"],
        )
        .expect("failed to create max_latency_per_pid gauge");
        registry
            .register(Box::new(max_latency_per_pid.clone()))
            .expect("failed to register max_latency_per_pid gauge");

        Self {
            max_latency_per_pid,
        }
    }
}

/// BPF program wrapper for SCA (tracing socket communication for latency analysis)
pub struct ScaProgram {
    name: String,
    ebpf: Option<Ebpf>,
    seen_pids: HashSet<u32>,
    metrics: Option<ScaMetrics>,
}

impl ScaProgram {
    /// Creates a new SCA BPF program
    pub fn new() -> Self {
        Self {
            name: "sca".to_string(),
            ebpf: None,
            seen_pids: HashSet::new(),
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

        // Cache processes once
        let processes = get_processes_by_name();

        // Initialize process names map
        populate_process_names_map(&mut ebpf, sca_common::PROCESS_NAMES)?;

        // Populate socket fd map from running processes
        populate_socket_fd_map(&mut ebpf, &processes, sca_common::SOCKET_PATHS)?;

        // Populate LATENCY_PID_HASH with PIDs of running processes and value 0
        populate_latency_pid_hash(&mut ebpf, &processes)?;

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
        let metrics = ScaMetrics::new(registry);
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

        if let Some(map) = ebpf.map("LATENCY_PID_HASH") {
            let latency_map: HashMap<_, u32, u64> = map.try_into().unwrap();
            info!("--- Max Latency per PID ---");

            // Try to get all entries using the iter method
            for entry in latency_map.iter() {
                match entry {
                    Ok((pid, latency)) => {
                        self.seen_pids.insert(pid);
                        let latency_us = latency / 1000; // covert nano to micro
                        info!("  PID {}: {} us", pid, latency_us);

                        // Update Prometheus metrics with max latency in microseconds
                        metrics
                            .max_latency_per_pid
                            .with_label_values(&[&pid.to_string()])
                            .set(latency_us as i64);
                    }
                    Err(e) => {
                        debug!("Failed to read entry: {}", e);
                    }
                }
            }

            if self.seen_pids.is_empty() {
                debug!("No PIDs with latency data yet");
            } else {
                debug!("Total unique PIDs seen: {}", self.seen_pids.len());
            }
        } else {
            warn!("LATENCY_PID_HASH not found");
        }

        Ok(())
    }
}

impl Default for ScaProgram {
    fn default() -> Self {
        Self::new()
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

/// Populate LATENCY_PID_HASH with PIDs of running processes and value 0
fn populate_latency_pid_hash(
    ebpf: &mut Ebpf,
    processes: &std::collections::HashMap<&'static str, Vec<u32>>,
) -> anyhow::Result<()> {
    debug!("Populating LATENCY_PID_HASH with PIDs from allowed processes");

    if let Some(map) = ebpf.map_mut("LATENCY_PID_HASH") {
        let mut latency_pid_map: aya::maps::HashMap<_, u32, u64> = map
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to get LATENCY_PID_HASH"))?;

        for process_name in sca_common::PROCESS_NAMES {
            for pid in processes.get(process_name).cloned().unwrap_or_default() {
                // Only insert if not already present
                match latency_pid_map.get(&pid, 0) {
                    Ok(_) => {
                        debug!("PID {} already in LATENCY_PID_HASH, skipping", pid);
                    }
                    Err(_) => {
                        latency_pid_map.insert(&pid, &0, 0).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to insert PID {} into LATENCY_PID_HASH: {}",
                                pid,
                                e
                            )
                        })?;
                        debug!("Inserted PID {} with value 0 into LATENCY_PID_HASH", pid);
                    }
                }
            }
        }
    } else {
        warn!("LATENCY_PID_HASH not found");
    }

    Ok(())
}

/// Populate SOCKET_FD_MAP with file descriptors from all Unix sockets
fn populate_socket_fd_map(
    ebpf: &mut Ebpf,
    processes: &std::collections::HashMap<&'static str, Vec<u32>>,
    _socket_paths: &[&str],
) -> anyhow::Result<()> {
    debug!("Populating SOCKET_FD_MAP with all Unix socket fds from allowed processes");

    // Populate SOCKET_FD_MAP from process file descriptors
    for process_name in sca_common::PROCESS_NAMES {
        for pid in processes.get(process_name).cloned().unwrap_or_default() {
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

/// Get processes by name
fn get_processes_by_name() -> std::collections::HashMap<&'static str, Vec<u32>> {
    let mut process_map: std::collections::HashMap<&'static str, Vec<u32>> =
        std::collections::HashMap::new();

    for name in sca_common::PROCESS_NAMES.iter() {
        let mut pids = Vec::new();

        for entry in procfs::process::all_processes().expect("Failed to get all processes") {
            let process = entry.expect("Failed to get process");
            let stat = process.stat().expect("Failed to get process stat");
            if stat.comm == *name {
                pids.push(process.pid as u32);
            }
        }

        if pids.is_empty() {
            debug!("No processes found for name {}", name);
        } else {
            debug!("Found {} PIDs for process {}", pids.len(), name);
        }

        process_map.insert(*name, pids);
    }

    process_map
}
