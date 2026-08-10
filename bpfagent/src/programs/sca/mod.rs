//! SCA (Socket Communication Analyzer) eBPF Program - Socket Latency Tracing
//!
//! This module provides a BPF program that traces socket communication latency
//! by measuring the timestamp difference between NNG protocol messages.
//!
//! The eBPF program attaches to various tracepoints (sendmsg, write, etc.) and
//! uses a key of Protocol to match REQ/REP message pairs on Unix domain sockets.
//!
//! # Latency Calculation
//!
//! - First send (to listening socket): stores timestamp with key = Protocol
//! - Second send (from listening socket as response): looks up with same Protocol key
//! - Latency is calculated as the timestamp difference on match
//!
//! # Moving Average
//!
//! Latencies are tracked using a sliding window moving average:
//! - Maintains sum and count of latencies within a 2-second window
//! - Average = sum / count
//! - Window resets when more than 2 seconds have elapsed
//!
//! Prometheus Metrics
//!
//! - `sca_avg_latency_per_pname`: Moving average latency in microseconds per process name

use std::{any::Any, collections::HashSet, sync::Arc};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::{debug, error, info, trace, warn};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Module re-exports for convenience
use sca_common;

/// SocketHop type from common - used for both userspace and eBPF
/// The struct layout must match between userspace and eBPF
/// Since both define it as #[repr(C)] with the same u32 fields, they are binary compatible
pub use sca_common::SocketHop;

/// Prometheus metrics for SCA program
pub struct ScaMetrics {
    pub avg_latency_per_pname: IntGaugeVec,
}

impl ScaMetrics {
    /// Create new SCA Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let avg_latency_per_pname = IntGaugeVec::new(
            Opts::new(
                "sca_avg_latency_per_pname",
                "Average latency in microseconds per process name",
            ),
            &["pname"],
        )
        .map_err(|e| anyhow::anyhow!("failed to create avg_latency_per_pname gauge: {}", e))?;

        registry
            .register(Box::new(avg_latency_per_pname.clone()))
            .map_err(|e| {
                anyhow::anyhow!("failed to register avg_latency_per_pname gauge: {}", e)
            })?;

        Ok(Self {
            avg_latency_per_pname,
        })
    }
}

/// BPF program wrapper for SCA (tracing socket communication for latency analysis)
pub struct ScaProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<ScaMetrics>,
    /// Mapping of FD to socket path for display metrics
    socket_fd_map: std::collections::HashMap<u32, String>,
    /// Mapping of PID to process name for display metrics
    socket_pid_map: std::collections::HashMap<u32, String>,
}

impl ScaProgram {
    /// Creates a new SCA BPF program
    pub fn new() -> Self {
        Self {
            name: "sca".to_string(),
            ebpf: None,
            metrics: None,
            socket_fd_map: std::collections::HashMap::new(),
            socket_pid_map: std::collections::HashMap::new(),
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

        debug!("Loaded BPF program, pre-populating SOCKET_HOPS_MAP...");

        // Pre-populate SOCKET_HOPS_MAP with default values based on DATA_FLOW
        prepopulate_socket_hops_map(&mut ebpf)?;

        // Populate socket fd map from running processes
        // This also populates socket_fd_map and socket_pid_map for metrics display
        populate_socket_fd_map(&mut self.socket_fd_map, &mut self.socket_pid_map, &mut ebpf)?;

        debug!("SOCKET_HOPS_MAP populated, now attaching tracepoints...");

        // Load and attach tracepoints AFTER map is populated
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

        // Read sum and count from separate maps (PID-based)
        let sum_map: HashMap<_, u32, u64> = ebpf
            .map("LATENCY_PID_SUM")
            .ok_or_else(|| anyhow::anyhow!("LATENCY_PID_SUM not found"))?
            .try_into()?;

        let count_map: HashMap<_, u32, u64> = ebpf
            .map("LATENCY_PID_COUNT")
            .ok_or_else(|| anyhow::anyhow!("LATENCY_PID_COUNT not found"))?
            .try_into()?;

        // Check if tracepoint is being called
        let tracepoint_counter_map: HashMap<_, u32, u64> = ebpf
            .map("TRACEPOINT_COUNTER")
            .ok_or_else(|| anyhow::anyhow!("TRACEPOINT_COUNTER not found"))?
            .try_into()?;
        match tracepoint_counter_map.get(&0, 0) {
            Ok(count) => trace!("TRACEPOINT_COUNTER: {}", count),
            Err(_) => trace!("TRACEPOINT_COUNTER: 0 (no entries)"),
        }

        info!("--- Moving Average Latency per PID ---");

        // Get all PIDs from the maps and calculate averages
        let mut all_pids: HashSet<u32> = HashSet::new();
        for result in sum_map.iter() {
            let (pid, _) =
                result.map_err(|e| anyhow::anyhow!("Failed to iterate LATENCY_PID_SUM: {}", e))?;
            all_pids.insert(pid);
        }
        for result in count_map.iter() {
            let (pid, _) = result
                .map_err(|e| anyhow::anyhow!("Failed to iterate LATENCY_PID_COUNT: {}", e))?;
            all_pids.insert(pid);
        }

        for pid in all_pids {
            let sum = sum_map.get(&pid, 0).unwrap_or(0);
            let count = count_map.get(&pid, 0).unwrap_or(0);

            // Calculate average latency
            let avg_latency = if count > 0 { sum / count } else { 0 };
            let avg_latency_us = avg_latency / 1000; // convert nano to micro

            // Get process name from socket_pid_map, default to "unknown"
            let process_name = self
                .socket_pid_map
                .get(&pid)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            // Get socket path if available
            let socket_path = self
                .socket_fd_map
                .iter()
                .find(|(_, path)| path.contains(&format!("{}", pid)))
                .map(|(_, path)| path.as_str())
                .unwrap_or("");

            info!(
                "  {} (PID {}): {} us (count: {}){}",
                process_name,
                pid,
                avg_latency_us,
                count,
                if !socket_path.is_empty() {
                    format!(" path={}", socket_path)
                } else {
                    String::new()
                }
            );

            // Update Prometheus metrics with average latency in microseconds
            let label = format!("{} (PID {})", process_name, pid);
            metrics
                .avg_latency_per_pname
                .with_label_values(&[&label])
                .set(avg_latency_us as i64);
        }

        debug!("Displaying moving average latency per PID");
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

/**
 * Pre-populate SOCKET_HOPS_MAP with default (zeroed) values based on DATA_FLOW configuration.
 * This ensures the map has entries for all configured socket hops, even if FDs aren't found yet.
 */
fn prepopulate_socket_hops_map(_ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // SOCKET_HOPS_MAP is now populated directly in populate_socket_fd_map
    // This function is kept for potential future pre-initialization if needed
    Ok(())
}

/**
 * Populate SOCKET_HOPS_MAP with file descriptors from Unix sockets.
 * Reads lsof output to find socket FDs and their associated PIDs,
 * then populates SOCKET_HOPS_MAP with FD/PID configurations.
 *
 * The SOCKET_HOPS_MAP BPF map is shared between eBPF and userspace.
 * Userspace populates SOCKET_HOPS_MAP with FD/PID configurations,
 * eBPF reads from SOCKET_HOPS_MAP to get hop configurations.
 *
 * Also populates local socket_fd_map and socket_pid_map for metrics display.
 */
fn populate_socket_fd_map(
    socket_fd_map: &mut std::collections::HashMap<u32, String>,
    socket_pid_map: &mut std::collections::HashMap<u32, String>,
    ebpf: &mut Ebpf,
) -> anyhow::Result<()> {
    debug!("Populating SOCKET_HOPS_MAP with Unix socket fds from running processes");

    // Get all PIDs from DATA_FLOW by reading /proc/*/comm
    // We need to collect PIDs for both sending and receiving processes
    let mut process_pid_map: std::collections::HashMap<&str, u32> =
        std::collections::HashMap::new();
    for (_socket_path, sending, receiving) in sca_common::DATA_FLOW {
        for &process_name in &[sending, receiving] {
            if !process_pid_map.contains_key(process_name) {
                if let Some(pid) = get_pid_by_process_name(process_name) {
                    process_pid_map.insert(process_name, pid);
                    info!("Found PID {} for process {}", pid, process_name);
                }
            }
        }
    }

    // Run lsof to get socket FDs from running processes
    // Parse PID, FD, and socket path from lsof output
    // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // Filter for type=STREAM (CONNECTED) Unix sockets only
    // The TYPE info is in fields 10-11: 'type=STREAM (CONNECTED)'
    // Note: FD is in field 4, socket path is in field 9
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"sudo -n lsof 2>/dev/null | awk '$4 ~ /u$/ && $10 ~ /type=STREAM/ && $11 ~ /CONNECTED/ {gsub(/u$/,"",$4); print "PID:"$2" FD:"$4" "$9}' | grep -E '/tmp/(DATA_L3_TO|DATA_L_TO|WF_L_TO|FRAG_TO|IRSS_L_TO)'"#)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run lsof command: {}", e))?;

    if !output.status.success() {
        warn!(
            "lsof command failed, stdout: {}, stderr: {:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Continue anyway - the map might be empty but not an error
    }

    // Debug: log the raw lsof output
    debug!(
        "Raw lsof output: stdout='{}', stderr='{}'",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Parse lsof output and build FD -> (pid, socket_path) map
    // Only include FDs that belong to interesting processes from DATA_FLOW
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut fd_to_info: std::collections::HashMap<u32, (u32, String)> =
        std::collections::HashMap::new();

    for line in stdout.lines() {
        // Parse lines like: "PID:1234 FD:5 /tmp/DATA_L3_TO_INTERNAL_ROUTER"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            // Extract PID
            let pid_part = parts.get(0).unwrap_or(&"");
            let pid_str = pid_part.strip_prefix("PID:").unwrap_or("");
            let pid = pid_str.parse::<u32>().ok();

            // Extract FD
            let fd_part = parts.get(1).unwrap_or(&"");
            let fd_str = fd_part.strip_prefix("FD:").unwrap_or("");
            let fd = fd_str.parse::<u32>().ok();

            // Extract socket path
            let socket_path = parts.get(2).unwrap_or(&"").to_string();

            if let (Some(pid), Some(fd)) = (pid, fd) {
                // Check if this PID is one of the interesting processes from DATA_FLOW
                let is_interesting = sca_common::DATA_FLOW.iter().any(|(_, sending, receiving)| {
                    process_pid_map.get(sending) == Some(&pid)
                        || process_pid_map.get(receiving) == Some(&pid)
                });

                if is_interesting {
                    fd_to_info.insert(fd, (pid, socket_path.clone()));
                    info!("Found FD {} (PID {}) for path {}", fd, pid, socket_path);
                }
            }
        }
    }

    debug!("Found {} interesting socket FDs", fd_to_info.len());
    debug!("fd_to_info contents: {:?}", fd_to_info);

    // Populate SOCKET_HOPS_MAP
    // Use FD as the key for direct lookup in eBPF
    let socket_hops_map_name = "SOCKET_HOPS_MAP";

    // Get reference to the map
    if let Some(map) = ebpf.map_mut(socket_hops_map_name) {
        debug!("SOCKET_HOPS_MAP found");
        // Convert to HashMap to work with it
        let mut hops_map: HashMap<_, u32, SocketHop> = map
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to get SOCKET_HOPS_MAP"))?;

        debug!(
            "SOCKET_HOPS_MAP max entries: {}",
            sca_common::SOCKET_HOPS_MAP_MAX_ENTRIES
        );

        debug!(
            "About to insert {} entries into SOCKET_HOPS_MAP",
            fd_to_info.len()
        );

        for (fd, (_pid, socket_path)) in fd_to_info.iter() {
            // For each socket path, we need to determine sending and receiving PIDs
            // We'll use the DATA_FLOW configuration to find matching entries
            for (_hop_key, (flow_path, sending, receiving)) in
                sca_common::DATA_FLOW.iter().enumerate()
            {
                if *flow_path == socket_path.as_str() {
                    // Get the actual PIDs for sending and receiving processes
                    let s_pid = process_pid_map.get(sending).copied();
                    let r_pid = process_pid_map.get(receiving).copied();

                    if let (Some(s_pid), Some(r_pid)) = (s_pid, r_pid) {
                        // Update local socket_fd_map with FD -> path mapping
                        socket_fd_map.insert(*fd, socket_path.clone());
                        info!("Added to socket_fd_map: fd={} -> path={}", fd, socket_path);

                        // Update local socket_pid_map with PID -> process name mapping
                        // Names are used in display metrics only
                        socket_pid_map.insert(s_pid, sending.to_string());
                        socket_pid_map.insert(r_pid, receiving.to_string());
                        info!(
                            "Added to socket_pid_map: s_pid={} -> {}, r_pid={} -> {}",
                            s_pid, sending, r_pid, receiving
                        );

                        // Create the hop with the FD and PIDs
                        let hop = SocketHop {
                            listening_socket_fd: *fd,
                            sending_process_id: s_pid,
                            receiving_process_id: r_pid,
                        };

                        // Write to SOCKET_HOPS_MAP using FD as the key
                        debug!(
                            "Attempting to insert hop with fd {} into SOCKET_HOPS_MAP",
                            fd
                        );
                        match hops_map.insert(fd, &hop, 0) {
                            Ok(()) => info!(
                                "Added to SOCKET_HOPS_MAP with fd {}: sending_pid={}, receiving_pid={}, path={}",
                                fd, s_pid, r_pid, socket_path
                            ),
                            Err(e) => error!(
                                "Failed to insert hop with fd {} into SOCKET_HOPS_MAP: {}",
                                fd, e
                            ),
                        };
                    }
                }
            }
        }
    } else {
        warn!("SOCKET_HOPS_MAP not found");
    }
    Ok(())
}

/// Get PID from process name by reading /proc/*/comm
fn get_pid_by_process_name(process_name: &str) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let dir_name = entry.file_name();
        let pid_str = dir_name.to_string_lossy();

        // Skip non-numeric directories
        if pid_str.parse::<u32>().is_err() {
            continue;
        }

        // Read comm file to get process name
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            // comm file contains process name with newline
            let comm = comm.trim();
            if comm == process_name {
                return pid_str.parse::<u32>().ok();
            }
        }
    }
    None
}
