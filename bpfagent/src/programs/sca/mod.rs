//! SCA (Socket Communication Analyzer) eBPF Program - Socket Latency Tracing
//!
//! This module provides a BPF program that traces socket communication latency
//! by measuring the timestamp difference between NNG protocol messages.
//!
//! The eBPF program attaches to sys_enter_sendmsg and uses the NNG Protocol
//! field plus the hop index to match REQ/REP message pairs on Unix domain
//! sockets.
//!
//! # Latency Calculation
//!
//! - Hop endpoints are tracked in SOCKET_HOPS_MAP keyed by (pid << 32) | fd,
//!   which is unambiguous because fd numbers are per-process. Each hop has a
//!   sender endpoint (its connected fd) and a receiver endpoint (its accepted
//!   fd). Userspace discovers both via `ss -xp` peer-inode pairing.
//! - First send (sender sends TO the listening socket): stores timestamp with
//!   key = (hop_index << 32) | Protocol
//! - Second send (receiver sends FROM the listening socket as response): looks
//!   up the timestamp with the same key
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

/// HopEndpoint type from common - used for both userspace and eBPF
/// The struct layout must match between userspace and eBPF
/// Since both define it as #[repr(C)] with the same u32 fields, they are binary compatible
pub use sca_common::HopEndpoint;

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
    /// Mapping of PID to the hop socket path(s) it receives on, for display
    socket_path_map: std::collections::HashMap<u32, String>,
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
            socket_path_map: std::collections::HashMap::new(),
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

        debug!("Loaded BPF program, populating SOCKET_HOPS_MAP...");

        // Populate SOCKET_HOPS_MAP with (pid, fd) -> HopEndpoint entries
        // discovered from running processes. Also populates socket_path_map
        // and socket_pid_map for metrics display.
        populate_socket_hops_map(&mut self.socket_path_map, &mut self.socket_pid_map, &mut ebpf)?;

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
        let sum_map = open_pid_map(ebpf, "LATENCY_PID_SUM")?;
        let count_map = open_pid_map(ebpf, "LATENCY_PID_COUNT")?;

        // Check if tracepoint is being called
        let tracepoint_counter_map = open_pid_map(ebpf, "TRACEPOINT_COUNTER")?;
        match tracepoint_counter_map.get(&0, 0) {
            Ok(count) => trace!("TRACEPOINT_COUNTER: {}", count),
            Err(_) => trace!("TRACEPOINT_COUNTER: 0 (no entries)"),
        }

        info!("--- Moving Average Latency per PID ---");

        for pid in collect_pids(&sum_map, &count_map)? {
            let sum = sum_map.get(&pid, 0).unwrap_or(0);
            let count = count_map.get(&pid, 0).unwrap_or(0);
            report_pid_latency(
                metrics,
                &self.socket_pid_map,
                &self.socket_path_map,
                pid,
                sum,
                count,
            );
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

/// One established Unix stream socket parsed from `ss -xpH` output.
pub struct UnixSockRec {
    pub pid: u32,
    pub fd: u32,
    pub inode: u64,
    pub peer_inode: u64,
    /// Bound path if the socket has one; the connected (client) side has none
    pub path: Option<String>,
}

/// Parse the users:((...)) column of ss output into (pid, fd) pairs.
/// Format: users:(("NAME",pid=123,fd=4),("NAME2",pid=456,fd=7))
pub fn parse_ss_users(users: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut rest = users;
    while let Some(pos) = rest.find("pid=") {
        rest = &rest[pos + 4..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(pid) = digits.parse::<u32>() else {
            break;
        };
        let Some(fd_pos) = rest.find("fd=") else {
            break;
        };
        rest = &rest[fd_pos + 3..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(fd) = digits.parse::<u32>() else {
            break;
        };
        out.push((pid, fd));
    }
    out
}

/// Parse `ss -xpH` output into established Unix stream socket records.
///
/// Line format (9+ whitespace-separated fields):
/// u_str ESTAB Recv-Q Send-Q <path|*> <inode> * <peer-inode> users:((...))
pub fn parse_ss_unix_stream(output: &str) -> Vec<UnixSockRec> {
    let mut recs = Vec::new();
    for line in output.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 9 || t[0] != "u_str" || t[1] != "ESTAB" {
            continue;
        }
        let (Ok(inode), Ok(peer_inode)) = (t[5].parse::<u64>(), t[7].parse::<u64>()) else {
            continue;
        };
        let path = if t[4] == "*" {
            None
        } else {
            Some(t[4].to_string())
        };
        for (pid, fd) in parse_ss_users(&t[8..].join(" ")) {
            recs.push(UnixSockRec {
                pid,
                fd,
                inode,
                peer_inode,
                path: path.clone(),
            });
        }
    }
    recs
}

/// Open a u32 -> u64 BPF hash map by name.
fn open_pid_map<'a>(
    ebpf: &'a Ebpf,
    name: &str,
) -> anyhow::Result<HashMap<&'a aya::maps::MapData, u32, u64>> {
    ebpf.map(name)
        .ok_or_else(|| anyhow::anyhow!("{} map not found", name))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to open {} map: {}", name, e))
}

/// Collect all PIDs present in either latency map.
fn collect_pids(
    sum_map: &HashMap<&aya::maps::MapData, u32, u64>,
    count_map: &HashMap<&aya::maps::MapData, u32, u64>,
) -> anyhow::Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    for result in sum_map.iter().chain(count_map.iter()) {
        let (pid, _) =
            result.map_err(|e| anyhow::anyhow!("failed to iterate latency maps: {}", e))?;
        pids.insert(pid);
    }
    Ok(pids)
}

/// Compute the moving average latency for a PID, print it, and update the gauge.
fn report_pid_latency(
    metrics: &ScaMetrics,
    socket_pid_map: &std::collections::HashMap<u32, String>,
    socket_path_map: &std::collections::HashMap<u32, String>,
    pid: u32,
    sum: u64,
    count: u64,
) {
    let avg_latency_us = sum.checked_div(count).unwrap_or(0) / 1000; // ns -> us

    let process_name = socket_pid_map
        .get(&pid)
        .map(String::as_str)
        .unwrap_or("unknown");
    let socket_path = socket_path_map.get(&pid).map(String::as_str).unwrap_or("");

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

    let label = format!("{} (PID {})", process_name, pid);
    metrics
        .avg_latency_per_pname
        .with_label_values(&[&label])
        .set(avg_latency_us as i64);
}

/// Resolve the PIDs of all processes named in DATA_FLOW by scanning /proc.
fn collect_data_flow_pids() -> std::collections::HashMap<&'static str, u32> {
    let mut pids = std::collections::HashMap::new();
    for &(_socket_path, sending, receiving) in sca_common::DATA_FLOW {
        for process_name in [sending, receiving] {
            if let std::collections::hash_map::Entry::Vacant(entry) = pids.entry(process_name) {
                if let Some(pid) = get_pid_by_process_name(process_name) {
                    entry.insert(pid);
                    info!("Found PID {} for process {}", pid, process_name);
                }
            }
        }
    }
    pids
}

/// Run `ss -xpH` and parse the established Unix stream sockets.
fn query_established_unix_sockets() -> anyhow::Result<Vec<UnixSockRec>> {
    let output = std::process::Command::new("ss")
        .arg("-xpH")
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ss -xpH: {}", e))?;
    if !output.status.success() {
        warn!(
            "ss -xpH failed, stderr: {:?} — SCA hop discovery may be incomplete",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_ss_unix_stream(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Build an inode -> path index, used to resolve the peer of path-less
/// client sockets.
pub fn paths_by_inode(sockets: &[UnixSockRec]) -> std::collections::HashMap<u64, &str> {
    sockets
        .iter()
        .filter_map(|s| s.path.as_deref().map(|p| (s.inode, p)))
        .collect()
}

/// Decide whether `sock` is an endpoint of the hop between `s_pid` and `r_pid`
/// on `path`, and if so, with which role.
///
/// Returns Some(1) for the sender endpoint and Some(0) for the receiver:
/// the receiver's accepted socket carries the hop path directly, while the
/// sender's connected socket has no path of its own and is resolved via its
/// peer inode (the receiver's accepted socket).
pub fn endpoint_role(
    sock: &UnixSockRec,
    s_pid: u32,
    r_pid: u32,
    path: &str,
    path_by_inode: &std::collections::HashMap<u64, &str>,
) -> Option<u32> {
    if sock.pid == r_pid && sock.path.as_deref() == Some(path) {
        Some(0)
    } else if sock.pid == s_pid
        && sock.path.is_none()
        && path_by_inode.get(&sock.peer_inode) == Some(&path)
    {
        Some(1)
    } else {
        None
    }
}

/// Insert one (pid, fd) -> HopEndpoint entry into SOCKET_HOPS_MAP.
/// Returns true on success.
fn insert_endpoint(
    hops_map: &mut HashMap<&mut aya::maps::MapData, u64, HopEndpoint>,
    hop_index: u32,
    sock: &UnixSockRec,
    is_sender: u32,
    path: &str,
) -> bool {
    let key = ((sock.pid as u64) << 32) | (sock.fd as u64);
    let mut path_bytes = [0u8; 32];
    let n = path.len().min(32);
    path_bytes[..n].copy_from_slice(&path.as_bytes()[..n]);
    let endpoint = HopEndpoint {
        hop_index,
        is_sender,
        path: path_bytes,
    };
    match hops_map.insert(&key, &endpoint, 0) {
        Ok(()) => {
            info!(
                "Added hop {} endpoint: pid={}, fd={}, is_sender={}, path={}",
                hop_index, sock.pid, sock.fd, is_sender, path
            );
            true
        }
        Err(e) => {
            error!(
                "Failed to insert hop {} endpoint (pid={}, fd={}): {}",
                hop_index, sock.pid, sock.fd, e
            );
            false
        }
    }
}

/**
 * Populate SOCKET_HOPS_MAP with (pid, fd) -> HopEndpoint entries.
 *
 * Discovery uses `ss -xp` peer-inode pairing (see endpoint_role).
 * Also populates socket_path_map and socket_pid_map for metrics display.
 */
fn populate_socket_hops_map(
    socket_path_map: &mut std::collections::HashMap<u32, String>,
    socket_pid_map: &mut std::collections::HashMap<u32, String>,
    ebpf: &mut Ebpf,
) -> anyhow::Result<()> {
    debug!("Populating SOCKET_HOPS_MAP from running processes via ss");

    let process_pid_map = collect_data_flow_pids();
    let sockets = query_established_unix_sockets()?;
    let path_by_inode = paths_by_inode(&sockets);

    let Some(map) = ebpf.map_mut("SOCKET_HOPS_MAP") else {
        return Err(anyhow::anyhow!("SOCKET_HOPS_MAP not found"));
    };
    let mut hops_map: HashMap<_, u64, HopEndpoint> = map
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to get SOCKET_HOPS_MAP"))?;

    for (hop_index, (path, sending, receiving)) in sca_common::DATA_FLOW.iter().enumerate() {
        let (Some(&s_pid), Some(&r_pid)) = (
            process_pid_map.get(sending),
            process_pid_map.get(receiving),
        ) else {
            warn!(
                "Skipping hop {} ({}): {} or {} not running",
                hop_index, path, sending, receiving
            );
            continue;
        };

        socket_pid_map.insert(s_pid, sending.to_string());
        socket_pid_map.insert(r_pid, receiving.to_string());
        socket_path_map
            .entry(r_pid)
            .and_modify(|p| {
                if !p.is_empty() {
                    p.push_str(", ");
                }
                p.push_str(path);
            })
            .or_insert_with(|| path.to_string());

        let mut found = false;
        for sock in &sockets {
            if let Some(role) = endpoint_role(sock, s_pid, r_pid, path, &path_by_inode) {
                found |= insert_endpoint(&mut hops_map, hop_index as u32, sock, role, path);
            }
        }
        if !found {
            warn!(
                "No endpoints found for hop {} ({}): sockets of {} (pid {}) / {} (pid {}) not visible",
                hop_index, path, sending, s_pid, receiving, r_pid
            );
        }
    }
    Ok(())
}

/// Get PID from process name by reading /proc/*/comm
fn get_pid_by_process_name(process_name: &str) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        // Skip unreadable entries instead of aborting the whole scan
        let Ok(entry) = entry else {
            continue;
        };
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
