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
//! - Raw latency is the timestamp difference on match. Because a receiver's
//!   response goes out only after the downstream hop completed, the raw value
//!   accumulates the rest of the chain, so the downstream hop's latency for
//!   the same message (LATENCY_HOP_MAP) is subtracted: the reported latency
//!   is each hop's individual contribution.
//!
//! # Moving Average
//!
//! Latencies are tracked using a sliding window moving average:
//! - Maintains sum and count of latencies within a 2-second window
//! - Average = sum / count
//! - Window resets when more than 2 seconds have elapsed
//! - A PID is reported only while new samples keep arriving: once its
//!   sum/count stop changing between display ticks (traffic paused or
//!   processes gone) it is dropped from the output and its Prometheus
//!   series is removed
//!
//! # Process Restart
//!
//! When no fresh samples arrive while PIDs are still tracked, the traced
//! processes have likely restarted, invalidating their PIDs and socket fds.
//! Endpoint discovery then re-runs (rate-limited): entries keyed by dead
//! PIDs are evicted from SOCKET_HOPS_MAP and the per-PID latency maps, and
//! SOCKET_HOPS_MAP is repopulated from the new processes.
//!
//! Prometheus Metrics
//!
//! - `sca_avg_latency_per_pname`: Moving average latency in microseconds per process name

use std::{any::Any, collections::HashSet, sync::Arc, time::{Duration, Instant}};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::{debug, error, info, warn};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

mod helpers;

/// Module re-exports for convenience
use sca_common;

/// HopEndpoint type from common - used for both userspace and eBPF
/// The struct layout must match between userspace and eBPF
/// Since both define it as #[repr(C)] with the same u32 fields, they are binary compatible
pub use sca_common::HopEndpoint;

pub use helpers::{UnixSockRec, parse_ss_unix_stream, parse_ss_users, paths_by_inode};
use helpers::{get_pid_by_process_name, query_established_unix_sockets};

/// Minimum interval between endpoint-rediscovery attempts while no fresh
/// latency samples arrive (the likely sign of restarted processes).
const REPOPULATION_INTERVAL: Duration = Duration::from_secs(5);

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
                "Average individual hop latency in microseconds per process name",
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
    /// Freshness ledger: state and last seen (sum, count) per PID. A PID
    /// whose counters did not change has no new samples and is not reported.
    last_samples: std::collections::HashMap<u32, SampleState>,
    /// Last time endpoint rediscovery ran while the data flow was quiet
    /// (rate limiting); None if it never ran.
    last_repopulation: Option<Instant>,
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
            last_samples: std::collections::HashMap::new(),
            last_repopulation: None,
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

        // Snapshot the current (sum, count) per PID.
        let mut samples = std::collections::HashMap::new();
        for pid in collect_pids(&sum_map, &count_map)? {
            let sum = sum_map.get(&pid, 0).unwrap_or(0);
            let count = count_map.get(&pid, 0).unwrap_or(0);
            samples.insert(pid, (sum, count));
        }

        // The eBPF window only advances when new samples arrive, so a PID
        // whose counters stopped changing (traffic paused or processes gone)
        // would otherwise be reported forever with its last average.
        let (fresh, newly_stale) = partition_fresh(&mut self.last_samples, &samples);

        // Drop the Prometheus series of PIDs that just went quiet so the
        // exported metrics go quiet together with the log output.
        for pid in newly_stale {
            let label = latency_label(&self.socket_pid_map, pid);
            if let Err(e) = metrics.avg_latency_per_pname.remove_label_values(&[&label]) {
                debug!("failed to remove stale latency series {}: {}", label, e);
            }
        }

        if fresh.is_empty() {
            // No latency updates at all: the traced processes were likely
            // restarted, invalidating their PIDs and socket fds. Rediscover
            // endpoints (rate-limited) so tracing resumes without an agent
            // restart. This also fires on a mere traffic pause or right at
            // agent startup, but rediscovery is idempotent: it finds the
            // same endpoints and changes nothing.
            if self
                .last_repopulation
                .map_or(true, |t| t.elapsed() >= REPOPULATION_INTERVAL)
            {
                self.last_repopulation = Some(Instant::now());
                if let Err(e) = repopulate_socket_hops_map(
                    &mut self.socket_path_map,
                    &mut self.socket_pid_map,
                    ebpf,
                ) {
                    warn!("endpoint rediscovery failed: {}", e);
                }
            }
            debug!("No fresh latency samples, nothing to display");
            return Ok(());
        }

        info!("--- Moving Average Latency per PID ---");
        for pid in fresh {
            let (sum, count) = samples[&pid];
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

/// Freshness state of a PID's latency samples, tracked across display ticks.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SampleState {
    /// Reported on the previous tick; holds the last seen (sum, count).
    Fresh(u64, u64),
    /// Already dropped from the output and metrics; holds the last seen
    /// (sum, count).
    Cleared(u64, u64),
}

/// Split latency samples into PIDs with new samples since the previous tick
/// (fresh) and PIDs that just went quiet (newly stale: their counters did
/// not change since a tick where they were still fresh), updating the
/// ledger. PIDs that stay quiet across further ticks remain in the ledger as
/// cleared and are reported in neither list, so their Prometheus series is
/// removed exactly once. Ledger entries for PIDs no longer present in the
/// maps are dropped.
pub fn partition_fresh(
    ledger: &mut std::collections::HashMap<u32, SampleState>,
    samples: &std::collections::HashMap<u32, (u64, u64)>,
) -> (Vec<u32>, Vec<u32>) {
    ledger.retain(|pid, _| samples.contains_key(pid));
    let mut fresh = Vec::new();
    let mut newly_stale = Vec::new();
    for (&pid, &current) in samples {
        match ledger.get(&pid).copied() {
            Some(SampleState::Fresh(sum, count)) if (sum, count) == current => {
                ledger.insert(pid, SampleState::Cleared(current.0, current.1));
                newly_stale.push(pid);
            }
            Some(SampleState::Cleared(sum, count)) if (sum, count) == current => {
                // Still quiet and already dropped: nothing to do.
            }
            _ => {
                ledger.insert(pid, SampleState::Fresh(current.0, current.1));
                fresh.push(pid);
            }
        }
    }
    (fresh, newly_stale)
}

/// Prometheus series label for a PID: "<process name> (PID <pid>)".
fn latency_label(socket_pid_map: &std::collections::HashMap<u32, String>, pid: u32) -> String {
    let process_name = socket_pid_map
        .get(&pid)
        .map(String::as_str)
        .unwrap_or("unknown");
    format!("{} (PID {})", process_name, pid)
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

    let label = latency_label(socket_pid_map, pid);
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

/**
 * Re-run endpoint discovery after the traced processes restarted.
 *
 * Entries keyed by dead PIDs are evicted first: SOCKET_HOPS_MAP has room
 * for exactly one sender and one receiver fd per hop, and the per-PID
 * latency maps (16 entries each) would otherwise fill up with dead PIDs
 * across restarts, silently dropping new samples. The display maps are
 * then rebuilt from scratch by populate_socket_hops_map.
 */
fn repopulate_socket_hops_map(
    socket_path_map: &mut std::collections::HashMap<u32, String>,
    socket_pid_map: &mut std::collections::HashMap<u32, String>,
    ebpf: &mut Ebpf,
) -> anyhow::Result<()> {
    let live_pids: HashSet<u32> = collect_data_flow_pids().into_values().collect();

    {
        let Some(map) = ebpf.map_mut("SOCKET_HOPS_MAP") else {
            return Err(anyhow::anyhow!("SOCKET_HOPS_MAP not found"));
        };
        let mut hops_map: HashMap<_, u64, HopEndpoint> = map
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to get SOCKET_HOPS_MAP"))?;
        let mut stale_keys = Vec::new();
        for result in hops_map.iter() {
            let (key, _) =
                result.map_err(|e| anyhow::anyhow!("failed to iterate SOCKET_HOPS_MAP: {}", e))?;
            if !live_pids.contains(&((key >> 32) as u32)) {
                stale_keys.push(key);
            }
        }
        for key in stale_keys {
            hops_map.remove(&key).ok();
        }
    }

    for name in [
        "LATENCY_PID_SUM",
        "LATENCY_PID_COUNT",
        "LATENCY_WINDOW_START",
    ] {
        let mut pid_map: HashMap<_, u32, u64> = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("{} map not found", name))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to open {} map", name))?;
        let mut stale_pids = Vec::new();
        for result in pid_map.iter() {
            let (pid, _) =
                result.map_err(|e| anyhow::anyhow!("failed to iterate {} map: {}", name, e))?;
            if !live_pids.contains(&pid) {
                stale_pids.push(pid);
            }
        }
        for pid in stale_pids {
            pid_map.remove(&pid).ok();
        }
    }

    socket_pid_map.clear();
    socket_path_map.clear();

    info!("Latency updates stopped, re-running SCA endpoint discovery");
    populate_socket_hops_map(socket_path_map, socket_pid_map, ebpf)
}
