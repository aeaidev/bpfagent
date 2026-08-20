//! kfree_skb eBPF Program - Kernel Packet Drop Tracing
//!
//! This module provides a BPF program that traces the kernel's `kfree_skb` tracepoint
//! to collect statistics on why network packets are being dropped.
//!
//! The eBPF program attaches to the `skb:kfree_skb` tracepoint and increments counters
//! for each drop reason defined in the kernel's `enum skb_drop_reason`.
//!
//! # Prometheus Metrics
//!
//! - `kfree_skb_total_drops_per_sec`: Total drop rate (all reasons)
//! - `kfree_skb_drops_per_sec`: Drop rate by reason code and name
//!
//! Both are moving averages over a 10-second sliding window: the BPF map
//! holds cumulative counts since program load, userspace converts them to
//! per-tick deltas and averages the deltas in the window. A reason with no
//! drops in the window decays to zero and its series is removed.
//!
//! # Example Output
//!
//! ```text
//! Drop rates (drops/sec, 10s moving average; total: 3.7):
//!   10 (TCP_CSUM               ): 2.1
//!   64 (QDISC_DROP             ): 1.2
//!    3 (NO_SOCKET              ): 0.4
//! ```

use std::{
    any::Any,
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use kfree_skb_common::{reason_name, SkbDropReason};
use log::{debug, info, trace};
use prometheus::{GaugeVec, Opts, Registry};

use crate::programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Sliding window for the moving-average drop rate.
const RATE_WINDOW: Duration = Duration::from_secs(10);

/// Prometheus metrics for KfreeSkb program
pub struct KfreeSkbMetrics {
    pub total_drops_per_sec: GaugeVec,
    pub drops_per_sec: GaugeVec,
}

impl KfreeSkbMetrics {
    /// Create new kfree_skb Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let total_drops_per_sec = GaugeVec::new(
            Opts::new(
                "kfree_skb_total_drops_per_sec",
                "Dropped packets per second, 10s moving average",
            ),
            &["reason"],
        )
        .map_err(|e| anyhow::anyhow!("failed to create total_drops_per_sec gauge: {}", e))?;

        registry
            .register(Box::new(total_drops_per_sec.clone()))
            .map_err(|e| {
                anyhow::anyhow!("failed to register total_drops_per_sec gauge: {}", e)
            })?;

        let drops_per_sec = GaugeVec::new(
            Opts::new(
                "kfree_skb_drops_per_sec",
                "Dropped packets per second by reason, 10s moving average",
            ),
            &["reason_code", "reason_name"],
        )
        .map_err(|e| anyhow::anyhow!("failed to create drops_per_sec gauge: {}", e))?;

        registry
            .register(Box::new(drops_per_sec.clone()))
            .map_err(|e| anyhow::anyhow!("failed to register drops_per_sec gauge: {}", e))?;

        Ok(Self {
            total_drops_per_sec,
            drops_per_sec,
        })
    }
}

/// BPF program wrapper for kfree_skb
pub struct KfreeSkbProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<KfreeSkbMetrics>,
    /// Last cumulative count seen per drop reason, used to compute per-tick
    /// deltas from the cumulative BPF counters
    last_counts: std::collections::HashMap<u32, u64>,
    /// Per-tick drop deltas within the moving-average window, per reason
    delta_windows: std::collections::HashMap<u32, VecDeque<(Instant, u64)>>,
}

impl KfreeSkbProgram {
    /// Creates a new kfree_skb BPF program
    pub fn new() -> Self {
        Self {
            name: "kfree_skb".to_string(),
            ebpf: None,
            metrics: None,
            last_counts: std::collections::HashMap::new(),
            delta_windows: std::collections::HashMap::new(),
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: KfreeSkbMetrics) {
        self.metrics = Some(metrics);
    }
}

impl EbpfProgram for KfreeSkbProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "kfree_skb"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/kfree_skb"
        )))?;

        // Get the BPF program and map
        let program: &mut TracePoint = ebpf
            .program_mut("kfree_skb")
            .ok_or_else(|| anyhow::anyhow!("program 'kfree_skb' not found"))
            .and_then(|p| {
                p.try_into()
                    .map_err(|e| anyhow::anyhow!("failed to convert to TracePoint: {}", e))
            })?;
        program.load()?;
        program.attach("skb", "kfree_skb")?;

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

/// Compute the Prometheus increment for a cumulative counter read from the BPF
/// map: the difference since the last value seen for this reason (0 if the
/// value went backwards, e.g. after a map reset). Updates `last_counts`.
pub fn counter_delta(
    last_counts: &mut std::collections::HashMap<u32, u64>,
    reason: u32,
    count: u64,
) -> u64 {
    let prev = last_counts.insert(reason, count).unwrap_or(0);
    count.saturating_sub(prev)
}

/// Push a per-tick delta into the sliding window, evict entries older than
/// RATE_WINDOW, and return the sum of the remaining deltas.
pub fn update_window(window: &mut VecDeque<(Instant, u64)>, now: Instant, delta: u64) -> u64 {
    if delta > 0 {
        window.push_back((now, delta));
    }
    while let Some((t, _)) = window.front() {
        if now.duration_since(*t) > RATE_WINDOW {
            window.pop_front();
        } else {
            break;
        }
    }
    window.iter().map(|(_, d)| d).sum()
}

impl MetricsDisplay for KfreeSkbProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = KfreeSkbMetrics::new(registry)?;
        self.set_metrics(metrics);
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        // Get metrics or return early if not set
        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metrics not set for kfree_skb program"))?;

        // Get the drop counts map from the BPF program
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;
        let map = ebpf
            .map_mut("DROP_COUNTS")
            .ok_or_else(|| anyhow::anyhow!("DROP_COUNTS map not found"))?;
        let drop_counts = HashMap::<_, u32, u64>::try_from(map)
            .map_err(|_| anyhow::anyhow!("failed to get DROP_COUNTS map"))?;

        // Collect all entries from the map
        let mut all_counts = Vec::new();
        for entry in drop_counts.iter() {
            let (reason, count) = entry?;
            let reason_name = reason_name(SkbDropReason::from(reason));
            all_counts.push((reason, reason_name, count));
        }

        // The BPF map holds cumulative counts since program load; convert to
        // per-tick deltas and average them over a sliding window, so the
        // reported rate reflects recent traffic instead of growing forever.
        let now = Instant::now();
        let mut rows = Vec::new();
        for (reason, name, count) in all_counts {
            let delta = counter_delta(&mut self.last_counts, reason, count);
            let sum = {
                let window = self.delta_windows.entry(reason).or_default();
                update_window(window, now, delta)
            };
            if sum == 0 {
                // No drops within the window: the rate decayed to zero, drop
                // the series and skip the reason in the output.
                self.delta_windows.remove(&reason);
                let label = [reason.to_string(), name.to_string()];
                let label_refs: Vec<&str> = label.iter().map(String::as_str).collect();
                if let Err(e) = metrics.drops_per_sec.remove_label_values(&label_refs) {
                    debug!("failed to remove decayed drop-rate series {}: {}", name, e);
                }
                continue;
            }
            let rate = sum as f64 / RATE_WINDOW.as_secs_f64();
            metrics
                .drops_per_sec
                .with_label_values(&[&reason.to_string(), &name.to_string()])
                .set(rate);
            rows.push((reason, name, rate));
        }

        // Sort by rate (descending)
        rows.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        if rows.is_empty() {
            trace!("No drops recorded in the last {}s", RATE_WINDOW.as_secs());
        } else {
            let total_rate: f64 = rows.iter().map(|(_, _, r)| *r).sum();
            metrics
                .total_drops_per_sec
                .with_label_values(&["all"])
                .set(total_rate);

            info!(
                "Drop rates (drops/sec, {}s moving average; total: {:.1}):",
                RATE_WINDOW.as_secs(),
                total_rate
            );
            for (reason, name, rate) in &rows {
                info!("  {:3} ({:30}): {:.1}", reason, name, rate);
            }
        }

        Ok(())
    }
}

impl Default for KfreeSkbProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for KfreeSkbProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("kfree_skb", || Box::new(KfreeSkbProgram::new()));
}
