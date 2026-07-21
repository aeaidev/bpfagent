use std::{any::Any, sync::Arc};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use kfree_skb_common::{reason_name, SkbDropReason};
use log::{debug, info, trace};
use prometheus::{IntCounterVec, Registry};

use crate::program::{EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Prometheus metrics for kfree_skb
#[derive(Clone)]
pub struct Metrics {
    pub total_drops: IntCounterVec,
    pub drops_by_reason: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: Arc<prometheus::Registry>) -> Self {
        let total_drops = IntCounterVec::new(
            prometheus::opts!("kfree_skb_total_drops", "Total number of SKB drops"),
            &["reason"],
        )
        .expect("failed to create total_drops counter");
        registry
            .register(Box::new(total_drops.clone()))
            .expect("failed to register total_drops counter");

        let drops_by_reason = IntCounterVec::new(
            prometheus::opts!("kfree_skb_drops_by_reason", "Number of drops by reason"),
            &["reason_code", "reason_name"],
        )
        .expect("failed to create drops_by_reason counter");
        registry
            .register(Box::new(drops_by_reason.clone()))
            .expect("failed to register drops_by_reason counter");

        Self {
            total_drops,
            drops_by_reason,
        }
    }
}

/// BPF program wrapper for kfree_skb
pub struct KfreeSkbProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<Metrics>,
}

impl KfreeSkbProgram {
    /// Creates a new kfree_skb BPF program
    pub fn new() -> Self {
        Self {
            name: "kfree_skb".to_string(),
            ebpf: None,
            metrics: None,
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: Metrics) {
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

impl MetricsDisplay for KfreeSkbProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = Metrics::new(registry);
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

        // Sort by count (descending)
        all_counts.sort_by_key(|b| std::cmp::Reverse(b.2));

        if all_counts.is_empty() {
            trace!("No drops recorded yet");
        } else {
            let total: u64 = all_counts.iter().map(|(_, _, c)| *c).sum();
            metrics
                .total_drops
                .with_label_values(&["all"])
                .inc_by(total);

            info!("Drop counts (total: {}):", total);
            for (reason, name, count) in &all_counts {
                info!("  {:3} ({:30}): {}", reason, name, count);
                // Update Prometheus metrics
                metrics
                    .drops_by_reason
                    .with_label_values(&[&reason.to_string(), name])
                    .inc_by(*count);
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

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("kfree_skb", || Box::new(KfreeSkbProgram::new()));
}
