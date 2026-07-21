use std::any::Any;

use aya::{
    Ebpf,
    maps::{HashMap, MapData},
    programs::TracePoint,
};
use kfree_skb_common::{SkbDropReason, reason_name};
use log::{debug, info, trace};
use prometheus::{IntCounterVec, Registry};

use crate::program::EbpfProgram;

/// Prometheus metrics for kfree_skb
pub struct Metrics {
    pub total_drops: IntCounterVec,
    pub drops_by_reason: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        let total_drops = IntCounterVec::new(
            prometheus::opts!["kfree_skb_total_drops", "Total number of SKB drops"],
            &["reason"],
        )
        .expect("failed to create total_drops counter");
        registry
            .register(Box::new(total_drops.clone()))
            .expect("failed to register total_drops counter");

        let drops_by_reason = IntCounterVec::new(
            prometheus::opts!["kfree_skb_drops_by_reason", "Number of drops by reason"],
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

pub fn display_drop_counts(
    drop_counts: &mut HashMap<&mut MapData, u32, u64>,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    // Collect all entries from the map
    let mut all_counts = Vec::new();
    for entry in drop_counts.iter() {
        let (reason, count) = entry?;
        let reason_name = reason_name(SkbDropReason::from(reason));
        all_counts.push((reason, reason_name, count));
    }

    // Sort by count (descending)
    all_counts.sort_by(|a, b| b.2.cmp(&a.2));

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

/// BPF program wrapper for kfree_skb
pub struct KfreeSkbProgram {
    pub name: String,
    pub enabled: bool,
    pub ebpf: Option<Ebpf>,
}

impl KfreeSkbProgram {
    pub fn new() -> Self {
        Self {
            name: "kfree_skb".to_string(),
            enabled: true,
            ebpf: None,
        }
    }

    /// Get the BPF program map for accessing DROP_COUNTS
    pub fn get_drop_counts_map(&mut self) -> Option<aya::maps::HashMap<&mut MapData, u32, u64>> {
        let ebpf = self.ebpf.as_mut()?;
        aya::maps::HashMap::<&mut MapData, u32, u64>::try_from(ebpf.map_mut("DROP_COUNTS").unwrap())
            .ok()
    }
}

impl Default for KfreeSkbProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfProgram for KfreeSkbProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/kfree_skb"
        )))?;

        // Get the BPF program and map
        let program: &mut TracePoint = ebpf.program_mut("kfree_skb").unwrap().try_into()?;
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
}
