use aya::maps::{HashMap, MapData};
use kfree_skb_common::{SkbDropReason, reason_name};
use log::{info, trace};
use prometheus::{IntCounterVec, Registry};

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
