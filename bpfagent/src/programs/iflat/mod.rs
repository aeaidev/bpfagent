//! IFLAT eBPF Program - Interface-to-Interface Forwarding Latency
//!
//! This module provides a BPF program that measures how long the kernel
//! holds one UDP or TCP datagram while forwarding it between two interfaces:
//! from ingress on the RX interface (e.g. eno1) to egress on the TX
//! interface (e.g. tun0). The forwarding path may apply NAT (nftables
//! masquerade): addresses, ports and checksums are rewritten, but the
//! payload is not, so each datagram is keyed on the tag in its first 4
//! payload bytes (big-endian) — the same correlation key before and after
//! NAT.
//!
//! The eBPF side has two programs (see ebpf/iflat):
//! - RX (`iflat_xdp_rx`, XDP on `rx_iface`): parses Ethernet/IPv4 + UDP/TCP
//!   and stores the receipt timestamp in TIMESTAMP_MAP, keyed on the tag.
//!   Runs before routing and netfilter (pre-NAT).
//! - TX (`iflat_tc_tx`, TC clsact egress on `tx_iface`): parses IPv4 +
//!   UDP/TCP (a tun device has no L2 header) and looks up the tag; on a
//!   match it removes the record and adds the latency (now - stored) to the
//!   cumulative LATENCY_SUM/LATENCY_COUNT accumulators. Runs after
//!   POSTROUTING (post-NAT), before the egress qdisc.
//!
//! # Moving Average
//!
//! The BPF maps hold cumulative accumulators since program load; userspace
//! converts them to per-tick deltas and averages each tick, so the reported
//! latency is a periodic moving average that reflects recent traffic instead
//! of growing stale. A tick with no matched datagrams reports 0.
//!
//! # Configuration
//!
//! Both interfaces are required settings; when they are missing (e.g. the
//! program got enabled implicitly because the config lists no
//! `[[ebpf_programs]]` entries), the program logs a warning and stays
//! disabled instead of failing the whole agent:
//!
//! ```toml
//! [[ebpf_programs]]
//! name = "iflat"
//! enabled = true
//!
//! [ebpf_programs.settings]
//! rx_iface = "eno1"   # ingress interface (XDP)
//! tx_iface = "tun0"   # egress interface (TC clsact egress)
//! ```
//!
//! # Prometheus Metrics
//!
//! - `iflat_avg_latency_us`: Average interface-to-interface forwarding
//!   latency in microseconds over the last display interval (0 when no
//!   traffic)

use std::{any::Any, sync::Arc};

/// Microseconds per nanosecond conversion factor
const NS_PER_US: u64 = 1_000;

use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpMode},
    Ebpf,
};
use log::{debug, info, trace, warn};
use prometheus::{Gauge, Opts, Registry};

use crate::{
    config::EbpfProgramConfig,
    programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry},
};

/// Key of the single LATENCY_SUM/LATENCY_COUNT accumulator in the BPF maps.
const ACCUM_KEY: u32 = 0;

/// Maximum accepted interface name length (Linux IFNAMSIZ is 16 including
/// the terminating NUL).
const MAX_IFACE_LEN: usize = 15;

/// Prometheus metrics for IFLAT program
pub struct IflatMetrics {
    pub avg_latency_us: Gauge,
}

impl IflatMetrics {
    /// Create new IFLAT Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let avg_latency_us = Gauge::with_opts(Opts::new(
            "iflat_avg_latency_us",
            "Average interface-to-interface forwarding latency in microseconds (per-interval moving average)",
        ))
        .map_err(|e| anyhow::anyhow!("failed to create avg_latency_us gauge: {}", e))?;

        registry
            .register(Box::new(avg_latency_us.clone()))
            .map_err(|e| anyhow::anyhow!("failed to register avg_latency_us gauge: {}", e))?;

        Ok(Self { avg_latency_us })
    }
}

/// BPF program wrapper for IFLAT (interface-to-interface forwarding latency)
pub struct IflatProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<IflatMetrics>,
    /// False when rx_iface/tx_iface are not configured: load() and
    /// display_metrics() no-op so the program can never fail an implicit
    /// enable (config without [[ebpf_programs]] entries).
    enabled: bool,
    /// Ingress interface the XDP program attaches to (required setting)
    rx_iface: String,
    /// Egress interface the TC egress classifier attaches to (required setting)
    tx_iface: String,
    /// Last cumulative latency sum (ns) seen, used to compute per-tick deltas
    last_sum: u64,
    /// Last cumulative sample count seen, used to compute per-tick deltas
    last_count: u64,
}

impl IflatProgram {
    /// Creates a new IFLAT BPF program
    pub fn new() -> Self {
        Self {
            name: "iflat".to_string(),
            ebpf: None,
            metrics: None,
            enabled: true,
            rx_iface: String::new(),
            tx_iface: String::new(),
            last_sum: 0,
            last_count: 0,
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: IflatMetrics) {
        self.metrics = Some(metrics);
    }
}

/// Parse an interface name setting from the program's settings table.
/// Returns None when the setting is missing; returns an error when it is
/// present but not a valid interface name (non-string, empty, or longer than
/// IFNAMSIZ allows).
pub fn parse_iface_setting(
    config: &EbpfProgramConfig,
    key: &str,
) -> anyhow::Result<Option<String>> {
    let Some(value) = config.settings.as_ref().and_then(|s| s.get(key)) else {
        return Ok(None);
    };
    let Some(name) = value.as_str() else {
        return Err(anyhow::anyhow!(
            "invalid iflat {} setting '{:?}': not a string",
            key,
            value
        ));
    };
    if name.is_empty() || name.len() > MAX_IFACE_LEN {
        return Err(anyhow::anyhow!(
            "invalid iflat {} setting '{}': not a valid interface name",
            key,
            name
        ));
    }
    Ok(Some(name.to_string()))
}

impl EbpfProgram for IflatProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "iflat_xdp_rx"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        if !self.enabled {
            debug!("iflat: rx_iface/tx_iface not configured, skipping load");
            return Ok(());
        }
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/iflat"
        )))?;

        // RX: XDP on the ingress interface. XdpMode::Default lets the kernel
        // pick native (driver) mode; fall back to generic (SKB) mode when the
        // NIC driver has no XDP support.
        let program: &mut Xdp = ebpf
            .program_mut("iflat_xdp_rx")
            .ok_or_else(|| anyhow::anyhow!("program 'iflat_xdp_rx' not found"))?
            .try_into()?;
        program.load()?;
        if let Err(e) = program.attach(&self.rx_iface, XdpMode::Default) {
            warn!(
                "iflat: XDP attach on {} failed ({}); retrying in generic (SKB) mode",
                self.rx_iface, e
            );
            program
                .attach(&self.rx_iface, XdpMode::Skb)
                .map_err(|e| anyhow::anyhow!("failed to attach XDP on {}: {}", self.rx_iface, e))?;
        }
        info!("iflat: XDP program attached to {}", self.rx_iface);

        // TX: TC egress classifier on the egress interface. The clsact qdisc
        // must exist before attaching; it may already be present.
        if let Err(e) = tc::qdisc_add_clsact(&self.tx_iface) {
            debug!(
                "iflat: qdisc_add_clsact({}): {} (already present?)",
                self.tx_iface, e
            );
        }
        let program: &mut SchedClassifier = ebpf
            .program_mut("iflat_tc_tx")
            .ok_or_else(|| anyhow::anyhow!("program 'iflat_tc_tx' not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach(&self.tx_iface, TcAttachType::Egress)
            .map_err(|e| {
                anyhow::anyhow!("failed to attach TC egress on {}: {}", self.tx_iface, e)
            })?;
        info!("iflat: TC egress program attached to {}", self.tx_iface);

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

    fn configure(&mut self, config: &EbpfProgramConfig) -> anyhow::Result<()> {
        let rx_iface = parse_iface_setting(config, "rx_iface")?;
        let tx_iface = parse_iface_setting(config, "tx_iface")?;
        match (rx_iface, tx_iface) {
            (Some(rx), Some(tx)) => {
                self.rx_iface = rx;
                self.tx_iface = tx;
                debug!(
                    "IFLAT configured: RX {} (XDP) -> TX {} (TC egress)",
                    self.rx_iface, self.tx_iface
                );
            }
            _ => {
                self.enabled = false;
                warn!("iflat: rx_iface/tx_iface settings are required; program stays disabled");
            }
        }
        Ok(())
    }

    fn supports_metrics(&self) -> bool {
        true
    }

    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        Some(self)
    }
}

/// Compute the per-tick deltas of the cumulative (sum, count) latency
/// accumulators read from the BPF maps: the difference since the last values
/// seen (0 if a value went backwards, e.g. after a program reload). Updates
/// `last_sum`/`last_count`.
pub fn latency_deltas(
    last_sum: &mut u64,
    last_count: &mut u64,
    sum: u64,
    count: u64,
) -> (u64, u64) {
    let sum_delta = sum.saturating_sub(*last_sum);
    let count_delta = count.saturating_sub(*last_count);
    *last_sum = sum;
    *last_count = count;
    (sum_delta, count_delta)
}

/// Average latency in microseconds for one display tick, or None when no
/// datagrams were matched since the previous tick.
///
/// # Examples
///
/// ```
/// use bpfagent::programs::iflat::avg_latency_us;
///
/// // With 1000 samples, each 1000000 ns (1ms) apart
/// let latency = avg_latency_us(1000000000, 1000);
/// assert_eq!(latency, Some(1000)); // 1000000000 / 1000 / 1000 = 1000 us
///
/// // No samples means no latency
/// let latency = avg_latency_us(0, 0);
/// assert_eq!(latency, None);
/// ```
pub fn avg_latency_us(sum_delta: u64, count_delta: u64) -> Option<u64> {
    sum_delta.checked_div(count_delta)?.checked_div(NS_PER_US)
}

impl MetricsDisplay for IflatProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = IflatMetrics::new(registry)?;
        self.set_metrics(metrics);
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Get metrics or return early if not set
        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metrics not set for iflat program"))?;

        // Get the latency accumulator maps from the BPF program
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;
        let sum_map = open_accumulator_map(ebpf, "LATENCY_SUM")?;
        let count_map = open_accumulator_map(ebpf, "LATENCY_COUNT")?;

        let sum = sum_map.get(&ACCUM_KEY, 0).unwrap_or(0);
        let count = count_map.get(&ACCUM_KEY, 0).unwrap_or(0);

        // The BPF maps hold cumulative values since program load; convert to
        // per-tick deltas so the reported average reflects recent traffic.
        let (sum_delta, count_delta) =
            latency_deltas(&mut self.last_sum, &mut self.last_count, sum, count);
        match avg_latency_us(sum_delta, count_delta) {
            Some(avg_us) => {
                metrics.avg_latency_us.set(avg_us as f64);
                info!(
                    "IFLAT forwarding latency: {} us ({} samples, {} -> {})",
                    avg_us, count_delta, self.rx_iface, self.tx_iface
                );
            }
            None => {
                metrics.avg_latency_us.set(0.0);
                trace!("No new IFLAT latency samples");
            }
        }

        Ok(())
    }
}

/// Open a u32 -> u64 BPF hash map by name.
fn open_accumulator_map<'a>(
    ebpf: &'a Ebpf,
    name: &str,
) -> anyhow::Result<HashMap<&'a aya::maps::MapData, u32, u64>> {
    ebpf.map(name)
        .ok_or_else(|| anyhow::anyhow!("{} map not found", name))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to open {} map: {}", name, e))
}

impl Default for IflatProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for IflatProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("iflat", || Box::new(IflatProgram::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(settings: Option<toml::Table>) -> EbpfProgramConfig {
        EbpfProgramConfig {
            name: "iflat".to_string(),
            enabled: true,
            settings,
        }
    }

    fn settings_of(pairs: &[(&str, toml::Value)]) -> toml::Table {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn test_avg_latency_us() {
        // Normal case: valid sum and count
        assert_eq!(avg_latency_us(1_000_000_000, 1000), Some(1000));
        // No samples - division by zero handled
        assert_eq!(avg_latency_us(0, 0), None);
        // Very small latency
        assert_eq!(avg_latency_us(500_000, 100), Some(5));
        // Exact division
        assert_eq!(avg_latency_us(2_000_000, 2), Some(1000));
    }

    #[test]
    fn test_latency_deltas() {
        let mut last_sum = 0u64;
        let mut last_count = 0u64;

        // First read: should be the full values
        let (sum_delta, count_delta) = latency_deltas(&mut last_sum, &mut last_count, 1000, 10);
        assert_eq!(sum_delta, 1000);
        assert_eq!(count_delta, 10);

        // Second read with new values
        let (sum_delta, count_delta) = latency_deltas(&mut last_sum, &mut last_count, 2500, 25);
        assert_eq!(sum_delta, 1500);
        assert_eq!(count_delta, 15);

        // Value went backwards (e.g., map reset) - should return 0
        let (sum_delta, count_delta) = latency_deltas(&mut last_sum, &mut last_count, 500, 5);
        assert_eq!(sum_delta, 0);
        assert_eq!(count_delta, 0);
    }

    #[test]
    fn test_avg_latency_us_overflow() {
        // Large sum that would overflow if we didn't use checked_div
        let large_sum = u64::MAX;
        let count = 1000;
        // This should not panic
        let _ = avg_latency_us(large_sum, count);
    }

    #[test]
    fn test_parse_iface_setting() {
        let config = config_with(Some(settings_of(&[(
            "rx_iface",
            toml::Value::String("eno1".to_string()),
        )])));
        assert_eq!(
            parse_iface_setting(&config, "rx_iface").unwrap(),
            Some("eno1".to_string())
        );
        // Missing setting is not an error
        assert_eq!(parse_iface_setting(&config, "tx_iface").unwrap(), None);
        assert_eq!(
            parse_iface_setting(&config_with(None), "rx_iface").unwrap(),
            None
        );

        // Present but not a string is an error
        let config = config_with(Some(settings_of(&[("rx_iface", toml::Value::Integer(1))])));
        assert!(parse_iface_setting(&config, "rx_iface").is_err());

        // Empty or over-long names are errors
        let config = config_with(Some(settings_of(&[(
            "rx_iface",
            toml::Value::String(String::new()),
        )])));
        assert!(parse_iface_setting(&config, "rx_iface").is_err());
        let config = config_with(Some(settings_of(&[(
            "rx_iface",
            toml::Value::String("a".repeat(MAX_IFACE_LEN + 1)),
        )])));
        assert!(parse_iface_setting(&config, "rx_iface").is_err());
    }

    #[test]
    fn test_configure_requires_both_ifaces() {
        let mut program = IflatProgram::new();

        // Missing settings disable the program without failing
        program.configure(&config_with(None)).unwrap();
        assert!(!program.enabled);

        // Only one interface set: still disabled
        let mut program = IflatProgram::new();
        let config = config_with(Some(settings_of(&[(
            "rx_iface",
            toml::Value::String("eno1".to_string()),
        )])));
        program.configure(&config).unwrap();
        assert!(!program.enabled);

        // Both interfaces set: enabled
        let mut program = IflatProgram::new();
        let config = config_with(Some(settings_of(&[
            ("rx_iface", toml::Value::String("eno1".to_string())),
            ("tx_iface", toml::Value::String("tun0".to_string())),
        ])));
        program.configure(&config).unwrap();
        assert!(program.enabled);
        assert_eq!(program.rx_iface, "eno1");
        assert_eq!(program.tx_iface, "tun0");
    }
}
