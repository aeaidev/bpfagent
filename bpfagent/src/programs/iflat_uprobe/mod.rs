//! IFLAT_UPROBE eBPF Program - Interface-to-Interface + Function-Call Latency
//!
//! This module provides a BPF program that measures a pair of latencies for
//! one UDP or TCP datagram on its way from a physical interface into a
//! userspace application function (see docs/IFLAT_UPROBE.md):
//!
//! 1. RX1 -> RX2: from ingress on the first RX interface (e.g. eno1) to
//!    ingress on the second RX interface (e.g. tun0).
//! 2. RX2 -> function call: from ingress on the second RX interface to the
//!    call of a configured function that receives the payload as a parameter
//!    (e.g. `void FpgaPciePhy::submitBurst(Endpoint from, TxSlot &slot)`).
//!
//! Each datagram is keyed on the tag in its first 4 payload bytes
//! (big-endian): the payload is never rewritten while the kernel and the
//! receiving application move the datagram along, so the same tag is seen at
//! all three measurement points.
//!
//! The eBPF side has three programs (see ebpf/iflat_uprobe):
//! - RX1 (`iflat_uprobe_xdp_rx1`, XDP on `rx1_iface`): parses IPv4 +
//!   UDP/TCP and stores the receipt timestamp in TIMESTAMP1_MAP, keyed on
//!   the tag.
//! - RX2 (`iflat_uprobe_xdp_rx2`, XDP on `rx2_iface`): looks up the tag in
//!   TIMESTAMP1_MAP; on a match it removes the record and adds the latency
//!   to the LATENCY1_SUM/LATENCY1_COUNT accumulators, then stores its own
//!   timestamp in TIMESTAMP2_MAP (unconditionally, so leg 2 is measured even
//!   for datagrams first seen at RX2).
//! - Function call (`iflat_uprobe_fn_call`, uprobe on `symbol` in `target`):
//!   resolves the payload pointer from the configured argument register
//!   (`arg_index`, x86_64 SysV ABI) — directly, or through the
//!   payload-pointer member of the struct the argument points to
//!   (`payload_ptr_offset`, e.g. offsetof(TxSlot, payload) for
//!   `TxSlot &slot` -> `slot->payload`) — rebuilds the tag from the first 4
//!   payload bytes at `tag_offset`, and looks it up in TIMESTAMP2_MAP; on a
//!   match it removes the record and adds the latency to the
//!   LATENCY2_SUM/LATENCY2_COUNT accumulators.
//!
//! # Moving Average
//!
//! The BPF maps hold cumulative accumulators since program load; userspace
//! converts them to per-tick deltas and averages each tick, so the reported
//! latencies are periodic moving averages that reflect recent traffic instead
//! of growing stale. A tick with no matched datagrams reports 0.
//!
//! # Configuration
//!
//! The interfaces and the attach target have no sensible defaults, so
//! `rx1_iface`, `rx2_iface`, `target` and `symbol` are required settings;
//! when any of them is missing (e.g. the program got enabled implicitly
//! because the config lists no `[[ebpf_programs]]` entries), the program
//! logs a warning and stays disabled instead of failing the whole agent:
//!
//! ```toml
//! [[ebpf_programs]]
//! name = "iflat_uprobe"
//! enabled = true
//!
//! [ebpf_programs.settings]
//! rx1_iface = "eno1"        # first ingress interface (XDP)
//! rx2_iface = "tun0"        # second ingress interface (XDP)
//! target = "/path/to/app"   # binary or shared library to instrument
//! symbol = "function_name"  # function receiving the payload (ELF symbol)
//! # offset = 0              # extra byte offset past the symbol
//! # pid = -1                # -1 = all processes, or a specific PID
//! # arg_index = 3           # SysV argument register leading to the payload
//!                         # (C++ method: 1 = this, 2 = first arg)
//! # payload_ptr_offset = -1 # offset of the payload pointer within the
//!                         # pointed-to struct (e.g. offsetof(TxSlot,
//!                         # payload) = 296); -1 = the argument points
//!                         # directly at the payload
//! # tag_offset = 0          # byte offset from the resolved payload pointer
//!                         # to the first payload byte
//! ```
//!
//! # Prometheus Metrics
//!
//! - `iflat_uprobe_avg_latency1_us`: Average RX1-to-RX2 latency in
//!   microseconds over the last display interval (0 when no traffic)
//! - `iflat_uprobe_avg_latency2_us`: Average RX2-to-function-call latency in
//!   microseconds over the last display interval (0 when no traffic)

use std::{any::Any, sync::Arc};

use aya::{
    maps::HashMap,
    programs::{uprobe::UProbeAttachLocation, UProbe, Xdp, XdpMode},
    Ebpf,
};
use iflat_uprobe_common::{UprobeConfig, MAX_ARGS, PAYLOAD_PTR_DIRECT, UPROBE_CONFIG_KEY};
use log::{debug, info, trace, warn};
use prometheus::{Gauge, Opts, Registry};

use crate::{
    config::EbpfProgramConfig,
    programs::{
        iflat::{avg_latency_us, latency_deltas},
        uprobe::pid_scope,
        EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry,
    },
};

/// Key of the single LATENCY*_SUM/LATENCY*_COUNT accumulator in the BPF maps.
const ACCUM_KEY: u32 = 0;

/// Maximum accepted interface name length (Linux IFNAMSIZ is 16 including
/// the terminating NUL).
const MAX_IFACE_LEN: usize = 15;

/// Default argument register holding the payload pointer: 3 (rdx) matches
/// `void FpgaPciePhy::submitBurst(Endpoint from, TxSlot &slot)` when
/// `Endpoint` occupies one register (rdi = this, rsi = from, rdx = slot).
const DEFAULT_ARG_INDEX: u32 = 3;

/// Prometheus metrics for the IFLAT_UPROBE program
pub struct IflatUprobeMetrics {
    pub avg_latency1_us: Gauge,
    pub avg_latency2_us: Gauge,
}

impl IflatUprobeMetrics {
    /// Create new IFLAT_UPROBE Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let avg_latency1_us = Gauge::with_opts(Opts::new(
            "iflat_uprobe_avg_latency1_us",
            "Average RX1-to-RX2 interface ingress latency in microseconds (per-interval moving average)",
        ))
        .map_err(|e| anyhow::anyhow!("failed to create avg_latency1_us gauge: {}", e))?;

        registry
            .register(Box::new(avg_latency1_us.clone()))
            .map_err(|e| anyhow::anyhow!("failed to register avg_latency1_us gauge: {}", e))?;

        let avg_latency2_us = Gauge::with_opts(Opts::new(
            "iflat_uprobe_avg_latency2_us",
            "Average RX2-to-function-call latency in microseconds (per-interval moving average)",
        ))
        .map_err(|e| anyhow::anyhow!("failed to create avg_latency2_us gauge: {}", e))?;

        registry
            .register(Box::new(avg_latency2_us.clone()))
            .map_err(|e| anyhow::anyhow!("failed to register avg_latency2_us gauge: {}", e))?;

        Ok(Self {
            avg_latency1_us,
            avg_latency2_us,
        })
    }
}

/// BPF program wrapper for IFLAT_UPROBE (interface + function-call latency)
pub struct IflatUprobeProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<IflatUprobeMetrics>,
    /// False when rx1_iface/rx2_iface/target/symbol are not configured:
    /// load() and display_metrics() no-op so the program can never fail an
    /// implicit enable (config without [[ebpf_programs]] entries).
    enabled: bool,
    /// First ingress interface the RX1 XDP program attaches to (required)
    rx1_iface: String,
    /// Second ingress interface the RX2 XDP program attaches to (required)
    rx2_iface: String,
    /// Path of the binary or shared library to instrument (required setting)
    target: String,
    /// Function symbol receiving the payload (required setting)
    symbol: String,
    /// Extra byte offset past the symbol (optional, default 0)
    offset: u64,
    /// PID filter: <= 0 traces all processes (optional, default -1)
    pid: i32,
    /// Argument register leading to the payload, 1..=MAX_ARGS
    /// (optional, default DEFAULT_ARG_INDEX)
    arg_index: u32,
    /// Byte offset of the payload pointer within the struct the argument
    /// points to; PAYLOAD_PTR_DIRECT when the argument itself points at the
    /// payload (optional, default PAYLOAD_PTR_DIRECT)
    payload_ptr_offset: u32,
    /// Byte offset from the resolved payload pointer to the first payload
    /// byte (optional, default 0)
    tag_offset: u32,
    /// Last cumulative leg-1 latency sum (ns) seen, for per-tick deltas
    last_sum1: u64,
    /// Last cumulative leg-1 sample count seen, for per-tick deltas
    last_count1: u64,
    /// Last cumulative leg-2 latency sum (ns) seen, for per-tick deltas
    last_sum2: u64,
    /// Last cumulative leg-2 sample count seen, for per-tick deltas
    last_count2: u64,
}

impl IflatUprobeProgram {
    /// Creates a new IFLAT_UPROBE BPF program
    pub fn new() -> Self {
        Self {
            name: "iflat_uprobe".to_string(),
            ebpf: None,
            metrics: None,
            enabled: false,
            rx1_iface: String::new(),
            rx2_iface: String::new(),
            target: String::new(),
            symbol: String::new(),
            offset: 0,
            pid: -1,
            arg_index: DEFAULT_ARG_INDEX,
            payload_ptr_offset: PAYLOAD_PTR_DIRECT,
            tag_offset: 0,
            last_sum1: 0,
            last_count1: 0,
            last_sum2: 0,
            last_count2: 0,
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: IflatUprobeMetrics) {
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
            "invalid iflat_uprobe {} setting '{:?}': not a string",
            key,
            value
        ));
    };
    if name.is_empty() || name.len() > MAX_IFACE_LEN {
        return Err(anyhow::anyhow!(
            "invalid iflat_uprobe {} setting '{}': not a valid interface name",
            key,
            name
        ));
    }
    Ok(Some(name.to_string()))
}

/// Parse an optional string setting from the program's settings table.
/// Returns None when the setting is missing or not a string.
pub fn parse_string_setting(config: &EbpfProgramConfig, key: &str) -> Option<String> {
    config
        .settings
        .as_ref()
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Parse an optional integer setting, converting it with `convert`; values
/// that fail conversion fall back to `default` with a warning.
fn parse_int_setting<T>(
    config: &EbpfProgramConfig,
    key: &str,
    default: T,
    convert: impl Fn(i64) -> Option<T>,
) -> T {
    let Some(value) = config
        .settings
        .as_ref()
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_integer())
    else {
        return default;
    };
    match convert(value) {
        Some(parsed) => parsed,
        None => {
            warn!(
                "invalid iflat_uprobe {} setting '{}': out of range; using default",
                key, value
            );
            default
        }
    }
}

/// Parse the optional `offset` byte offset past the symbol (default 0).
pub fn parse_offset(config: &EbpfProgramConfig) -> u64 {
    parse_int_setting(config, "offset", 0, |v| u64::try_from(v).ok())
}

/// Parse the optional `pid` filter (default -1 = all processes).
pub fn parse_pid(config: &EbpfProgramConfig) -> i32 {
    parse_int_setting(config, "pid", -1, |v| i32::try_from(v).ok())
}

/// Parse the optional `arg_index` register leading to the payload
/// (default DEFAULT_ARG_INDEX, valid range 1..=MAX_ARGS).
pub fn parse_arg_index(config: &EbpfProgramConfig) -> u32 {
    parse_int_setting(config, "arg_index", DEFAULT_ARG_INDEX, |v| {
        u32::try_from(v)
            .ok()
            .filter(|n| (1..=MAX_ARGS as u32).contains(n))
    })
}

/// Parse the optional `payload_ptr_offset`: the byte offset of the payload
/// pointer within the struct the argument points to, or -1
/// (PAYLOAD_PTR_DIRECT) when the argument points directly at the payload
/// (default -1).
pub fn parse_payload_ptr_offset(config: &EbpfProgramConfig) -> u32 {
    parse_int_setting(config, "payload_ptr_offset", PAYLOAD_PTR_DIRECT, |v| {
        if v == -1 {
            Some(PAYLOAD_PTR_DIRECT)
        } else {
            u32::try_from(v).ok().filter(|n| *n != PAYLOAD_PTR_DIRECT)
        }
    })
}

/// Parse the optional `tag_offset` byte offset from the payload pointer to
/// the first payload byte (default 0).
pub fn parse_tag_offset(config: &EbpfProgramConfig) -> u32 {
    parse_int_setting(config, "tag_offset", 0, |v| u32::try_from(v).ok())
}

impl EbpfProgram for IflatUprobeProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "iflat_uprobe_xdp_rx1"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        if !self.enabled {
            debug!("iflat_uprobe: required settings missing, skipping load");
            return Ok(());
        }
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/iflat_uprobe"
        )))?;

        // Write the uprobe tag-location settings before the program starts
        // using them.
        let mut config_map = HashMap::<_, u32, UprobeConfig>::try_from(
            ebpf.map_mut("UPROBE_CONFIG_MAP")
                .ok_or_else(|| anyhow::anyhow!("UPROBE_CONFIG_MAP map not found"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to open UPROBE_CONFIG_MAP map: {}", e))?;
        let uprobe_config = UprobeConfig {
            arg_index: self.arg_index,
            payload_ptr_offset: self.payload_ptr_offset,
            tag_offset: self.tag_offset,
        };
        config_map
            .insert(&UPROBE_CONFIG_KEY, &uprobe_config, 0)
            .map_err(|e| anyhow::anyhow!("failed to configure UPROBE_CONFIG_MAP: {}", e))?;

        // RX1: XDP on the first ingress interface. XdpMode::Default lets the
        // kernel pick native (driver) mode; fall back to generic (SKB) mode
        // when the NIC driver has no XDP support.
        let program: &mut Xdp = ebpf
            .program_mut("iflat_uprobe_xdp_rx1")
            .ok_or_else(|| anyhow::anyhow!("program 'iflat_uprobe_xdp_rx1' not found"))?
            .try_into()?;
        program.load()?;
        if let Err(e) = program.attach(&self.rx1_iface, XdpMode::Default) {
            warn!(
                "iflat_uprobe: XDP attach on {} failed ({}); retrying in generic (SKB) mode",
                self.rx1_iface, e
            );
            program.attach(&self.rx1_iface, XdpMode::Skb).map_err(|e| {
                anyhow::anyhow!("failed to attach XDP on {}: {}", self.rx1_iface, e)
            })?;
        }
        info!(
            "iflat_uprobe: RX1 XDP program attached to {}",
            self.rx1_iface
        );

        // RX2: XDP on the second ingress interface.
        let program: &mut Xdp = ebpf
            .program_mut("iflat_uprobe_xdp_rx2")
            .ok_or_else(|| anyhow::anyhow!("program 'iflat_uprobe_xdp_rx2' not found"))?
            .try_into()?;
        program.load()?;
        if let Err(e) = program.attach(&self.rx2_iface, XdpMode::Default) {
            warn!(
                "iflat_uprobe: XDP attach on {} failed ({}); retrying in generic (SKB) mode",
                self.rx2_iface, e
            );
            program.attach(&self.rx2_iface, XdpMode::Skb).map_err(|e| {
                anyhow::anyhow!("failed to attach XDP on {}: {}", self.rx2_iface, e)
            })?;
        }
        info!(
            "iflat_uprobe: RX2 XDP program attached to {}",
            self.rx2_iface
        );

        // Function call: uprobe on the configured symbol.
        let program: &mut UProbe = ebpf
            .program_mut("iflat_uprobe_fn_call")
            .ok_or_else(|| anyhow::anyhow!("program 'iflat_uprobe_fn_call' not found"))?
            .try_into()?;
        program.load()?;
        program.attach(
            [UProbeAttachLocation::SymbolOffset(
                self.symbol.as_str(),
                self.offset,
            )],
            self.target.as_str(),
            pid_scope(self.pid),
        )?;
        info!(
            "iflat_uprobe: uprobe attached: {}+{:#x} in {} (pid filter {})",
            self.symbol, self.offset, self.target, self.pid
        );

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
        let rx1_iface = parse_iface_setting(config, "rx1_iface")?;
        let rx2_iface = parse_iface_setting(config, "rx2_iface")?;
        self.target = parse_string_setting(config, "target").unwrap_or_default();
        self.symbol = parse_string_setting(config, "symbol").unwrap_or_default();
        self.offset = parse_offset(config);
        self.pid = parse_pid(config);
        self.arg_index = parse_arg_index(config);
        self.payload_ptr_offset = parse_payload_ptr_offset(config);
        self.tag_offset = parse_tag_offset(config);

        match (rx1_iface, rx2_iface) {
            (Some(rx1), Some(rx2)) if !self.target.is_empty() && !self.symbol.is_empty() => {
                self.rx1_iface = rx1;
                self.rx2_iface = rx2;
                self.enabled = true;
                let payload_ptr = if self.payload_ptr_offset == PAYLOAD_PTR_DIRECT {
                    "direct".to_string()
                } else {
                    self.payload_ptr_offset.to_string()
                };
                debug!(
                    "IFLAT_UPROBE configured: RX1 {} -> RX2 {} (XDP) -> {}+{:#x} in {} (uprobe, pid {}, arg_index {}, payload_ptr_offset {}, tag_offset {})",
                    self.rx1_iface,
                    self.rx2_iface,
                    self.symbol,
                    self.offset,
                    self.target,
                    self.pid,
                    self.arg_index,
                    payload_ptr,
                    self.tag_offset
                );
            }
            _ => {
                self.enabled = false;
                warn!(
                    "iflat_uprobe: rx1_iface/rx2_iface/target/symbol settings are required; program stays disabled"
                );
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

impl MetricsDisplay for IflatUprobeProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = IflatUprobeMetrics::new(registry)?;
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
            .ok_or_else(|| anyhow::anyhow!("metrics not set for iflat_uprobe program"))?;

        // Get the latency accumulator maps from the BPF program
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;
        let sum1_map = open_accumulator_map(ebpf, "LATENCY1_SUM")?;
        let count1_map = open_accumulator_map(ebpf, "LATENCY1_COUNT")?;
        let sum2_map = open_accumulator_map(ebpf, "LATENCY2_SUM")?;
        let count2_map = open_accumulator_map(ebpf, "LATENCY2_COUNT")?;

        let sum1 = sum1_map.get(&ACCUM_KEY, 0).unwrap_or(0);
        let count1 = count1_map.get(&ACCUM_KEY, 0).unwrap_or(0);
        let sum2 = sum2_map.get(&ACCUM_KEY, 0).unwrap_or(0);
        let count2 = count2_map.get(&ACCUM_KEY, 0).unwrap_or(0);

        // The BPF maps hold cumulative values since program load; convert to
        // per-tick deltas so the reported averages reflect recent traffic.
        let (sum1_delta, count1_delta) =
            latency_deltas(&mut self.last_sum1, &mut self.last_count1, sum1, count1);
        match avg_latency_us(sum1_delta, count1_delta) {
            Some(avg_us) => {
                metrics.avg_latency1_us.set(avg_us as f64);
                info!(
                    "IFLAT_UPROBE RX1->RX2 latency: {} us ({} samples, {} -> {})",
                    avg_us, count1_delta, self.rx1_iface, self.rx2_iface
                );
            }
            None => {
                metrics.avg_latency1_us.set(0.0);
                trace!("No new IFLAT_UPROBE leg-1 latency samples");
            }
        }

        let (sum2_delta, count2_delta) =
            latency_deltas(&mut self.last_sum2, &mut self.last_count2, sum2, count2);
        match avg_latency_us(sum2_delta, count2_delta) {
            Some(avg_us) => {
                metrics.avg_latency2_us.set(avg_us as f64);
                info!(
                    "IFLAT_UPROBE RX2->{} latency: {} us ({} samples)",
                    self.symbol, avg_us, count2_delta
                );
            }
            None => {
                metrics.avg_latency2_us.set(0.0);
                trace!("No new IFLAT_UPROBE leg-2 latency samples");
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

impl Default for IflatUprobeProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for IflatUprobeProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("iflat_uprobe", || Box::new(IflatUprobeProgram::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(settings: Option<toml::Table>) -> EbpfProgramConfig {
        EbpfProgramConfig {
            name: "iflat_uprobe".to_string(),
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

    fn full_settings() -> toml::Table {
        settings_of(&[
            ("rx1_iface", toml::Value::String("eno1".to_string())),
            ("rx2_iface", toml::Value::String("tun0".to_string())),
            ("target", toml::Value::String("/bin/app".to_string())),
            ("symbol", toml::Value::String("submitBurst".to_string())),
        ])
    }

    #[test]
    fn test_parse_iface_setting() {
        let config = config_with(Some(settings_of(&[(
            "rx1_iface",
            toml::Value::String("eno1".to_string()),
        )])));
        assert_eq!(
            parse_iface_setting(&config, "rx1_iface").unwrap(),
            Some("eno1".to_string())
        );
        // Missing setting is not an error
        assert_eq!(parse_iface_setting(&config, "rx2_iface").unwrap(), None);
        assert_eq!(
            parse_iface_setting(&config_with(None), "rx1_iface").unwrap(),
            None
        );

        // Present but not a string is an error
        let config = config_with(Some(settings_of(&[("rx1_iface", toml::Value::Integer(1))])));
        assert!(parse_iface_setting(&config, "rx1_iface").is_err());

        // Empty or over-long names are errors
        let config = config_with(Some(settings_of(&[(
            "rx1_iface",
            toml::Value::String(String::new()),
        )])));
        assert!(parse_iface_setting(&config, "rx1_iface").is_err());
        let config = config_with(Some(settings_of(&[(
            "rx1_iface",
            toml::Value::String("a".repeat(MAX_IFACE_LEN + 1)),
        )])));
        assert!(parse_iface_setting(&config, "rx1_iface").is_err());
    }

    #[test]
    fn test_parse_offset_and_pid() {
        let config = config_with(Some(settings_of(&[
            ("offset", toml::Value::Integer(16)),
            ("pid", toml::Value::Integer(1234)),
        ])));
        assert_eq!(parse_offset(&config), 16);
        assert_eq!(parse_pid(&config), 1234);

        // Out of range falls back to the defaults
        let config = config_with(Some(settings_of(&[("offset", toml::Value::Integer(-1))])));
        assert_eq!(parse_offset(&config), 0);
        assert_eq!(parse_offset(&config_with(None)), 0);
        assert_eq!(parse_pid(&config_with(None)), -1);
    }

    #[test]
    fn test_parse_arg_index() {
        let config = config_with(Some(settings_of(&[("arg_index", toml::Value::Integer(2))])));
        assert_eq!(parse_arg_index(&config), 2);

        // Missing: default
        assert_eq!(parse_arg_index(&config_with(None)), DEFAULT_ARG_INDEX);

        // 0, above MAX_ARGS, or negative: default
        for bad in [0i64, (MAX_ARGS + 1) as i64, -2] {
            let config = config_with(Some(settings_of(&[(
                "arg_index",
                toml::Value::Integer(bad),
            )])));
            assert_eq!(parse_arg_index(&config), DEFAULT_ARG_INDEX);
        }
    }

    #[test]
    fn test_parse_payload_ptr_offset() {
        // Missing or -1: direct mode (the argument points at the payload)
        assert_eq!(
            parse_payload_ptr_offset(&config_with(None)),
            PAYLOAD_PTR_DIRECT
        );
        let config = config_with(Some(settings_of(&[(
            "payload_ptr_offset",
            toml::Value::Integer(-1),
        )])));
        assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);

        // Struct mode: offset of the payload pointer member
        let config = config_with(Some(settings_of(&[(
            "payload_ptr_offset",
            toml::Value::Integer(296),
        )])));
        assert_eq!(parse_payload_ptr_offset(&config), 296);

        // Other negative values fall back to the default
        let config = config_with(Some(settings_of(&[(
            "payload_ptr_offset",
            toml::Value::Integer(-2),
        )])));
        assert_eq!(parse_payload_ptr_offset(&config), PAYLOAD_PTR_DIRECT);
    }

    #[test]
    fn test_parse_tag_offset() {
        let config = config_with(Some(settings_of(&[(
            "tag_offset",
            toml::Value::Integer(24),
        )])));
        assert_eq!(parse_tag_offset(&config), 24);

        // Missing or negative: default
        assert_eq!(parse_tag_offset(&config_with(None)), 0);
        let config = config_with(Some(settings_of(&[(
            "tag_offset",
            toml::Value::Integer(-1),
        )])));
        assert_eq!(parse_tag_offset(&config), 0);
    }

    #[test]
    fn test_configure_requires_settings() {
        // No settings (implicit enable): stays disabled, no error
        let mut program = IflatUprobeProgram::new();
        program.configure(&config_with(None)).unwrap();
        assert!(!program.enabled);

        // Only the interfaces: still disabled (target/symbol missing)
        let mut program = IflatUprobeProgram::new();
        let config = config_with(Some(settings_of(&[
            ("rx1_iface", toml::Value::String("eno1".to_string())),
            ("rx2_iface", toml::Value::String("tun0".to_string())),
        ])));
        program.configure(&config).unwrap();
        assert!(!program.enabled);

        // Only the attach target: still disabled (interfaces missing)
        let mut program = IflatUprobeProgram::new();
        let config = config_with(Some(settings_of(&[
            ("target", toml::Value::String("/bin/app".to_string())),
            ("symbol", toml::Value::String("submitBurst".to_string())),
        ])));
        program.configure(&config).unwrap();
        assert!(!program.enabled);

        // All required settings: enabled with defaults
        let mut program = IflatUprobeProgram::new();
        program
            .configure(&config_with(Some(full_settings())))
            .unwrap();
        assert!(program.enabled);
        assert_eq!(program.rx1_iface, "eno1");
        assert_eq!(program.rx2_iface, "tun0");
        assert_eq!(program.target, "/bin/app");
        assert_eq!(program.symbol, "submitBurst");
        assert_eq!(program.offset, 0);
        assert_eq!(program.pid, -1);
        assert_eq!(program.arg_index, DEFAULT_ARG_INDEX);
        assert_eq!(program.payload_ptr_offset, PAYLOAD_PTR_DIRECT);
        assert_eq!(program.tag_offset, 0);
    }

    #[test]
    fn test_bpf_program_name() {
        let program = IflatUprobeProgram::new();
        assert_eq!(program.bpf_program_name(), "iflat_uprobe_xdp_rx1");
        assert_eq!(program.name(), "iflat_uprobe");
    }
}
