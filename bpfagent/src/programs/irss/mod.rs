//! IRSS eBPF Program - UDP-to-Raw-IP Forwarding Latency Tracing
//!
//! This module provides a BPF program that measures how long the IRSS
//! component holds one datagram: from the incoming UDP packet (from CRYPTO
//! to the configured listen port, default 5020) to the outgoing raw-IP
//! packet (to the configured destination, default 10.10.10.253). See
//! docs/IRSS.md for the data flow.
//!
//! The eBPF program keys each datagram on the tag in its first 4 payload
//! bytes (big-endian):
//! - RX (`irss_udp_recvmsg` kprobe + `sys_exit_recvmsg`): the kprobe checks
//!   the receiving socket's local port against LISTEN_PORT_MAP and stashes
//!   the user_msghdr pointer; the exit handler reads the payload tag from
//!   the now-filled buffer and stores the receipt timestamp in TIMESTAMP_MAP.
//! - TX (`sys_enter_sendmsg`): if the sendmsg() destination matches
//!   RAW_DEST_MAP, it looks up the tag; on a match it removes the record and
//!   adds the latency (now - stored) to the cumulative
//!   LATENCY_SUM/LATENCY_COUNT accumulators.
//!
//! Both filters are runtime-configurable; unrelated recvmsg()/sendmsg()
//! traffic on the host cannot pollute the measurement — no PID/FD discovery
//! needed (unlike SCA).
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
//! Both filters default to the docs/IRSS.md data flow and can be changed in
//! the config file:
//!
//! ```toml
//! [[ebpf_programs]]
//! name = "irss"
//! enabled = true
//!
//! [ebpf_programs.settings]
//! listen_port = 5020
//! raw_dest = "10.10.10.253"
//! ```
//!
//! # Prometheus Metrics
//!
//! - `irss_avg_latency_us`: Average UDP-to-raw-IP forwarding latency in
//!   microseconds over the last display interval (0 when no traffic)

use std::{any::Any, net::Ipv4Addr, sync::Arc};

use aya::{
    maps::HashMap,
    programs::{KProbe, TracePoint},
    Ebpf,
};
use irss_common::{KPROBE_FUNCTION, LISTEN_PORT, LISTEN_PORT_KEY, RAW_DEST, RAW_DEST_KEY};
use log::{debug, info, trace, warn};
use prometheus::{Gauge, Opts, Registry};

use crate::{
    config::EbpfProgramConfig,
    programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry},
};

/// Key of the single LATENCY_SUM/LATENCY_COUNT accumulator in the BPF maps.
const ACCUM_KEY: u32 = 0;

/// Prometheus metrics for IRSS program
pub struct IrssMetrics {
    pub avg_latency_us: Gauge,
}

impl IrssMetrics {
    /// Create new IRSS Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let avg_latency_us = Gauge::with_opts(Opts::new(
            "irss_avg_latency_us",
            "Average UDP-to-raw-IP forwarding latency in microseconds (per-interval moving average)",
        ))
        .map_err(|e| anyhow::anyhow!("failed to create avg_latency_us gauge: {}", e))?;

        registry
            .register(Box::new(avg_latency_us.clone()))
            .map_err(|e| anyhow::anyhow!("failed to register avg_latency_us gauge: {}", e))?;

        Ok(Self { avg_latency_us })
    }
}

/// BPF program wrapper for IRSS (UDP-to-raw-IP forwarding latency)
pub struct IrssProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<IrssMetrics>,
    /// Raw-IP destination the TX filter matches (default: irss_common::RAW_DEST)
    raw_dest: [u8; 4],
    /// UDP listen port the RX filter accepts (default: irss_common::LISTEN_PORT)
    listen_port: u16,
    /// Last cumulative latency sum (ns) seen, used to compute per-tick deltas
    last_sum: u64,
    /// Last cumulative sample count seen, used to compute per-tick deltas
    last_count: u64,
}

impl IrssProgram {
    /// Creates a new IRSS BPF program
    pub fn new() -> Self {
        Self {
            name: "irss".to_string(),
            ebpf: None,
            metrics: None,
            raw_dest: RAW_DEST,
            listen_port: LISTEN_PORT,
            last_sum: 0,
            last_count: 0,
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: IrssMetrics) {
        self.metrics = Some(metrics);
    }
}

/// Parse the optional `raw_dest` IPv4 address from the program's settings
/// table. Falls back to the compiled-in default (irss_common::RAW_DEST) when
/// the setting is missing, not a string, or not a valid IPv4 address.
pub fn parse_raw_dest(config: &EbpfProgramConfig) -> [u8; 4] {
    let default = || RAW_DEST;
    let Some(value) = config
        .settings
        .as_ref()
        .and_then(|s| s.get("raw_dest"))
        .and_then(|v| v.as_str())
    else {
        return default();
    };
    match value.parse::<Ipv4Addr>() {
        Ok(ip) => ip.octets(),
        Err(e) => {
            warn!(
                "invalid irss raw_dest setting '{}': {}; using default {:?}",
                value,
                e,
                default()
            );
            default()
        }
    }
}

/// Parse the optional `listen_port` UDP port from the program's settings
/// table. Falls back to the compiled-in default (irss_common::LISTEN_PORT)
/// when the setting is missing, not an integer, or out of range.
pub fn parse_listen_port(config: &EbpfProgramConfig) -> u16 {
    let default = || LISTEN_PORT;
    let Some(value) = config
        .settings
        .as_ref()
        .and_then(|s| s.get("listen_port"))
        .and_then(|v| v.as_integer())
    else {
        return default();
    };
    match u16::try_from(value) {
        Ok(port) if port != 0 => port,
        _ => {
            warn!(
                "invalid irss listen_port setting '{}': out of range; using default {}",
                value,
                default()
            );
            default()
        }
    }
}

impl EbpfProgram for IrssProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "irss_sys_enter_sendmsg"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/irss"
        )))?;

        // Write the configured filter values into the BPF config maps before
        // the programs start matching on them. The raw-IP destination is
        // stored as network-order address bytes in a native u32.
        let mut raw_dest_map = HashMap::<_, u32, u32>::try_from(
            ebpf.map_mut("RAW_DEST_MAP")
                .ok_or_else(|| anyhow::anyhow!("RAW_DEST_MAP map not found"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to open RAW_DEST_MAP map: {}", e))?;
        raw_dest_map
            .insert(&RAW_DEST_KEY, &u32::from_ne_bytes(self.raw_dest), 0)
            .map_err(|e| anyhow::anyhow!("failed to configure RAW_DEST_MAP: {}", e))?;

        let mut listen_port_map = HashMap::<_, u32, u32>::try_from(
            ebpf.map_mut("LISTEN_PORT_MAP")
                .ok_or_else(|| anyhow::anyhow!("LISTEN_PORT_MAP map not found"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to open LISTEN_PORT_MAP map: {}", e))?;
        listen_port_map
            .insert(&LISTEN_PORT_KEY, &(self.listen_port as u32), 0)
            .map_err(|e| anyhow::anyhow!("failed to configure LISTEN_PORT_MAP: {}", e))?;
        debug!(
            "IRSS filters: RX listen port {}, TX raw-IP destination {}",
            self.listen_port,
            Ipv4Addr::from(self.raw_dest)
        );

        for (name, category, event) in irss_common::TRACEPOINTS {
            let program: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program '{}' not found", name))?
                .try_into()?;
            program.load()?;
            program.attach(category, event)?;
            debug!("Attached tracepoint {}:{}:{}", name, category, event);
        }

        // Attach the RX port-filter kprobe (udp_recvmsg)
        let program: &mut KProbe = ebpf
            .program_mut("irss_udp_recvmsg")
            .ok_or_else(|| anyhow::anyhow!("program 'irss_udp_recvmsg' not found"))?
            .try_into()?;
        program.load()?;
        program.attach(KPROBE_FUNCTION, 0)?;
        debug!("Attached kprobe irss_udp_recvmsg:{}", KPROBE_FUNCTION);

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
        self.raw_dest = parse_raw_dest(config);
        self.listen_port = parse_listen_port(config);
        debug!(
            "IRSS configured: listen port {}, raw-IP destination {}",
            self.listen_port,
            Ipv4Addr::from(self.raw_dest)
        );
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
pub fn avg_latency_us(sum_delta: u64, count_delta: u64) -> Option<u64> {
    if count_delta == 0 {
        None
    } else {
        Some(sum_delta / count_delta / 1_000)
    }
}

impl MetricsDisplay for IrssProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = IrssMetrics::new(registry)?;
        self.set_metrics(metrics);
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        // Get metrics or return early if not set
        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metrics not set for irss program"))?;

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
                    "IRSS forwarding latency: {} us ({} samples, UDP:{} -> raw IP {})",
                    avg_us,
                    count_delta,
                    self.listen_port,
                    Ipv4Addr::from(self.raw_dest)
                );
            }
            None => {
                metrics.avg_latency_us.set(0.0);
                trace!("No new IRSS latency samples");
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

impl Default for IrssProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for IrssProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("irss", || Box::new(IrssProgram::new()));
}
