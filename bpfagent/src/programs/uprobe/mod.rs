//! uprobe eBPF Program - Userspace Function Call Tracing
//!
//! This module provides a BPF program that attaches a uprobe to a function
//! in a userspace binary or shared library and counts calls per process,
//! snapshotting the function's arguments.
//!
//! The eBPF program keeps one CallRecord per calling pid in the CALLS map:
//! a cumulative call count plus the arguments of the most recent call (the
//! six integer/pointer argument registers of the x86_64 SysV ABI: rdi, rsi,
//! rdx, rcx, r8, r9). Userspace reads the map every display tick, converts
//! the cumulative counts to per-tick deltas for the Prometheus counter, and
//! prints the last call's arguments in interactive mode.
//!
//! # Configuration
//!
//! The attach target has no sensible default, so `target` and `symbol` are
//! required settings; when they are missing (e.g. the program got enabled
//! implicitly because the config lists no `[[ebpf_programs]]` entries), the
//! program logs a warning and stays disabled instead of failing:
//!
//! ```toml
//! [[ebpf_programs]]
//! name = "uprobe"
//! enabled = true
//!
//! [ebpf_programs.settings]
//! target = "/path/to/app"     # binary or shared library to instrument
//! symbol = "function_name"    # function to trace (ELF symbol)
//! # offset = 0                # extra byte offset past the symbol
//! # pid = -1                  # -1 = all processes, or a specific PID
//! # string_arg = 0            # 1-6: also read this argument as a C string
//! ```
//!
//! # Prometheus Metrics
//!
//! - `uprobe_calls_total{pname}`: Total number of calls to the traced
//!   function, per calling process (`pname` = "comm (PID n)")

use std::{any::Any, collections::HashMap as StdHashMap, num::NonZeroU32, sync::Arc};

use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{
        uprobe::{UProbeAttachLocation, UProbeScope},
        UProbe,
    },
    Ebpf,
};
use log::{debug, info, trace, warn};
use prometheus::{IntCounterVec, Opts, Registry};
use uprobe_common::{CallRecord, MAX_ARGS, STRING_ARG_KEY};

use crate::{
    config::EbpfProgramConfig,
    programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry},
};

/// Prometheus metrics for the uprobe program
pub struct UprobeMetrics {
    pub calls_total: IntCounterVec,
}

impl UprobeMetrics {
    /// Create new uprobe Prometheus metrics with proper error handling
    ///
    /// # Errors
    /// Returns error if metric creation or registration fails
    pub fn new(registry: Arc<Registry>) -> anyhow::Result<Self> {
        let calls_total = IntCounterVec::new(
            Opts::new(
                "uprobe_calls_total",
                "Total number of calls to the traced function",
            ),
            &["pname"],
        )
        .context("failed to create calls_total counter")?;

        registry
            .register(Box::new(calls_total.clone()))
            .context("failed to register calls_total counter")?;

        Ok(Self { calls_total })
    }
}

/// BPF program wrapper for uprobe (userspace function call tracing)
pub struct UprobeProgram {
    name: String,
    ebpf: Option<Ebpf>,
    metrics: Option<UprobeMetrics>,
    /// False when target/symbol are not configured: load() and
    /// display_metrics() no-op so the program can never fail an implicit
    /// enable (config without [[ebpf_programs]] entries).
    enabled: bool,
    /// Path of the binary or shared library to instrument (required setting)
    target: String,
    /// Function symbol to trace (required setting)
    symbol: String,
    /// Extra byte offset past the symbol (optional, default 0)
    offset: u64,
    /// PID filter: <= 0 traces all processes (optional, default -1)
    pid: i32,
    /// Argument to also read as a C string: 0 = none, 1..=MAX_ARGS
    /// (optional, default 0)
    string_arg: u32,
    /// Last cumulative call count seen per pid, used to compute per-tick
    /// deltas from the cumulative BPF counters
    last_counts: StdHashMap<u32, u64>,
}

impl UprobeProgram {
    /// Creates a new uprobe BPF program
    pub fn new() -> Self {
        Self {
            name: "uprobe".to_string(),
            ebpf: None,
            metrics: None,
            enabled: false,
            target: String::new(),
            symbol: String::new(),
            offset: 0,
            pid: -1,
            string_arg: 0,
            last_counts: StdHashMap::new(),
        }
    }

    /// Set the Prometheus metrics for this program (internal method)
    fn set_metrics(&mut self, metrics: UprobeMetrics) {
        self.metrics = Some(metrics);
    }
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
                "invalid uprobe {} setting '{}': out of range; using default",
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

/// Parse the optional `string_arg` index (default 0 = none, 1..=MAX_ARGS =
/// read that argument as a C string).
pub fn parse_string_arg(config: &EbpfProgramConfig) -> u32 {
    parse_int_setting(config, "string_arg", 0, |v| {
        u32::try_from(v).ok().filter(|n| *n as usize <= MAX_ARGS)
    })
}

/// Map the configured PID filter to a uprobe attach scope: positive PIDs
/// trace that one process, anything else traces all processes.
///
/// # Examples
///
/// ```
/// use aya::programs::uprobe::UProbeScope;
/// use bpfagent::programs::uprobe::pid_scope;
///
/// assert!(matches!(pid_scope(-1), UProbeScope::AllProcesses));
/// assert!(matches!(pid_scope(0), UProbeScope::AllProcesses));
/// assert!(matches!(pid_scope(1234), UProbeScope::OneProcess(p) if p.get() == 1234));
/// ```
pub fn pid_scope(pid: i32) -> UProbeScope {
    u32::try_from(pid)
        .ok()
        .and_then(NonZeroU32::new)
        .map_or(UProbeScope::AllProcesses, UProbeScope::OneProcess)
}

/// Render a NUL-padded byte buffer (comm, arg_str) as a string.
fn cstr_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl EbpfProgram for UprobeProgram {
    fn name(&self) -> &str {
        &self.name
    }

    fn bpf_program_name(&self) -> &str {
        "uprobe_trace_call"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        if !self.enabled {
            debug!("uprobe: no target/symbol configured, skipping load");
            return Ok(());
        }
        debug!("Loading BPF program: {}", self.name);

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/uprobe"
        )))?;

        // Write the string-argument setting before the program starts using
        // it; 0 disables the C-string read on the eBPF side.
        let mut string_arg_map = HashMap::<_, u32, u32>::try_from(
            ebpf.map_mut("STRING_ARG_MAP")
                .ok_or_else(|| anyhow::anyhow!("STRING_ARG_MAP map not found"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to open STRING_ARG_MAP map: {}", e))?;
        string_arg_map
            .insert(&STRING_ARG_KEY, &self.string_arg, 0)
            .map_err(|e| anyhow::anyhow!("failed to configure STRING_ARG_MAP: {}", e))?;

        let program: &mut UProbe = ebpf
            .program_mut("uprobe_trace_call")
            .ok_or_else(|| anyhow::anyhow!("program 'uprobe_trace_call' not found"))?
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
        debug!(
            "Attached uprobe uprobe_trace_call: {}+{:#x} in {} (pid filter {})",
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
        self.target = parse_string_setting(config, "target").unwrap_or_default();
        self.symbol = parse_string_setting(config, "symbol").unwrap_or_default();
        self.offset = parse_offset(config);
        self.pid = parse_pid(config);
        self.string_arg = parse_string_arg(config);
        self.enabled = !(self.target.is_empty() || self.symbol.is_empty());
        if self.enabled {
            debug!(
                "uprobe configured: {}+{:#x} in {}, pid {}, string_arg {}",
                self.symbol, self.offset, self.target, self.pid, self.string_arg
            );
        } else {
            warn!("uprobe: 'target' and 'symbol' settings are required; program disabled");
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

impl MetricsDisplay for UprobeProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = UprobeMetrics::new(registry)?;
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
            .ok_or_else(|| anyhow::anyhow!("metrics not set for uprobe program"))?;

        // Get the per-process call records from the BPF program
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;
        let calls: HashMap<_, u32, CallRecord> = ebpf
            .map("CALLS")
            .ok_or_else(|| anyhow::anyhow!("CALLS map not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to open CALLS map: {}", e))?;

        let mut lines = Vec::new();
        for entry in calls.iter() {
            let (pid, record) = match entry {
                Ok(kv) => kv,
                Err(e) => {
                    warn!("failed to read CALLS entry: {}", e);
                    continue;
                }
            };

            // The BPF map holds cumulative counts since program load; convert
            // to per-tick deltas so the counter and display reflect recent
            // traffic.
            let last = self.last_counts.insert(pid, record.count).unwrap_or(0);
            let delta = record.count.saturating_sub(last);
            if delta == 0 {
                continue;
            }

            let pname = format!("{} (PID {})", cstr_string(&record.comm), pid);
            metrics
                .calls_total
                .with_label_values(&[&pname])
                .inc_by(delta);

            let mut line = format!(
                "  {}: {} calls (+{}), last args: {:x?}",
                pname, record.count, delta, record.args
            );
            let arg_str = cstr_string(&record.arg_str);
            if !arg_str.is_empty() {
                line.push_str(&format!(", str=\"{}\"", arg_str));
            }
            lines.push(line);
        }

        if lines.is_empty() {
            trace!("No new uprobe calls");
        } else {
            info!("--- uprobe calls to {} ({}) ---", self.symbol, self.target);
            for line in lines {
                info!("{}", line);
            }
        }

        Ok(())
    }
}

impl Default for UprobeProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfAccess for UprobeProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// Initialize this program by registering it with the registry
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("uprobe", || Box::new(UprobeProgram::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(settings: Option<toml::Table>) -> EbpfProgramConfig {
        EbpfProgramConfig {
            name: "uprobe".to_string(),
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
    fn test_parse_string_setting() {
        let config = config_with(Some(settings_of(&[(
            "target",
            toml::Value::String("/bin/app".to_string()),
        )])));
        assert_eq!(
            parse_string_setting(&config, "target"),
            Some("/bin/app".to_string())
        );
        assert_eq!(parse_string_setting(&config, "symbol"), None);

        let empty = config_with(None);
        assert_eq!(parse_string_setting(&empty, "target"), None);
    }

    #[test]
    fn test_parse_offset() {
        let config = config_with(Some(settings_of(&[("offset", toml::Value::Integer(16))])));
        assert_eq!(parse_offset(&config), 16);

        // Negative offsets fall back to the default
        let config = config_with(Some(settings_of(&[("offset", toml::Value::Integer(-1))])));
        assert_eq!(parse_offset(&config), 0);

        assert_eq!(parse_offset(&config_with(None)), 0);
    }

    #[test]
    fn test_parse_pid() {
        let config = config_with(Some(settings_of(&[("pid", toml::Value::Integer(1234))])));
        assert_eq!(parse_pid(&config), 1234);

        assert_eq!(parse_pid(&config_with(None)), -1);
    }

    #[test]
    fn test_parse_string_arg() {
        let config = config_with(Some(settings_of(&[(
            "string_arg",
            toml::Value::Integer(3),
        )])));
        assert_eq!(parse_string_arg(&config), 3);

        // Out of range (> MAX_ARGS) falls back to the default
        let config = config_with(Some(settings_of(&[(
            "string_arg",
            toml::Value::Integer((MAX_ARGS + 1) as i64),
        )])));
        assert_eq!(parse_string_arg(&config), 0);

        // Negative falls back to the default
        let config = config_with(Some(settings_of(&[(
            "string_arg",
            toml::Value::Integer(-2),
        )])));
        assert_eq!(parse_string_arg(&config), 0);

        assert_eq!(parse_string_arg(&config_with(None)), 0);
    }

    #[test]
    fn test_pid_scope() {
        assert!(matches!(pid_scope(-1), UProbeScope::AllProcesses));
        assert!(matches!(pid_scope(0), UProbeScope::AllProcesses));
        assert!(matches!(pid_scope(1234), UProbeScope::OneProcess(p) if p.get() == 1234));
    }

    #[test]
    fn test_cstr_string() {
        assert_eq!(cstr_string(b"hello\0\0\0"), "hello");
        assert_eq!(cstr_string(&[0; 4]), "");
        assert_eq!(cstr_string(b"no-nul"), "no-nul");
    }

    #[test]
    fn test_configure_requires_target_and_symbol() {
        // No settings (implicit enable): stays disabled, no error
        let mut program = UprobeProgram::new();
        program.configure(&config_with(None)).unwrap();
        assert!(!program.enabled);

        // Only target: still disabled
        let mut program = UprobeProgram::new();
        let config = config_with(Some(settings_of(&[(
            "target",
            toml::Value::String("/bin/app".to_string()),
        )])));
        program.configure(&config).unwrap();
        assert!(!program.enabled);

        // target + symbol: enabled with defaults
        let mut program = UprobeProgram::new();
        let config = config_with(Some(settings_of(&[
            ("target", toml::Value::String("/bin/app".to_string())),
            ("symbol", toml::Value::String("my_func".to_string())),
        ])));
        program.configure(&config).unwrap();
        assert!(program.enabled);
        assert_eq!(program.target, "/bin/app");
        assert_eq!(program.symbol, "my_func");
        assert_eq!(program.offset, 0);
        assert_eq!(program.pid, -1);
        assert_eq!(program.string_arg, 0);
    }

    #[test]
    fn test_bpf_program_name() {
        let program = UprobeProgram::new();
        assert_eq!(program.bpf_program_name(), "uprobe_trace_call");
        assert_eq!(program.name(), "uprobe");
    }
}
