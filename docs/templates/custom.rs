//! Example: userspace handler matching both eBPF kernel templates
//!
//! Works unchanged with either kernel program:
//! - the Rust template from docs/PLUGINS.md (ebpf/my_program crate, aya-ebpf)
//! - the C template docs/templates/custom_program.c (clang, docs/PLUGINS_C.md)
//!
//! Both templates:
//! - export a tracepoint program named "my_handler"
//! - keep a pid -> event-count map (named `counters` in the C template,
//!   `COUNTERS` in the Rust counter example — set MAP_NAME accordingly)
//!
//! To use this:
//! 1. Build one of the kernel templates so its object lands in OUT_DIR as
//!    "my_program" (Rust: [[bin]] name; C: the clang -o name in build.rs)
//! 2. Copy this file to bpfagent/src/programs/my_program/mod.rs
//! 3. Add `pub mod my_program;` to bpfagent/src/programs/mod.rs
//! 4. Register in register_programs() in bpfagent/src/app.rs:
//!    `crate::programs::my_program::init(&mut registry);`
//! 5. Enable it in the config:
//!    [[ebpf_programs]]
//!    name = "my_program"
//!    enabled = true

use std::sync::Arc;

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::info;
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Object file name in OUT_DIR (Rust [[bin]] name, or clang -o name for C).
const OBJECT_NAME: &str = "my_program";
/// aya program name == the eBPF function name in both templates.
const PROGRAM_NAME: &str = "my_handler";
/// Tracepoint the templates hook: SEC("tracepoint/syscalls/sys_enter_openat").
const TP_CATEGORY: &str = "syscalls";
const TP_EVENT: &str = "sys_enter_openat";
/// Event-count map: `counters` in the C template, `COUNTERS` in the Rust
/// counter example from docs/PLUGINS.md.
const MAP_NAME: &str = "counters";

/// Userspace handler for the my_program template plugin
pub struct MyProgram {
    ebpf: Option<Ebpf>,
    metrics: Option<MyMetrics>,
}

/// Prometheus metrics for MyProgram
pub struct MyMetrics {
    pub events_per_pid: IntGaugeVec,
}

impl MyProgram {
    pub fn new() -> Self {
        Self {
            ebpf: None,
            metrics: None,
        }
    }
}

impl Default for MyProgram {
    fn default() -> Self {
        Self::new()
    }
}

/// EbpfAccess is a mandatory supertrait of EbpfProgram; it gives the agent
/// low-level access to the loaded Ebpf instance (e.g. for eBPF log capture).
impl EbpfAccess for MyProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

impl EbpfProgram for MyProgram {
    fn name(&self) -> &str {
        OBJECT_NAME
    }

    fn bpf_program_name(&self) -> &str {
        PROGRAM_NAME
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        // Identical for Rust- and C-produced objects: both are BPF ELFs.
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/my_program"
        )))?;

        let program: &mut TracePoint = ebpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow::anyhow!("program '{}' not found", PROGRAM_NAME))?
            .try_into()?;

        program.load()?;
        program.attach(TP_CATEGORY, TP_EVENT)?;

        self.ebpf = Some(ebpf);
        Ok(())
    }

    fn start(&mut self) -> anyhow::Result<()> {
        info!("MyProgram started");
        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    // The defaults (false/None) disable all metrics wiring; programs that
    // export metrics must override both.
    fn supports_metrics(&self) -> bool {
        true
    }

    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        Some(self)
    }
}

impl MetricsDisplay for MyProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let events_per_pid = IntGaugeVec::new(
            Opts::new(
                "my_program_events_per_pid",
                "Events counted by my_handler per PID",
            ),
            &["pid"],
        )?;
        registry.register(Box::new(events_per_pid.clone()))?;
        self.metrics = Some(MyMetrics { events_per_pid });
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("metrics not set for my_program"))?;
        let ebpf = self
            .ebpf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;

        let counts: HashMap<_, u32, u64> = ebpf
            .map(MAP_NAME)
            .ok_or_else(|| anyhow::anyhow!("{} map not found", MAP_NAME))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to open {} map: {}", MAP_NAME, e))?;

        for entry in counts.iter() {
            let (pid, count) =
                entry.map_err(|e| anyhow::anyhow!("failed to iterate {}: {}", MAP_NAME, e))?;
            info!("  PID {}: {} events", pid, count);
            metrics
                .events_per_pid
                .with_label_values(&[&pid.to_string()])
                .set(count as i64);
        }
        Ok(())
    }
}

/// Registration function called from register_programs() in bpfagent/src/app.rs
pub fn init(registry: &mut ProgramRegistry) {
    registry.register(OBJECT_NAME, || Box::new(MyProgram::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_creation() {
        let program = MyProgram::new();
        assert_eq!(program.bpf_program_name(), "my_handler");
        assert!(program.supports_metrics());
    }
}
