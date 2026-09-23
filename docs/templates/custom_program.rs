//! Skeleton: userspace module for a custom eBPF program
//!
//! This is a skeleton showing the structure every userspace handler follows.
//! For a complete, compilable example (with metrics) see
//! docs/templates/custom.rs; for the matching eBPF kernel programs see
//! docs/templates/custom_program_ebpf.rs (Rust) and
//! docs/templates/custom_program.c (C).
//!
//! To use this (full walkthrough: docs/PLUGINS.md):
//! 1. Copy this file to a new module in bpfagent/src/programs/<name>/mod.rs
//! 2. Create the corresponding eBPF crate in ebpf/<name>/ and shared-types
//!    crate in common/<name>/
//! 3. Implement the EbpfProgram trait as shown below
//! 4. Add `pub mod <name>;` to bpfagent/src/programs/mod.rs
//! 5. Register it in register_programs() in bpfagent/src/app.rs by adding:
//!    `crate::programs::<name>::init(&mut registry);`
//! 6. Wire up the build:
//!    - add "common/<name>" and "ebpf/<name>" to workspace `members` in the
//!      root Cargo.toml, and "common/<name>" to `default-members` (never the
//!      eBPF crate — it only builds for the BPF target)
//!    - add `<name>-common = { path = "../common/<name>" }` to
//!      [dependencies] in bpfagent/Cargo.toml
//!    - add "<name>-ebpf" to the match in bpfagent/build.rs
//! 7. Add a [[ebpf_programs]] entry to the config
//!
//! # Structure
//!
//! A typical program consists of:
//! - A struct implementing the EbpfProgram trait plus its mandatory
//!   EbpfAccess supertrait (both defined in programs/traits.rs)
//! - load(): load the bytecode, get programs/maps, load + attach them
//! - start(): log that the program is running (attach already happened in
//!   load(); see programs/kfree_skb/mod.rs)
//! - Optional: MetricsDisplay for Prometheus export

use std::any::Any;

use aya::Ebpf;

// The real traits live in programs/traits.rs and are re-exported here;
// do not redefine them locally.
use crate::programs::{EbpfAccess, EbpfProgram, ProgramRegistry};

/// A minimal example program that traces a kernel tracepoint
///
/// # Implementation Steps
///
/// 1. Define your program struct with the required fields
/// 2. Implement EbpfAccess (mandatory supertrait) and EbpfProgram with
///    load() and start() methods
/// 3. Create an init() function to register with the registry
/// 4. Add to programs/mod.rs for public access
#[allow(dead_code)]
pub struct ExampleProgram {
    /// Holds the loaded eBPF program
    ebpf: Option<Ebpf>,
}

impl ExampleProgram {
    /// Create a new instance of the program
    pub fn new() -> Self {
        Self { ebpf: None }
    }
}

impl Default for ExampleProgram {
    fn default() -> Self {
        Self::new()
    }
}

/// EbpfAccess is a mandatory supertrait of EbpfProgram; it gives the agent
/// low-level access to the loaded Ebpf instance (e.g. for eBPF log capture).
impl EbpfAccess for ExampleProgram {
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }
}

/// # Implementing the EbpfProgram Trait
///
/// The load() method should:
/// - Load the compiled eBPF bytecode via Ebpf::load()
/// - Get references to the eBPF programs and maps
/// - Call program.load() and program.attach(...) for each program
/// - Perform any initial setup (e.g., populate config BPF maps)
///
/// The start() method is called after all programs are loaded; existing
/// programs only log there, since attach already happened in load().
///
/// If the program exports Prometheus metrics, also implement MetricsDisplay
/// and override supports_metrics() and as_metrics_mut() to return
/// true/Some(self) — the defaults (false/None) disable all metrics wiring
/// (see programs/sca/mod.rs for a real example).
#[allow(dead_code)]
impl EbpfProgram for ExampleProgram {
    fn bpf_program_name(&self) -> &str {
        "example"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        // Example: Load eBPF program from compiled bytecode
        // let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        //     env!("OUT_DIR"),
        //     "/example"
        // )))?;
        //
        // // Get the program, load it into the kernel, and attach it.
        // // The aya program name is the eBPF *function* name.
        // let program: &mut aya::programs::TracePoint = ebpf
        //     .program_mut("example")
        //     .ok_or_else(|| anyhow::anyhow!("program not found"))?
        //     .try_into()?;
        // program.load()?;
        // program.attach("category", "event")?;
        //
        // self.ebpf = Some(ebpf);
        // Ok(())

        // Placeholder for demonstration
        unimplemented!("Implement loading and attaching of your eBPF program")
    }

    fn start(&mut self) -> anyhow::Result<()> {
        // Attach already happened in load(); just log.
        // log::info!("ExampleProgram started");
        // Ok(())

        unimplemented!("Implement any post-load startup logic (usually just a log line)")
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    // Programs that support metrics must override both methods below:
    //
    // fn supports_metrics(&self) -> bool {
    //     true
    // }
    //
    // fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
    //     Some(self)
    // }
}

/// Registration function called from register_programs() in bpfagent/src/app.rs
///
/// # Example Usage in bpfagent/src/app.rs
///
/// ```ignore
/// fn register_programs() -> ProgramRegistry {
///     let mut registry = ProgramRegistry::new();
///
///     crate::programs::kfree_skb::init(&mut registry);
///     crate::programs::sca::init(&mut registry);
///     // Register your program
///     crate::programs::example::init(&mut registry);
///
///     registry
/// }
/// ```
#[allow(dead_code)]
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("example", || Box::new(ExampleProgram::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_creation() {
        let program = ExampleProgram::new();
        assert_eq!(program.bpf_program_name(), "example");
    }
}
