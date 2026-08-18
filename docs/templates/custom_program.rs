//! Example: Creating a Custom eBPF Program
//!
//! This is a template that shows how to create a new eBPF program plugin.
//! To use this:
//! 1. Copy this file to a new module in bpfagent/src/programs/
//! 2. Create a corresponding eBPF program in ebpf/
//! 3. Implement the EbpfProgram trait as shown
//! 4. Register it in register_programs() in bpfagent/src/app.rs by adding:
//!    `crate::programs::your_program::init(&mut registry);`
//!
//! # Structure
//!
//! A typical program consists of:
//! - A struct implementing the EbpfProgram trait plus its mandatory
//!   EbpfAccess supertrait (both defined in programs/traits.rs)
//! - Load: Initialization from bytecode
//! - Start: Attaching to kernel hooks
//! - Optional: Metrics display for Prometheus
//!
//! # Example: Simple Tracepoint Program
//!
//! This shows a minimal program that traces a kernel tracepoint.

use aya::Ebpf;
use std::any::Any;

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
/// - Load the compiled eBPF bytecode
/// - Get references to programs and maps
/// - Perform initialization
///
/// The start() method should:
/// - Attach the eBPF program to kernel hooks
/// - This might be tracepoints, kprobes, or other attachment points
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
        // let ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        //     env!("OUT_DIR"),
        //     "/example"
        // )))?;
        // self.ebpf = Some(ebpf);
        // Ok(())

        // Placeholder for demonstration
        unimplemented!("Implement loading of your eBPF program bytecode")
    }

    fn start(&mut self) -> anyhow::Result<()> {
        // Example: Attach to a tracepoint
        // if let Some(ebpf) = &mut self.ebpf {
        //     let program: &mut TracePoint = ebpf.program_mut("trace_example")
        //         .ok_or_else(|| anyhow::anyhow!("program not found"))?
        //         .try_into()?;
        //     program.load()?;
        //     program.attach("category", "event")?;
        // }
        // Ok(())

        unimplemented!("Implement attaching your eBPF program to kernel hooks")
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
