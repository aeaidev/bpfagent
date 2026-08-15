//! Example: Creating a Custom eBPF Program
//!
//! This is a template that shows how to create a new eBPF program plugin.
//! To use this:
//! 1. Copy this file to a new module in src/programs/
//! 2. Create a corresponding eBPF program in ebpf/
//! 3. Implement the EbpfProgram trait as shown
//! 4. Register it in main.rs by adding: `your_program::init(&mut registry);`
//!
//! # Structure
//!
//! A typical program consists of:
//! - A struct implementing EbpfProgram trait
//! - Load: Initialization from bytecode
//! - Start: Attaching to kernel hooks
//! - Optional: Metrics display for Prometheus
//!
//! # Example: Simple Tracepoint Program
//!
//! This shows a minimal program that traces a kernel tracepoint.

use std::any::Any;
use aya::Ebpf;

/// Trait definitions are in programs/traits.rs
pub trait EbpfProgram {
    fn name(&self) -> &str {
        self.bpf_program_name()
    }
    fn bpf_program_name(&self) -> &str;
    fn load(&mut self) -> Result<(), anyhow::Error>;
    fn start(&mut self) -> anyhow::Result<()>;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A minimal example program that traces a kernel tracepoint
///
/// # Implementation Steps
///
/// 1. Define your program struct with the required fields
/// 2. Implement EbpfProgram trait with load() and start() methods
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
#[allow(dead_code)]
impl EbpfProgram for ExampleProgram {
    fn bpf_program_name(&self) -> &str {
        "example"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        // Example: Load eBPF program from compiled bytecode
        // let ebpf = Ebpf::load(include_bytes_aligned!("../../target/release/example"))?;
        // self.ebpf = Some(ebpf);
        // Ok(())

        // Placeholder for demonstration
        unimplemented!("Implement loading of your eBPF program bytecode")
    }

    fn start(&mut self) -> anyhow::Result<()> {
        // Example: Attach to a tracepoint
        // if let Some(ebpf) = &mut self.ebpf {
        //     let program: &mut Tracepoint = ebpf.program_mut("trace_example")
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
}

/// Registration function called from main.rs
///
/// # Example Usage in main.rs
///
/// ```ignore
/// fn register_programs() -> ProgramRegistry {
///     let mut registry = ProgramRegistry::new();
///
///     // Register your program
///     example::init(&mut registry);
///
///     registry
/// }
/// ```
#[allow(dead_code)]
pub fn init(registry: &mut crate::programs::ProgramRegistry) {
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
