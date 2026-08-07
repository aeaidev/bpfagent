//! BPF Program Registry and Trait Definitions
//!
//! This module provides the core traits and registry for managing eBPF programs.
//! It defines the lifecycle (load, start, metrics) and plugin architecture for
//! adding new eBPF programs to the agent.
//!
//! # Architecture
//!
//! The design uses trait objects to support multiple eBPF programs:
//! - `EbpfProgram`: Core trait for program lifecycle
//! - `MetricsDisplay`: Optional trait for programs that export metrics
//! - `EbpfAccess`: Provides access to the underlying Aya Ebpf instance
//!
//! # Adding New Programs
//!
//! 1. Create a new module (e.g., `my_program.rs`)
//! 2. Implement `EbpfProgram` and optionally `MetricsDisplay`
//! 3. Call `registry.register()` in the module's `init()` function
//! 4. Add the module to `main.rs` and call its `init()` in `register_programs()`

use std::{any::Any, collections::HashMap, sync::Arc};

use aya::Ebpf;

/// Trait for eBPF programs that support metrics display and export
pub trait MetricsDisplay {
    /// Set the Prometheus registry for collecting metrics
    ///
    /// # Errors
    /// Returns error if metric registration fails
    fn set_metrics_registry(&mut self, registry: Arc<prometheus::Registry>) -> anyhow::Result<()>;

    /// Display collected metrics and update Prometheus metrics
    ///
    /// This is called periodically (typically every 3 seconds) to read data
    /// from the eBPF program's maps and update Prometheus counters/gauges.
    ///
    /// # Errors
    /// Returns error if metric reading or updating fails
    fn display_metrics(&mut self) -> anyhow::Result<()>;
}

/// Trait for accessing the underlying Aya Ebpf instance
pub trait EbpfAccess {
    /// Get a mutable reference to the underlying Ebpf instance
    ///
    /// This is used for low-level access to the loaded eBPF program,
    /// such as reading from BPF maps or attaching to additional tracepoints.
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf>;
}

/// Trait for eBPF programs managed by the agent
///
/// Defines the lifecycle and interface for eBPF programs:
/// 1. Load: Load the compiled eBPF bytecode into the kernel
/// 2. Start: Attach to kernel events (tracepoints, kprobes, etc.)
/// 3. Optional: Display metrics if the program supports metrics
pub trait EbpfProgram: EbpfAccess {
    /// Returns the program name (typically matches the config name)
    #[allow(dead_code)]
    fn name(&self) -> &str {
        self.bpf_program_name()
    }

    /// Returns the name of the BPF program inside the compiled object file
    fn bpf_program_name(&self) -> &str;

    /// Load the compiled eBPF program into the kernel
    ///
    /// This should:
    /// 1. Load the compiled bytecode via `Ebpf::load()`
    /// 2. Get references to the eBPF programs and maps
    /// 3. Perform any initial setup (e.g., populate BPF maps)
    ///
    /// # Errors
    /// Returns error if loading or program setup fails
    fn load(&mut self) -> Result<(), anyhow::Error>;

    /// Start the eBPF program by attaching to kernel events
    ///
    /// This should attach the program to appropriate kernel hooks
    /// (tracepoints, kprobes, etc.) to start collecting data.
    ///
    /// # Errors
    /// Returns error if attachment fails
    fn start(&mut self) -> anyhow::Result<()>;

    /// Downcast to Any for type-specific access
    ///
    /// Used internally to access program-specific functionality
    #[allow(dead_code)]
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Check if this program supports metrics display
    ///
    /// Programs that collect data for Prometheus should return `true`
    fn supports_metrics(&self) -> bool {
        false
    }

    /// Get a mutable reference to the MetricsDisplay trait if supported
    ///
    /// Returns `Some` if this program implements `MetricsDisplay`,
    /// used for periodic metrics collection and display
    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        None
    }
}

/// Registry for managing available and loaded eBPF programs
pub struct ProgramRegistry {
    factories: HashMap<String, Box<dyn Fn() -> Box<dyn EbpfProgram>>>,
}

impl ProgramRegistry {
    /// Create a new empty program registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register an eBPF program factory
    ///
    /// The factory function will be called each time a program instance
    /// needs to be created.
    pub fn register<F>(&mut self, name: &str, factory: F)
    where
        F: Fn() -> Box<dyn EbpfProgram> + 'static,
    {
        self.factories.insert(name.to_string(), Box::new(factory));
    }

    /// Get list of all registered program names
    pub fn available_programs(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }

    /// Create an instance of a registered program
    ///
    /// Returns `None` if the program name is not registered
    pub fn create_program(&self, name: &str) -> Option<Box<dyn EbpfProgram>> {
        self.factories.get(name).map(|f| f())
    }
}

impl Default for ProgramRegistry {
    fn default() -> Self {
        Self::new()
    }
}
