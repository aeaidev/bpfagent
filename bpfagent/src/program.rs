use std::{any::Any, collections::HashMap, sync::Arc};

use aya::Ebpf;

/// Trait for EBPF programs that support metrics display
pub trait MetricsDisplay {
    /// Set the Prometheus registry for this program
    fn set_metrics_registry(&mut self, registry: Arc<prometheus::Registry>) -> anyhow::Result<()>;

    /// Display metrics (e.g., drop counts) and update Prometheus metrics
    fn display_metrics(&mut self) -> anyhow::Result<()>;
}

/// Trait for accessing the underlying Ebpf instance
pub trait EbpfAccess {
    /// Get a mutable reference to the underlying Ebpf instance
    fn ebpf_mut(&mut self) -> Option<&mut Ebpf>;
}

/// Trait for EBPF programs
pub trait EbpfProgram: EbpfAccess {
    /// Returns the program name (config name)
    #[allow(dead_code)]
    fn name(&self) -> &str {
        self.bpf_program_name()
    }

    /// Returns the BPF program name inside the object file
    fn bpf_program_name(&self) -> &str;

    /// Loads the BPF program
    fn load(&mut self) -> Result<(), anyhow::Error>;

    /// Starts the program
    fn start(&mut self) -> anyhow::Result<()>;

    /// Downcast to Any for type-specific access
    #[allow(dead_code)]
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Check if this program supports metrics display
    fn supports_metrics(&self) -> bool {
        false
    }

    /// Get a mutable reference to the MetricsDisplay trait if supported
    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        None
    }
}

/// Registry for EBPF programs - maps config names to program constructors
pub struct ProgramRegistry {
    registry: HashMap<String, Box<dyn Fn() -> Box<dyn EbpfProgram> + Send + Sync>>,
}

impl ProgramRegistry {
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    pub fn register<F>(&mut self, config_name: &str, constructor: F)
    where
        F: Fn() -> Box<dyn EbpfProgram> + Send + Sync + 'static,
    {
        self.registry
            .insert(config_name.to_string(), Box::new(constructor));
    }

    pub fn create_program(&self, config_name: &str) -> Option<Box<dyn EbpfProgram>> {
        self.registry.get(config_name).map(|f| f())
    }

    pub fn available_programs(&self) -> Vec<String> {
        self.registry.keys().cloned().collect()
    }
}
