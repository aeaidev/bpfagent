//! Program registry for managing available and loaded eBPF programs

use super::traits::EbpfProgram;
use std::collections::HashMap;

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
