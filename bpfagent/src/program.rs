use std::any::Any;

/// Trait for EBPF programs
pub trait EbpfProgram {
    /// Returns the program name
    fn name(&self) -> &str;

    /// Returns the enabled status
    fn enabled(&self) -> bool;

    /// Loads the BPF program
    fn load(&mut self) -> Result<(), anyhow::Error>;

    /// Starts the program (returns a future that runs until cancelled)
    fn start(&mut self) -> anyhow::Result<()>;

    /// Downcast to Any for type-specific access
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Registry for EBPF programs
pub struct ProgramRegistry {
    programs: Vec<Box<dyn EbpfProgram>>,
    enabled_programs: Vec<String>,
}

impl ProgramRegistry {
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
            enabled_programs: Vec::new(),
        }
    }

    /// Register a program with the registry
    pub fn register(&mut self, program: Box<dyn EbpfProgram>) {
        self.programs.push(program);
    }

    /// Configure which programs are enabled based on config
    pub fn configure_from_config(&mut self, config: &crate::config::DaemonConfig) {
        self.enabled_programs.clear();

        for program in &mut self.programs {
            let name = program.name().to_string();
            if config.is_program_enabled(&name) {
                self.enabled_programs.push(name);
            }
        }
    }

    /// Get list of enabled program names
    pub fn enabled_programs(&self) -> &[String] {
        &self.enabled_programs
    }

    /// Get mutable reference to a program by name
    pub fn get_program_mut(&mut self, name: &str) -> Option<&mut Box<dyn EbpfProgram>> {
        self.programs.iter_mut().find(|p| p.name() == name)
    }

    /// Load all enabled programs
    pub fn load_enabled(&mut self) -> Result<(), anyhow::Error> {
        for program in &mut self.programs {
            if self.enabled_programs.contains(&program.name().to_string()) {
                program.load()?;
            }
        }
        Ok(())
    }

    /// Start all enabled programs
    pub fn start_enabled(&mut self) -> Result<(), anyhow::Error> {
        for program in &mut self.programs {
            if self.enabled_programs.contains(&program.name().to_string()) {
                program.start()?;
            }
        }
        Ok(())
    }
}
