# Plugin Development Guide

Learn how to create new eBPF programs (plugins) for BPF Agent.

## Overview

A plugin consists of three parts:
1. **eBPF kernel program** - collects data from kernel
2. **Shared types** - common structures between kernel and userspace
3. **Userspace handler** - collects and displays metrics

## Quick Start

A complete, copy-ready program template is also available at
[`docs/templates/custom_program.rs`](templates/custom_program.rs).

### 1. Create eBPF Program Directory

```bash
mkdir -p ebpf/my_program/src
cd ebpf/my_program
```

Create `Cargo.toml`:
```toml
[package]
name = "my_program-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = { git = "https://github.com/aya-rs/aya" }
aya-log-ebpf = { git = "https://github.com/aya-rs/aya" }

[lib]
path = "src/main.rs"
```

Create `src/main.rs`:
```rust
#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, EbpfContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn my_handler(ctx: TracePointContext) -> u32 {
    match unsafe { try_handler(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_handler(ctx: &TracePointContext) -> Result<u32, u32> {
    info!(ctx, "Tracepoint handler called");
    Ok(0)
}
```

### 2. Create Shared Types

```bash
mkdir -p common/my_program/src
cd common/my_program
```

Create `Cargo.toml`:
```toml
[package]
name = "my_program-common"
version = "0.1.0"
edition = "2021"
```

Create `src/lib.rs`:
```rust
#[repr(C)]
pub struct MyEvent {
    pub pid: u32,
    pub timestamp: u64,
}
```

### 3. Create Userspace Handler

```bash
mkdir -p bpfagent/src/programs/my_program
```

Create `bpfagent/src/programs/my_program/mod.rs`:
```rust
use std::sync::Arc;
use aya::Ebpf;
use log::info;
use prometheus::Registry;

pub struct MyProgram {
    ebpf: Option<Ebpf>,
}

impl MyProgram {
    pub fn new() -> Self {
        Self { ebpf: None }
    }
}

// Implement EbpfProgram trait
use crate::program::EbpfProgram;

impl EbpfProgram for MyProgram {
    fn bpf_program_name(&self) -> &str {
        "my_program_handler"
    }

    fn load(&mut self) -> Result<(), anyhow::Error> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/my_program"
        )))?;
        
        let program = ebpf
            .program_mut("my_program_handler")
            .ok_or_else(|| anyhow::anyhow!("program not found"))?
            .try_into()?;
        
        program.load()?;
        program.attach("category", "event")?;
        
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
}
```

### 4. Register the Program

Add the module in `bpfagent/src/programs/mod.rs`:
```rust
pub mod my_program;  // Add this
```

Then register it in `bpfagent/src/app.rs` (`register_programs`):
```rust
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();
    crate::programs::kfree_skb::init(&mut registry);
    crate::programs::sca::init(&mut registry);
    crate::programs::my_program::init(&mut registry);  // Add this
    registry
}
```

### 5. Create build.rs

Create `bpfagent/build.rs` entry:
```rust
// This is already set up in the workspace
// No changes needed if using aya-build
```

### 6. Add to Configuration

Edit `config/bpfagent.conf.example`:
```toml
[[ebpf_programs]]
name = "my_program"
enabled = false  # Disabled by default if optional
```

## Complete Example: Simple Counter

### eBPF Program (`ebpf/counter/src/main.rs`)

```rust
#![no_std]
#![no_main]

use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::TracePointContext;

#[aya_ebpf::macros::map]
pub static COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[aya_ebpf::macros::tracepoint]
pub fn count_events(ctx: TracePointContext) -> u32 {
    let pid = unsafe { (*ctx.as_ptr()).pid_t } as u32;
    
    if let Some(count) = COUNTERS.get(&pid) {
        COUNTERS.insert(&pid, &(count + 1), 0).unwrap_or_default();
    } else {
        COUNTERS.insert(&pid, &1, 0).unwrap_or_default();
    }
    
    0
}
```

### Shared Types (`common/counter/src/lib.rs`)

```rust
pub struct EventCount {
    pub pid: u32,
    pub count: u64,
}
```

### Userspace Handler (`bpfagent/src/programs/counter/mod.rs`)

```rust
use aya::maps::HashMap;
use prometheus::IntGaugeVec;

pub struct CounterProgram {
    ebpf: Option<Ebpf>,
    metrics: Option<CounterMetrics>,
}

pub struct CounterMetrics {
    pub event_count: IntGaugeVec,
}

impl MetricsDisplay for CounterProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        let metrics = CounterMetrics {
            event_count: IntGaugeVec::new(
                Opts::new("counter_events", "Event count per PID"),
                &["pid"],
            )?,
        };
        registry.register(Box::new(metrics.event_count.clone()))?;
        self.metrics = Some(metrics);
        Ok(())
    }

    fn display_metrics(&mut self) -> anyhow::Result<()> {
        // Read from COUNTERS map and update metrics
        Ok(())
    }
}
```

## Testing Your Plugin

### Unit Tests

Create `bpfagent/src/programs/my_program/tests.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let program = MyProgram::new();
        assert_eq!(program.bpf_program_name(), "my_program_handler");
    }
}
```

### Integration Tests

Create `bpfagent/tests/my_program_test.rs`:
```rust
#[test]
fn test_my_program_loads() {
    // Load and verify the program
}
```

## Best Practices

1. **Keep eBPF Programs Small** - Less complex code = fewer bugs
2. **Use Meaningful Names** - Map names match eBPF source
3. **Document Everything** - Explain what the program does
4. **Add Error Handling** - Handle all error cases
5. **Test Thoroughly** - Unit and integration tests
6. **Follow Conventions** - Match existing program style
7. **Version Carefully** - Don't break existing configs
8. **Provide Examples** - Show how to use the program

## Publishing

1. Create a PR with your plugin
2. Include documentation
3. Include example configuration
4. Include tests
5. Request review from maintainers
6. After merge, it's available to all users!

## Resources

- [Aya Documentation](https://docs.aya-rs.dev/)
- [Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF Maps](https://ebpf.io/what-is-ebpf/#maps)
- [Prometheus Client](https://prometheus.io/docs/instrumenting/clientlibs/)

## Troubleshooting

### Program fails to load
```bash
RUST_LOG=debug cargo run --release -- --daemon=false --verbose
```

### Metrics not appearing
Check:
1. Program is enabled in config
2. Metrics registry is set up
3. BPF maps are being populated
4. No errors in logs

### eBPF Compilation Errors
Ensure:
- Using `no_std` attribute
- All imports are from eBPF-compatible crates
- No std library usage in eBPF code
