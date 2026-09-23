# Plugin Development Guide

Learn how to create new eBPF programs (plugins) for BPF Agent.

## Overview

A plugin consists of three parts:
1. **eBPF kernel program** (`ebpf/<name>/`) — collects data from the kernel
2. **Shared types** (`common/<name>/`) — structures used by both sides
3. **Userspace handler** (`bpfagent/src/programs/<name>/mod.rs`) — loads the
   program, reads its maps, exports Prometheus metrics

> Writing the kernel program in C instead of Rust? See
> [PLUGINS_C.md](PLUGINS_C.md).

## Quick Start

The steps below create a complete, working plugin called `my_program` that
attaches to the `syscalls/sys_enter_openat` tracepoint, counts calls per PID
in a BPF hash map, and exports the counts as a Prometheus gauge. Every
snippet was verified by actually building and running the plugin against
this repository.

Copy-ready templates matching these steps:

- eBPF kernel program: [`docs/templates/custom_program_ebpf.rs`](templates/custom_program_ebpf.rs)
- userspace handler: [`docs/templates/custom.rs`](templates/custom.rs)
- (C kernel alternative: [`docs/templates/custom_program.c`](templates/custom_program.c);
  minimal userspace skeleton: [`docs/templates/custom_program.rs`](templates/custom_program.rs))

### 1. Create the eBPF Crate

```bash
mkdir -p ebpf/my_program/src
```

Create `ebpf/my_program/Cargo.toml`:
```toml
[package]
name = "my_program-ebpf"
version = "0.1.0"
edition.workspace = true

[dependencies]
my_program-common = { path = "../../common/my_program" }

aya-ebpf = { workspace = true }
aya-log-ebpf = { workspace = true }

[[bin]]
name = "my_program"
path = "src/main.rs"
```

The `[[bin]]` name determines the object file name under `OUT_DIR`, which is
what `include_bytes_aligned!` loads in the userspace handler below.

Create `ebpf/my_program/src/main.rs`:
```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use my_program_common::{EventCount, Pid};

// Counts sys_enter_openat calls per process ID. The userspace handler reads
// this map on every stats tick and exports the values as Prometheus gauges.
#[map]
pub static COUNTERS: HashMap<Pid, EventCount> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn my_handler(ctx: TracePointContext) -> u32 {
    match try_my_handler(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_my_handler(ctx: &TracePointContext) -> Result<u32, u32> {
    // Upper 32 bits of bpf_get_current_pid_tgid() are the thread-group ID,
    // i.e. the PID as userspace knows it.
    let pid = (bpf_get_current_pid_tgid() >> 32) as Pid;

    debug!(ctx, "my_handler: openat by pid {}", pid);

    // The HashMap uses interior mutability, so no mutable reference is needed.
    match unsafe { COUNTERS.get(&pid) } {
        Some(count) => {
            COUNTERS
                .insert(&pid, &count.wrapping_add(1), 0)
                .map_err(|e| e as u32)?;
        }
        None => {
            COUNTERS.insert(&pid, &1, 0).map_err(|e| e as u32)?;
        }
    }

    Ok(0)
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

Conventions that matter:

- The **function name** (`my_handler`) becomes the aya program name;
  `bpf_program_name()` and `ebpf.program_mut()` in the handler must match it.
- The **static variable name** (`COUNTERS`) becomes the map name;
  `ebpf.map("COUNTERS")` in the handler must match it.
- The `#[panic_handler]` (gated on `target_arch = "bpf"` so host-side
  `cargo check` still works) is required — without it the crate does not
  compile. The `license` section is required by the kernel for GPL-only
  helpers and is part of every eBPF crate in this repository.
- To read tracepoint fields, read from `ctx.as_ptr()` at the offsets from
  `/sys/kernel/tracing/events/<category>/<event>/format` with
  `aya_ebpf::helpers::bpf_probe_read_kernel` (see `ebpf/kfree_skb/src/main.rs`).
  Prefer helpers like `bpf_get_current_pid_tgid()` when they give you what you
  need — raw offsets are fragile.

### 2. Create the Shared-Types Crate

```bash
mkdir -p common/my_program/src
```

Create `common/my_program/Cargo.toml`:
```toml
[package]
name = "my_program-common"
version = "0.1.0"
edition.workspace = true

license.workspace = true

[lib]
path = "src/lib.rs"
```

Create `common/my_program/src/lib.rs`:
```rust
#![no_std]

//! Shared types between the `my_program` eBPF program and its userspace
//! handler. Keep this crate `no_std`-compatible so both sides can use it.

/// Key of the `COUNTERS` map: the process ID (thread-group ID).
pub type Pid = u32;

/// Value of the `COUNTERS` map: number of `sys_enter_openat` events observed
/// for the process since program load.
pub type EventCount = u64;
```

The counter needs only scalar map keys/values, so type aliases suffice. When
you share richer payloads, define `#[repr(C)]` structs here instead (see
`common/kfree_skb`). Add a `user` feature with an optional `aya` dependency
when userspace needs `aya::Pod` implementations (see `common/sca`).

### 3. Create the Userspace Handler

```bash
mkdir -p bpfagent/src/programs/my_program
```

Create `bpfagent/src/programs/my_program/mod.rs` (also available as
[`docs/templates/custom.rs`](templates/custom.rs)):
```rust
//! my_program eBPF Program - Per-PID openat() Counter (Plugin Template)
//!
//! The eBPF program attaches to the `syscalls/sys_enter_openat` tracepoint
//! and counts calls per PID in the `COUNTERS` BPF hash map.
//!
//! # Prometheus Metrics
//!
//! - `my_program_events_per_pid`: openat() calls per PID since program load

use std::{any::Any, sync::Arc};

use aya::{maps::HashMap, programs::TracePoint, Ebpf};
use log::info;
use my_program_common::{EventCount, Pid};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::programs::{EbpfAccess, EbpfProgram, MetricsDisplay, ProgramRegistry};

/// Object file name in OUT_DIR (the eBPF crate's [[bin]] name).
const OBJECT_NAME: &str = "my_program";
/// aya program name == the eBPF function name.
const PROGRAM_NAME: &str = "my_handler";
/// Tracepoint the program hooks.
const TP_CATEGORY: &str = "syscalls";
const TP_EVENT: &str = "sys_enter_openat";
/// Event-count map in the eBPF object.
const MAP_NAME: &str = "COUNTERS";

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
    /// Create a new instance of the program
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

    fn as_any_mut(&mut self) -> &mut dyn Any {
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
                "openat() calls counted by my_handler per PID",
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

        let counts: HashMap<_, Pid, EventCount> = ebpf
            .map(MAP_NAME)
            .ok_or_else(|| anyhow::anyhow!("{} map not found", MAP_NAME))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to open {} map: {}", MAP_NAME, e))?;

        info!("my_program events (openat calls per PID):");
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
        assert_eq!(program.name(), "my_program");
        assert_eq!(program.bpf_program_name(), "my_handler");
        assert!(program.supports_metrics());
    }
}
```

Note the pieces that are easy to miss:

- `EbpfAccess` is a **mandatory supertrait** of `EbpfProgram` — implement both.
- The `init()` function is what step 4 calls from `register_programs()`;
  the name passed to `registry.register()` is what the config file uses in
  `[[ebpf_programs]] name = ...`.
- `display_metrics()` runs on every stats tick (`stats_interval_ms`, default
  3000 ms); its `info!` output is also what you see on the console in
  interactive (non-daemon) mode.
- If your program has no metrics, skip `MetricsDisplay`,
  `supports_metrics()`, and `as_metrics_mut()` — see
  [Enabling Metrics](#enabling-metrics-supports_metrics-and-as_metrics_mut).

### 4. Register the Program

Add the module in `bpfagent/src/programs/mod.rs` (keep the list sorted):
```rust
pub mod iflat;
pub mod irss;
pub mod kfree_skb;
pub mod my_program;  // Add this
pub mod registry;
pub mod sca;
pub mod traits;
pub mod uprobe;
```

Then register it in `register_programs()` in `bpfagent/src/app.rs`:
```rust
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();

    // Initialize all program modules - each module registers itself
    // To add a new program, add its module and call its init function here
    crate::programs::iflat::init(&mut registry);
    crate::programs::irss::init(&mut registry);
    crate::programs::kfree_skb::init(&mut registry);
    crate::programs::my_program::init(&mut registry);  // Add this
    crate::programs::sca::init(&mut registry);
    crate::programs::uprobe::init(&mut registry);

    registry
}
```

### 5. Wire Up the Build

Four edits are required so both crates compile and the eBPF object gets
embedded into the agent binary:

1. Add **both** crates to workspace `members` in the root `Cargo.toml`, and
   the common crate to `default-members`:
   ```toml
   members = [
       # ...
       "common/my_program",
       "ebpf/my_program",
   ]
   # default-members: add "common/my_program" to the existing list, e.g.
   # default-members = ["bpfagent", "common/iflat", ..., "common/my_program"]
   ```
   Only the common crate goes into `default-members`: the eBPF crate is
   compiled for `bpfel-unknown-none` by `bpfagent/build.rs`, and building it
   for the host target would fail (`no_std` binary without a host panic
   handler).

2. Add the common crate as a dependency of the agent in
   `bpfagent/Cargo.toml`:
   ```toml
   [dependencies]
   my_program-common = { path = "../common/my_program" }
   ```

3. Add the eBPF package name to the match in `bpfagent/build.rs`, which
   discovers eBPF packages from workspace metadata and builds them with
   aya-build:
   ```rust
   "iflat-ebpf" | "irss-ebpf" | "kfree_skb-ebpf" | "my_program-ebpf" | "sca-ebpf"
   | "uprobe-ebpf" => {
   ```

The compiled object lands in `OUT_DIR` under its `[[bin]]` name
(`my_program`), which is what the userspace handler loads via
`include_bytes_aligned!(concat!(env!("OUT_DIR"), "/my_program"))`.

### 6. Add to the Example Configuration

Edit `config/bpfagent.conf.example` (see `config/bpfagent.conf.full` for the
full reference):
```toml
[[ebpf_programs]]
name = "my_program"
enabled = false  # Disabled by default if optional
```

Note: if a config file has **no** `[[ebpf_programs]]` entries at all, the
agent enables *all* registered programs — your new plugin included.

### 7. Build and Run

```bash
cargo build --package bpfagent   # build.rs compiles the eBPF crate with
                                 # nightly + bpf-linker into OUT_DIR
```

Create a minimal config that enables only the new plugin:
```toml
# target/tmp/my_program.conf
pid_file = "/tmp/bpfagent_my_program.pid"
working_directory = "/"
log_file = "/tmp/bpfagent_my_program.log"
stats_interval_ms = 1000

[[ebpf_programs]]
name = "my_program"
enabled = true
```

Running requires root (eBPF loading):
```bash
sudo ./target/debug/bpfagent -f target/tmp/my_program.conf -p 19101
```

Expected log output:
```text
[INFO  bpfagent::app] Available programs: ["irss", "iflat", "my_program", "kfree_skb", "uprobe", "sca"]
[INFO  bpfagent::app] Enabled programs: ["my_program"]
[INFO  bpfagent::programs::my_program] MyProgram started
[INFO  bpfagent::programs::my_program] my_program events (openat calls per PID):
[INFO  bpfagent::programs::my_program]   PID 918: 1 events
```

And the Prometheus endpoint:
```bash
$ curl -s http://localhost:19101/metrics | grep my_program
my_program_events_per_pid{pid="918"} 596
my_program_events_per_pid{pid="2112"} 1694
...
```

## Enabling Metrics: `supports_metrics()` and `as_metrics_mut()`

Implementing `MetricsDisplay` alone is not enough for metrics to appear.
The agent gates all metrics wiring on two `EbpfProgram` methods
(`bpfagent/src/app.rs` calls them in `setup_prometheus_metrics` and in the
event loop), and their default implementations — `false` and `None` —
disable metrics entirely. Programs that export metrics must override both
(as the handler in step 3 does; see `bpfagent/src/programs/sca/mod.rs` for a
real example):

```rust
impl EbpfProgram for MyProgram {
    // ... bpf_program_name, load, start, as_any_mut ...

    fn supports_metrics(&self) -> bool {
        true
    }

    fn as_metrics_mut(&mut self) -> Option<&mut dyn MetricsDisplay> {
        Some(self)
    }
}
```

Without these overrides the program loads and runs, but its metrics are
never registered or displayed. See [Metrics not
appearing](#metrics-not-appearing) if your metrics are missing.

## Program Settings: `configure()`

A program can accept its own free-form settings table from the config file
by overriding the optional `EbpfProgram::configure` hook. It is called once
after creation, before `load()`, with the program's `[[ebpf_programs]]`
entry; the default implementation ignores all settings:

```toml
[[ebpf_programs]]
name = "my_program"
enabled = true

[ebpf_programs.settings]
threshold = "100"
```

```rust
fn configure(&mut self, config: &EbpfProgramConfig) -> anyhow::Result<()> {
    // read config.settings (Option<toml::Table>), keep defaults for
    // missing/invalid values
    Ok(())
}
```

Runtime values reach the eBPF program through a small config map written in
`load()` before attaching; the eBPF side should fall back to a compiled-in
default when the map entry is absent. See `bpfagent/src/programs/irss/mod.rs`
(`raw_dest` -> `RAW_DEST_MAP`) for a real example.

## Testing Your Plugin

### Unit Tests

Unit tests live inline in the source file, in a `#[cfg(test)] mod tests`
block (see step 3 for an example). They run without root because they never
load eBPF:

```bash
cargo test --lib -p bpfagent my_program
```

### Integration Tests

Integration tests live in `bpfagent/tests/`. They test config parsing, the
metrics HTTP handler, and program logic over plain data structures — they do
**not** load eBPF programs and do not need root, so they can run in CI.
Create `bpfagent/tests/my_program_test.rs` for yours.

### Checks Before Submitting

```bash
cargo build --package bpfagent   # compiles the eBPF crate via build.rs
cargo clippy -- -D warnings      # lints default members (agent + common crates)
cargo fmt --all -- --check
cargo test --all --lib           # unit tests
cargo test --test '*'            # integration tests
```

Note: `cargo clippy --all` / `cargo clippy --workspace` additionally tries to
compile the eBPF crates for the **host** target, which fails on current
toolchains (`#[panic_handler] function required` — the eBPF panic handler is
gated on `target_arch = "bpf"`). This is expected and not caused by your
plugin; lint the default members as above.

## Best Practices

1. **Keep eBPF Programs Small** - Less complex code = fewer bugs
2. **Use Meaningful Names** - Map names match eBPF source; the aya program
   name is the eBPF function name
3. **Document Everything** - Module doc comment: what is measured, map
   keying, configuration, Prometheus metrics
4. **Add Error Handling** - `anyhow::Result` with `.context(...)`; no
   `.expect()` in production code
5. **Test Thoroughly** - Unit and integration tests
6. **Follow Conventions** - Match existing program style (see
   `bpfagent/src/programs/kfree_skb/mod.rs`)
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
RUST_LOG=debug cargo run --release -- --verbose
```

### "program not found" at load
The name passed to `ebpf.program_mut(...)` does not match any function in the
eBPF object. aya names programs after the eBPF **function name** — check
`bpf_program_name()` and the function name in `ebpf/<name>/src/main.rs` agree.

### "map not found" at runtime
The name passed to `ebpf.map(...)` does not match the `pub static` name in
the eBPF source (`COUNTERS` in the example above).

### Metrics not appearing
Check:
1. Program is enabled in config
2. Program overrides `supports_metrics()` (returns `true`) and
   `as_metrics_mut()` (returns `Some(self)`) — see
   [Enabling Metrics](#enabling-metrics-supports_metrics-and-as_metrics_mut);
   the defaults (`false`/`None`) silently disable all metrics wiring
3. Metrics registry is set up
4. BPF maps are being populated
5. No errors in logs

### eBPF Compilation Errors
Ensure:
- `#![no_std]` and `#![no_main]` attributes are present
- A `#[panic_handler]` gated on `target_arch = "bpf"` exists
- A `license` section exists (`Dual MIT/GPL`) — required for GPL-only helpers
- All imports are from eBPF-compatible crates (`aya-ebpf`, `aya-log-ebpf`,
  your `no_std` common crate)
- No std library usage in eBPF code
