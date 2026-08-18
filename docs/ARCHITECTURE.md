# BPF Agent Architecture

This document describes the architecture and design of the bpfagent application.

## Overview

The bpfagent is a generic eBPF program manager that loads, manages, and collects metrics from multiple eBPF programs. It exposes collected metrics via Prometheus HTTP endpoint and supports both daemon and interactive modes.

## Core Components

### 1. Program Registry (`programs/registry.rs`, `programs/traits.rs`)

The program registry implements a plugin architecture for managing eBPF programs:

#### Traits

- **`EbpfProgram`**: Core trait for all eBPF programs
  - `load()`: Load the compiled eBPF bytecode into the kernel
  - `start()`: Attach to kernel events (tracepoints, kprobes, etc.)
  - `bpf_program_name()`: Return the program name in the object file

- **`MetricsDisplay`**: Optional trait for programs that collect metrics
  - `set_metrics_registry()`: Register Prometheus metrics
  - `display_metrics()`: Read data from BPF maps and update metrics

- **`EbpfAccess`**: Provides access to underlying Aya Ebpf instance
  - `ebpf_mut()`: Get mutable reference to the loaded eBPF program

#### ProgramRegistry

The `ProgramRegistry` manages available programs:
```
┌─────────────────────────────────┐
│    ProgramRegistry              │
├─────────────────────────────────┤
│ factories: HashMap<name, Fn()>  │
├─────────────────────────────────┤
│ register()                      │
│ create_program()                │
│ available_programs()            │
└─────────────────────────────────┘
```

### 2. Configuration (`config/loader.rs`)

Configuration is loaded from TOML files with this structure:
```toml
pid_file = "/tmp/bpfagent.pid"
working_directory = "/"
log_file = "/tmp/bpfagent.log"

[[ebpf_programs]]
name = "kfree_skb"
enabled = true
```

**Search paths** (in order):
1. Specified via `-f/--config-file`
2. `/etc/bpfagent.conf`
3. `/etc/bpfagent/bpfagent.conf`
4. `/usr/local/etc/bpfagent.conf`
5. `/usr/local/etc/bpfagent/bpfagent.conf`
6. `~/.bpfagent.conf`
7. `~/.config/bpfagent/config.toml`
8. `./bpfagent.conf` (current directory)

**Other CLI flags**:
- `-d/--daemon`: Run in daemon mode (background, no stdout output); interactive mode is the default
- `-i/--metrics-ip`: Metrics server IP address (default `0.0.0.0`)
- `-p/--metrics-port`: Metrics server port (default `9101`)
- `-v/--verbose`: Enable verbose output (overrides daemon mode for interactive debugging)

### 3. Daemonization (`daemon.rs`)

The application supports daemon mode via `fork()` and proper file descriptor management:

```
┌──────────────────────────────────┐
│ init_logger_initial()            │ (before fork)
├──────────────────────────────────┤
│ daemonize()                      │
│ ├─ fork_and_detach()            │ (fork here)
│ ├─ redirect_stdio()             │ (dup2 to log file)
│ ├─ create_new_session()         │ (setsid)
│ └─ change_working_directory()   │
├──────────────────────────────────┤
│ init_logger_after_daemonize()    │ (after fork, redirect to log file)
└──────────────────────────────────┘
```

**Unsafe code documentation**:
- `fork()`: Safe to call before any threads are created
- `dup2()`: Safely redirects file descriptors in child process
- `setsid()`: Creates new session to detach from terminal
- All unsafe calls properly check return values and return errors

### 4. Program Lifecycle

Programs follow this lifecycle:

```
┌─────────┐
│ Created │
└────┬────┘
     │
     ▼
┌──────────┐   (load eBPF bytecode)
│  Loaded  │
└────┬─────┘
     │
     ▼
┌──────────────┐  (attach to kernel events)
│   Started    │
└────┬─────────┘
     │
     ├─── (if supports metrics)
     │    ├── set_metrics_registry()
     │    └── display_metrics() [periodic]
     │
     └─── (event loop running)
     
     ▼ (on signal)
┌──────────┐
│ Shutdown │
└──────────┘
```

### 5. Metrics Collection

Programs that support metrics implement `MetricsDisplay`:

```
┌──────────────────────────────────────┐
│ Prometheus Registry                  │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ MetricsDisplay::set_metrics_registry()│
│ - Create metric objects              │
│ - Register with Prometheus           │
└──────────────────────────────────────┘
       │
       │ (every 3 seconds)
       ▼
┌──────────────────────────────────────┐
│ MetricsDisplay::display_metrics()    │
│ - Read from BPF maps                 │
│ - Update counters/gauges             │
│ - Print to stdout (interactive mode) │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ HTTP Server (:9101/metrics)          │
│ - Renders Prometheus text format     │
└──────────────────────────────────────┘
```

### 6. HTTP Metrics Server (`metrics/server.rs`)

Runs in a separate thread and serves metrics in Prometheus format:

```
listen() on 0.0.0.0:9101 (default)
    │
    ├─ GET /metrics
    │   └─ gather() from registry
    │   └─ TextEncoder.encode()
    │   └─ HTTP 200 response
    │
    └─ GET * (other paths)
        └─ HTTP 404 response
```

Thread-safety: Uses `Arc<Registry>` to share metrics registry between threads.

### 7. Event Loop (`run_event_loop()`)

Main event loop handles:
- Signal handling (SIGINT, SIGTERM, CTRL-C)
- Periodic metrics display (every 3 seconds)
- Graceful shutdown

```
┌─────────────────────────────────────┐
│ Event Loop (tokio::select!)         │
├─────────────────────────────────────┤
│ - Listen for CTRL+C                 │
│ - Listen for SIGINT                 │
│ - Listen for SIGTERM                │
│ - Timer for metrics display (3s)    │
│   └─ call display_metrics() on each │
│      program that supports it       │
└─────────────────────────────────────┘
```

## Adding New Programs

To add a new eBPF program:

1. **Create a new module** (e.g., `my_program.rs`)

2. **Implement `EbpfProgram` trait**:
```rust
pub struct MyProgram {
    name: String,
    ebpf: Option<Ebpf>,
}

impl EbpfProgram for MyProgram {
    fn bpf_program_name(&self) -> &str {
        "my_program"
    }
    
    fn load(&mut self) -> Result<(), anyhow::Error> {
        // Load eBPF bytecode
        // Attach to kernel hooks
    }
    
    fn start(&mut self) -> anyhow::Result<()> {
        // Start collecting data
    }
    
    // ... other required methods
}
```

3. **Optionally implement `MetricsDisplay`** if program collects metrics:
```rust
impl MetricsDisplay for MyProgram {
    fn set_metrics_registry(&mut self, registry: Arc<Registry>) -> anyhow::Result<()> {
        // Create Prometheus metrics
    }
    
    fn display_metrics(&mut self) -> anyhow::Result<()> {
        // Read from BPF maps and update metrics
    }
}
```

4. **Add initialization function**:
```rust
pub fn init(registry: &mut ProgramRegistry) {
    registry.register("my_program", || Box::new(MyProgram::new()));
}
```

5. **Register in `bpfagent/src/app.rs`**:
```rust
fn register_programs() -> ProgramRegistry {
    let mut registry = ProgramRegistry::new();
    crate::programs::kfree_skb::init(&mut registry);
    crate::programs::sca::init(&mut registry);
    crate::programs::my_program::init(&mut registry);  // Add this
    registry
}
```

6. **Add module declaration in `bpfagent/src/programs/mod.rs`**:
```rust
pub mod my_program;
```

7. **Enable in config file**:
```toml
[[ebpf_programs]]
name = "my_program"
enabled = true
```

## Error Handling

- All fallible operations use `Result<T, anyhow::Error>`
- Context added using `anyhow::Context` trait
- No `.expect()` calls in production code
- Unsafe code wrapped in safe abstractions with error checking

Example:
```rust
// Good
std::fs::read_to_string(path).context("failed to read config")?

// Avoid
std::fs::read_to_string(path).expect("failed to read config")
```

## Thread Safety

- `Arc<Registry>` shared between main thread and metrics server thread
- `CancellationToken` used for graceful shutdown
- All program access through mutable references (single-threaded per program)
- Tokio async runtime for managing concurrent tasks

## Logging

- `env_logger` for logging
- Configurable via `RUST_LOG` environment variable
- Log level defaults to `info` in interactive (foreground) mode and `debug` in daemon mode
- Logs directed to:
  - Stdout/stderr in interactive mode
  - Log file in daemon mode (configured in config file)

## Performance Considerations

1. **eBPF Maps**: Plain shared `aya_ebpf::maps::HashMap`s (no per-CPU maps)
2. **Metrics Display**: Periodic polling (3 seconds) balances responsiveness and overhead
3. **HTTP Server**: Blocking, synchronous `TcpListener` I/O on a dedicated `std::thread`; only shutdown waits on an async `CancellationToken`
4. **Memory**: BPF map sizes configured at compile time in eBPF programs

## Security

- Requires root privileges to run (eBPF program loading)
- File access restricted to uid/gid of root
- Input validation on config file parsing
- Safe handling of process file descriptors
