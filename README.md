# BPF Agent

A generic eBPF agent application that manages multiple eBPF programs and exposes Prometheus metrics. It includes:

- **kfree_skb** - traces kernel packet drops
- **SCA** - traces socket communication latency per process

## Quick Links

- 📖 **[Architecture Guide](docs/ARCHITECTURE.md)** - System design and components
- 🔧 **[Development Guide](docs/DEVELOPMENT.md)** - Build, test, and debug
- 🛠️ **[Plugin Development](docs/PLUGINS.md)** - Create new eBPF programs
- 📝 **[Contributing](docs/CONTRIBUTING.md)** - How to contribute
- ⚙️ **[Configuration](config/bpfagent.conf.full)** - Full config options
- 🐳 **[Examples](examples/)** - Deployment examples (Docker; systemd unit in [config/systemd/](config/systemd/))
- 📋 **[Changelog](CHANGELOG.md)** - Version history

## Overview

### kfree_skb Program

This tool monitors the Linux kernel's `kfree_skb` tracepoint to collect statistics on why network packets are being dropped. It provides real-time visibility into network stack issues by tracking drop reasons defined in the kernel's `enum skb_drop_reason`.

### SCA Program

The SCA program traces socket communication latency by measuring the timestamp difference between sends to and from Unix domain sockets. It tracks each hop in the data flow chain:

- **DATA_SOURCE → INTERNAL_ROUTER**: Measures latency for `/tmp/DATA_L3_TO_INTERNAL_ROUTER`
- **INTERNAL_ROUTER → RED_WF_COMM_L**: Measures latency for `/tmp/DATA_L3_TO_WF_L`
- **RED_WF_COMM_L → FRAGMENTER**: Measures latency for `/tmp/WF_L_TO_FRAG`
- **FRAGMENTER → RED_IRSS_COMM_L**: Measures latency for `/tmp/FRAG_TO_IRSS_L`
- **RED_IRSS_COMM_L → FRAGMENTER**: Measures latency for `/tmp/IRSS_L_TO_FRAG`
- **FRAGMENTER → RED_WF_COMM_L**: Measures latency for `/tmp/FRAG_TO_COMM_WF_L`
- **RED_WF_COMM_L → DATA_SINK**: Measures latency for `/tmp/DATA_L_TO_SINK`

For each hop, it:
1. Stores timestamp when the sending process sends TO the listening socket
2. Looks up timestamp when the receiving process sends FROM that socket
3. Calculates latency as the timestamp difference

Latencies are tracked using a sliding window moving average (2-second window) and exported via Prometheus.

## Quick Start

### Prerequisites

- Linux kernel 5.8+ with BPF support
- Rust and Cargo
- Development tools (see `./scripts/setup.sh`)

### Build and Run

```bash
# Setup development environment
./scripts/setup.sh

# Build
./scripts/build.sh release

# Run in interactive mode (default)
sudo ./target/x86_64-unknown-linux-gnu/release/bpfagent

# Run as daemon
sudo ./target/x86_64-unknown-linux-gnu/release/bpfagent -d -f config/bpfagent.conf.example
```

### Access Metrics

```bash
# View metrics (while running)
curl http://localhost:9101/metrics
```

## Configuration

The application uses a TOML configuration file to control daemon settings and which eBPF programs to load.

### Config File Format

```toml
# Daemon settings
pid_file = "/tmp/bpfagent.pid"
working_directory = "/"
log_file = "/tmp/bpfagent.log"

# EBPF programs to load and run
[[ebpf_programs]]
name = "kfree_skb"
enabled = true

[[ebpf_programs]]
name = "sca"
enabled = true
```

### Config File Locations

By default, the application searches for the config file in these locations:
- `/etc/bpfagent.conf`
- `/etc/bpfagent/bpfagent.conf`
- `/usr/local/etc/bpfagent.conf`
- `/usr/local/etc/bpfagent/bpfagent.conf`
- `~/.bpfagent.conf` (if HOME is set)
- `~/.config/bpfagent/config.toml` (if HOME is set)
- `./bpfagent.conf` (current directory for development)

Use the `-f/--config-file` option to specify a custom config file path.

## Features

- **Modular architecture** - easy to add new eBPF programs via separate modules
- **Configurable program loading** - load specific programs from config file
- **kfree_skb program** - traces packet drops at the kernel's `kfree_skb` tracepoint
  - Counts drops by reason (e.g., `TCP_CSUM`, `NO_SOCKET`, `QDISC_DROP`, etc.)
  - Displays drop statistics every 3 seconds
  - Uses BPF CO-RE compatible types via Aya framework
- **SCA program** - traces socket communication latency per process
  - Measures latency based on socket path + direction (TO/FROM) matching
  - On send TO listening socket: stores timestamp with key = (hop_index << 32) | Protocol
  - On send FROM listening socket: looks up timestamp with the same key
  - Raw latency is the timestamp difference on match; the downstream hop's
    latency for the same message is then subtracted, so the reported value is
    each hop's individual contribution rather than the accumulated chain
  - Tracks moving average latency per process name (2-second sliding window)
  - Exports metrics via Prometheus with process name labels
- **Prometheus metrics exporter** - exposes metrics via HTTP endpoint for monitoring
- **Configurable metrics server** - customize IP address and port via command-line options
- **Clean code organization** - separates concerns into modules (common, config, programs, metrics)

## Prerequisites

1. **Rust toolchains**:
   ```bash
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```

2. **bpf-linker** (required for building eBPF programs):
   ```bash
   cargo install bpf-linker
   ```

3. **Linux kernel** with:
   - BPF support (CONFIG_BPF=y)
   - Tracepoint support for `skb:kfree_skb` (for kfree_skb program)
   - Tracepoint support for `syscalls:sys_enter_sendmsg` (for SCA program)
   - BTF debug info (CONFIG_DEBUG_INFO_BTF=y) - for best compatibility

## Build & Run

### Standard build (x86_64 Linux)

### Running Modes

The application supports two running modes:

**Interactive Mode (default)**
- Displays statistics to stdout every 3 seconds
  - For kfree_skb: drop counts by reason
  - For SCA: moving average latency per process name

**Daemon Mode**
- Runs in the background without stdout output
- Only Prometheus metrics endpoint provides feedback
- Use `-d` to enable daemon mode
- Use `--verbose` to enable verbose logging (overrides daemon mode for interactive debugging)

The metrics server listens on port **9101** by default (changeable with `-p`).

```bash
# Build in release mode
cargo build --release

# Run with sudo (required for eBPF)
sudo cargo run --release -- -f /etc/bpfagent.conf
```

### Command-line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `-d, --daemon` | | `false` | Run in daemon mode (no stdout output) |
| `-i, --metrics-ip` | | `0.0.0.0` | Metrics server IP address |
| `-p, --metrics-port` | | `9101` | Metrics server port |
| `-v, --verbose` | | | Enable verbose output (overrides daemon mode for interactive debugging) |
| `-f, --config-file` | | | Path to config file (overrides default config file paths) |

**Examples:**

```bash
# Default: run in interactive mode with default config paths
sudo cargo run --release

# Run with custom config file
sudo cargo run --release -- -f /path/to/bpfagent.conf

# Run in daemon mode
sudo cargo run --release -- -d

# Run interactively with verbose logging (verbose overrides daemon mode)
sudo cargo run --release -- --verbose

# Listen on localhost only
sudo cargo run --release -- --metrics-ip 127.0.0.1

# Use a custom port
sudo cargo run --release -- --metrics-port 8080

# Use custom IP and port (short forms)
sudo cargo run --release -- -i 127.0.0.1 -p 9999
```

### Check for errors without running

```bash
cargo check --all
```

### Cross-compiling for Petalinux 2024.2

To build for ARM64 Linux targets (aarch64-unknown-linux-musl):

```bash
# Install the target
rustup target add aarch64-unknown-linux-musl

# Install musl cross-compiler (Ubuntu/Debian)
sudo apt-get install musl-tools

# Build for aarch64
CC=aarch64-linux-musl-gcc cargo build --package bpfagent --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker="aarch64-linux-musl-gcc"

# The binary will be at:
# target/aarch64-unknown-linux-musl/release/bpfagent
```

## How It Works

1. The eBPF program (e.g., `kfree_skb`) attaches to a kernel tracepoint
2. When an event occurs, the program reads context and increments counters in a hash map
3. The user-space program periodically reads and displays the counters
4. Prometheus metrics are updated with the collected data

## Prometheus Metrics Exporter

The application exposes a Prometheus metrics endpoint (default: **0.0.0.0:9101**) at the `/metrics` path. This allows you to monitor packet drops using Prometheus and visualize them with Grafana.

You can customize the metrics server IP address and port using the `--metrics-ip` (`-i`) and `--metrics-port` (`-p`) command-line options.

### Running the application

```bash
sudo cargo run --release
```

### Accessing metrics

Once the application is running, you can retrieve metrics in Prometheus format (adjust port if using a custom address):

```bash
curl http://localhost:9101/metrics
```

Or configure Prometheus to scrape the endpoint (adjust address if using a custom metrics server IP/port):

```yaml
scrape_configs:
  - job_name: 'bpfagent'
    static_configs:
      - targets: ['localhost:9101']
```

### Available Metrics

#### kfree_skb Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kfree_skb_total_drops` | Counter | `reason` | Total number of SKB drops |
| `kfree_skb_drops_by_reason` | Counter | `reason_code`, `reason_name` | Number of drops by reason |

#### SCA Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sca_avg_latency_per_pname` | Gauge | `pname` | Moving average of the individual hop latency in microseconds per process name (raw REQ/REP timestamp difference minus the downstream hop's latency) |

### Metrics Output Example

#### kfree_skb

```
# HELP kfree_skb_total_drops Total number of dropped packets
# TYPE kfree_skb_total_drops counter
 kfree_skb_total_drops{reason="all"} 1234
# HELP kfree_skb_drops_by_reason Number of dropped packets by reason
# TYPE kfree_skb_drops_by_reason counter
 kfree_skb_drops_by_reason{reason_code="10",reason_name="TCP_CSUM"} 456
 kfree_skb_drops_by_reason{reason_code="64",reason_name="QDISC_DROP"} 321
 kfree_skb_drops_by_reason{reason_code="3",reason_name="NO_SOCKET"} 234
```

#### SCA

The SCA program calculates latency per hop; see [SCA Data Flow](docs/SCA_DATA_FLOW.md#latency-measurement-approach) for the endpoint tracking and timestamp keying details.

```
# HELP sca_avg_latency_per_pname Average individual hop latency in microseconds per process name
# TYPE sca_avg_latency_per_pname gauge
 sca_avg_latency_per_pname{pname="INTERNAL_ROUTER (PID 1234)"} 60769
 sca_avg_latency_per_pname{pname="FRAGMENTER (PID 1237)"} 34985
```

## Output Example

### kfree_skb Output

```
Drop counts (total: 1234):
  10 (TCP_CSUM               ): 456
  64 (QDISC_DROP             ): 321
   3 (NO_SOCKET              ): 234
  55 (BPF_CGROUP_EGRESS      ): 123
```

### SCA Output

The SCA program tracks latency per receiving process for each hop (keying details in [SCA Data Flow](docs/SCA_DATA_FLOW.md#latency-measurement-approach)):

```
--- Moving Average Latency per PID ---
  INTERNAL_ROUTER (PID 1234): 60769 us (count: 2) path=/tmp/DATA_L3_TO_INTERNAL_ROUTER
  FRAGMENTER (PID 1237): 34985 us (count: 4) path=/tmp/WF_L_TO_FRAG, /tmp/IRSS_L_TO_FRAG
```

## Mapping Drop Reasons

The drop reasons correspond to the kernel's `enum skb_drop_reason` (see `include/linux/skbuff.h`):

| Reason | Description |
|--------|-------------|
| 0-1 | Not dropped / Consumed |
| 2-67 | Core network stack (TCP, UDP, IP, routing, etc.) |
| 68-69 | MACVLAN/IPvlan backlog |
| 70-83 | Device/queue issues (XDP, TC, rings, memory) |
| 84-103 | Protocol-specific (ICMP, IP, IPv6) |
| 104-126 | Qdisc, TC, VXLAN, CAN, PSP, etc. |

## Project Structure

```
bpfagent/
├── bpfagent/           # User-space Rust application
│   ├── src/
│   │   ├── main.rs     # Thin binary entry point
│   │   ├── lib.rs      # Library root (all modules live here)
│   │   ├── app.rs      # Program wiring and main event loop
│   │   ├── daemon.rs   # Daemonization (fork, stdio redirect, setsid)
│   │   ├── cli/        # Command-line argument definitions
│   │   ├── config/     # Config file parsing and daemon settings
│   │   ├── metrics/    # Prometheus metrics HTTP server
│   │   └── programs/   # Program registry, traits, and eBPF program modules
│   │       ├── kfree_skb/  # kfree_skb-specific logic (metrics, display)
│   │       └── sca/        # SCA-specific logic (metrics, display, hop discovery)
│   └── examples/
│       └── sca_sim.rs  # SCA pipeline simulator for end-to-end testing
├── common/
│   ├── kfree_skb/      # Shared types between user and eBPF code
│   └── sca/            # Shared types between user and eBPF code
└── ebpf/
    ├── kfree_skb/      # Kernel-space eBPF program source
    └── sca/            # Kernel-space eBPF program source
```

### Key Files

#### kfree_skb

- `bpfagent/src/programs/kfree_skb/mod.rs` - kfree_skb-specific logic (metrics, display functions)
- `ebpf/kfree_skb/src/main.rs` - eBPF program attached to `kfree_skb` tracepoint
- `common/kfree_skb/src/lib.rs` - Common types (`SkbDropReason`, `reason_name`)

#### SCA

- `bpfagent/src/programs/sca/mod.rs` - SCA-specific logic (metrics, display, hop discovery via `ss -xpH`)
- `ebpf/sca/src/main.rs` - eBPF program that matches NNG Protocol timestamps per hop for latency calculation
- `common/sca/src/lib.rs` - Common types (hop endpoints, data flow, tracepoints)
- `bpfagent/examples/sca_sim.rs` - SCA pipeline simulator for end-to-end testing

**SCA Latency Calculation:**
- Uses a combined key of hop index (4B) + Protocol (4B) to match REQ/REP message pairs
- On send TO the listening socket (sender endpoint): stores timestamp with key = (hop_index << 32) | Protocol
- On send FROM the listening socket (receiver endpoint): looks up timestamp with the same key
- Raw latency = current_timestamp - stored_timestamp on match; the downstream
  hop's latency for the same message is then subtracted (LATENCY_HOP_MAP), so
  the reported value is each hop's individual contribution
