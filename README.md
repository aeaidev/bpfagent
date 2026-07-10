# BPF Agent

A generic eBPF agent application that manages multiple eBPF programs and exposes Prometheus metrics. Currently includes the `kfree_skb` program that traces kernel packet drops.

## Overview

This tool monitors the Linux kernel's `kfree_skb` tracepoint to collect statistics on why network packets are being dropped. It provides real-time visibility into network stack issues by tracking drop reasons defined in the kernel's `enum skb_drop_reason`.

## Features

- **Modular architecture** - easy to add new eBPF programs via separate modules
- **kfree_skb program** - traces packet drops at the kernel's `kfree_skb` tracepoint
- Counts drops by reason (e.g., `TCP_CSUM`, `NO_SOCKET`, `QDISC_DROP`, etc.)
- Displays drop statistics every 3 seconds
- Uses BPF CO-RE compatible types via Aya framework
- **Prometheus metrics exporter** - exposes metrics via HTTP endpoint for monitoring
- **Configurable metrics server** - customize IP address and port via command-line options
- **Clean code organization** - separates concerns into modules (common, kfree_skb, metrics)

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
   - Tracepoint support for `skb:kfree_skb`
   - BTF debug info (CONFIG_DEBUG_INFO_BTF=y) - for best compatibility

## Build & Run

### Standard build (x86_64 Linux)

```bash
# Build in release mode
cargo build --release

# Run with sudo (required for eBPF)
sudo cargo run --release
```

### Command-line Options

The application supports command-line arguments for customizing the metrics server IP address and port:

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--metrics-ip` | `-i` | `0.0.0.0` | Metrics server IP address |
| `--metrics-port` | `-p` | `9190` | Metrics server port |

**Examples:**

```bash
# Use default address (0.0.0.0:9190)
sudo cargo run --release

# Listen on localhost only
sudo cargo run --release -- --metrics-ip 127.0.0.1

# Use a custom port
sudo cargo run --release -- --metrics-port 8080

# Use custom IP and port (short forms)
sudo cargo run --release -- -i 0.0.0.0 -p 9999
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

The application exposes a Prometheus metrics endpoint (default: **0.0.0.0:9190**) at the `/metrics` path. This allows you to monitor packet drops using Prometheus and visualize them with Grafana.

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

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kfree_skb_total_drops` | Counter | `reason` | Total number of SKB drops |
| `kfree_skb_drops_by_reason` | Counter | `reason_code`, `reason_name` | Number of drops by reason |

### Metrics Output Example

```
# HELP kfree_skb_total_drops Total number of SKB drops
# TYPE kfree_skb_total_drops counter
kfree_skb_total_drops{reason="all"} 1234
# HELP kfree_skb_drops_by_reason Number of drops by reason
# TYPE kfree_skb_drops_by_reason counter
kfree_skb_drops_by_reason{reason_code="10",reason_name="TCP_CSUM"} 456
kfree_skb_drops_by_reason{reason_code="64",reason_name="QDISC_DROP"} 321
kfree_skb_drops_by_reason{reason_code="3",reason_name="NO_SOCKET"} 234
```

## Output Example

```
Drop counts (total: 1234):
  10 (TCP_CSUM               ): 456
  64 (QDISC_DROP             ): 321
   3 (NO_SOCKET              ): 234
  55 (BPF_CGROUP_EGRESS      ): 123
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
│   └── src/
│       ├── main.rs     # Application entry point with argument parsing
│       ├── common.rs   # Shared CLI arguments for bpfagent
│       ├── kfree_skb.rs# kfree_skb-specific logic (metrics, display)
│       └── metrics.rs  # Prometheus metrics HTTP server
├── common/
│   └── kfree_skb/      # Shared types between user and eBPF code
└── ebpf/
    └── kfree_skb/      # Kernel-space eBPF program source
```

### Key Files

- `bpfagent/src/main.rs` - Main application entry point with argument parsing
- `bpfagent/src/common.rs` - Shared CLI arguments (metrics IP/port)
- `bpfagent/src/kfree_skb.rs` - kfree_skb-specific logic (metrics, display functions)
- `bpfagent/src/metrics.rs` - Prometheus metrics HTTP server
- `ebpf/kfree_skb/src/main.rs` - eBPF program attached to `kfree_skb` tracepoint
- `common/kfree_skb/src/lib.rs` - Common types (`SkbDropReason`, `reason_name`)
