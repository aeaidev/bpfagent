# EBPF

An eBPF application that traces kernel packet drops via the `kfree_skb` tracepoint and reports drop counts by reason.

## Overview

This tool monitors the Linux kernel's `kfree_skb` tracepoint to collect statistics on why network packets are being dropped. It provides real-time visibility into network stack issues by tracking drop reasons defined in the kernel's `enum skb_drop_reason`.

## Features

- Traces packet drops at the `kfree_skb` kernel tracepoint
- Counts drops by reason (e.g., `TCP_CSUM`, `NO_SOCKET`, `QDISC_DROP`, etc.)
- Displays drop statistics every 3 seconds
- Uses BPF CO-RE compatible types via Aya framework
- **Prometheus metrics exporter** - exposes metrics via HTTP endpoint for monitoring
- **Code quality improvements** - refactored HTTP response handlers, removed unused code

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
CC=aarch64-linux-musl-gcc cargo build --package kfree_skb --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker="aarch64-linux-musl-gcc"

# The binary will be at:
# target/aarch64-unknown-linux-musl/release/kfree_skb
```

## How It Works

1. The eBPF program attaches to the `kfree_skb` tracepoint
2. When a packet is dropped, the program reads the drop reason from the tracepoint context
3. The reason is used as a key to increment a counter in a hash map
4. The user-space program periodically reads and displays the counters

## Code Quality & Improvements

### Recent Improvements

- **Removed dead code**: Eliminated unused `drop_size` field from `Metrics` struct
- **Refactored HTTP handlers**: Extracted duplicate HTTP response logic into separate functions (`handle_metrics_response`, `handle_not_found_response`)
- **Improved code organization**: Cleaner separation of concerns with dedicated response handler functions

## Prometheus Metrics Exporter

The application exposes a Prometheus metrics endpoint on port **9090** at the `/metrics` path. This allows you to monitor packet drops using Prometheus and visualize them with Grafana.

### Running the application

```bash
sudo cargo run --release
```

### Accessing metrics

Once the application is running, you can retrieve metrics in Prometheus format:

```bash
curl http://localhost:9090/metrics
```

Or configure Prometheus to scrape the endpoint:

```yaml
scrape_configs:
  - job_name: 'kfree_skb'
    static_configs:
      - targets: ['localhost:9090']
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kfree_skb_total_drops` | Counter | `reason` | Total number of SKB drops |
| `kfree_skb_drops_by_reason` | Counter | `reason_code`, `reason_name` | Number of drops by reason |
| `kfree_skb_drops_total_bytes` | Gauge | `reason` | Total bytes dropped by reason |

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
# HELP kfree_skb_drops_total_bytes Total bytes dropped by reason
# TYPE kfree_skb_drops_total_bytes gauge
kfree_skb_drops_total_bytes{reason="all"} 524288
```

## Output Example

```
Waiting for Ctrl-C... (drops will be displayed periodically)

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

- `kfree_skb/` - User-space Rust application with Prometheus metrics exporter
- `kfree_skb-ebpf/` - Kernel-space eBPF program source
- `kfree_skb-common/` - Shared types between user and eBPF code
