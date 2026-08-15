# Development Guide

This guide explains how to develop and debug BPF Agent.

## Prerequisites

- Linux kernel with BPF support
- Rust stable and nightly toolchains
- LLVM and Clang
- bpf-linker

Run `./scripts/setup.sh` to install everything.

## Project Structure

```
bpfagent/
├── bpfagent/              # User-space application
│   ├── src/
│   │   ├── main.rs        # Application entry point
│   │   ├── cli/           # Command-line argument parsing
│   │   ├── config/        # Configuration loading
│   │   ├── programs/      # eBPF program management
│   │   ├── daemon/        # Daemonization logic
│   │   ├── metrics/       # Prometheus metrics
│   │   └── error.rs       # Error types
│   └── tests/             # Integration tests
│
├── common/                # Shared types between eBPF and userspace
│   ├── kfree_skb/
│   └── sca/
│
├── ebpf/                  # eBPF kernel programs
│   ├── kfree_skb/
│   └── sca/
│
└── docs/                  # Documentation
```

## Build

### Development Build
```bash
cargo build --package bpfagent
```

### Release Build
```bash
./scripts/build.sh release
```

### Cross-compile for ARM64
```bash
rustup target add aarch64-unknown-linux-musl
cargo build --package bpfagent --release --target aarch64-unknown-linux-musl
```

## Testing

### Run All Tests
```bash
./scripts/test.sh
```

### Run Specific Test
```bash
cargo test --lib test_name
```

### Run with Output
```bash
cargo test -- --nocapture
```

### Run Integration Tests
```bash
cargo test --test integration_test
```

### SCA End-to-End Simulation

Run the SCA pipeline simulator (6 processes, 7 Unix-socket hops, NNG-like
REQ/REP over sendmsg; no root needed):

```bash
cargo run -p bpfagent --example sca_sim
```

Then, in another terminal, start the agent — hop discovery happens once at
load, so the simulator must be running first:

```bash
sudo ./target/debug/bpfagent
```

Watch the SCA metrics:

```bash
watch -n1 'curl -s http://localhost:9101/metrics | grep sca'
```

## Debugging

### Enable Debug Logging
```bash
RUST_LOG=debug cargo run --release -- --daemon=false
```

### Debug with GDB
```bash
rust-gdb ./target/debug/bpfagent
```

### Check eBPF Program Loads
```bash
cargo run --release -- --daemon=false --verbose
```

Look for "Loaded program" messages to verify eBPF programs loaded successfully.

## Code Quality

### Format Code
```bash
cargo fmt
```

### Run Linter
```bash
./scripts/lint.sh
```

### Check for Issues
```bash
cargo clippy --all
```

## Performance Testing

### Run with Profiling
```bash
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release
perf record ./target/release/bpfagent
perf report
```

## Common Issues

### eBPF Program Load Fails
- Check kernel version (need 5.8+)
- Verify BPF syscall permissions
- Check CONFIG_BPF=y in kernel

### Metrics Not Appearing
- Verify HTTP endpoint: `curl http://localhost:9101/metrics`
- Check program status: enable verbose mode
- Review logs: `RUST_LOG=debug`

### Memory Usage High
- eBPF maps are pre-allocated, check size in ebpf/*/src/main.rs
- Process large maps with pagination

## Adding a New Program

1. Create eBPF source in `ebpf/<name>/src/main.rs`
2. Create common types in `common/<name>/src/lib.rs`
3. Create handler in `bpfagent/src/programs/<name>/`
4. Register in `bpfagent/src/programs/mod.rs`
5. Add tests
6. Document in `docs/PLUGINS.md`

## Useful Commands

```bash
# Check compilation without building
cargo check --all

# Build documentation
cargo doc --open

# Run with custom config
cargo run --release -- -f config/bpfagent.conf.full

# List available programs
cargo run --release -- --help
```

## Benchmarking

### Measure startup time
```bash
time ./target/release/bpfagent --daemon=false --help
```

### Profile memory
```bash
/usr/bin/time -v ./target/release/bpfagent
```

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run `./scripts/test.sh`
4. Tag release: `git tag v1.2.3`
5. Run `./scripts/release.sh 1.2.3`
6. Create GitHub release with binaries

## Resources

- [eBPF Documentation](https://ebpf.io/)
- [Aya Framework](https://github.com/aya-rs/aya)
- [Prometheus Metrics](https://prometheus.io/)
- [Rust Book](https://doc.rust-lang.org/book/)
