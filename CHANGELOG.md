# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive file structure reorganization
- Documentation directory (docs/) with guides
- Configuration examples and templates
- Development scripts (build, test, lint, format, release)
- Contributing guidelines
- Plugin development guide
- Development setup guide
- Improved error messages with context
- `.gitignore` with comprehensive ignore rules
- SCA pipeline simulator example (`bpfagent/examples/sca_sim.rs`) for end-to-end testing
- `sca_sim` space-bar pause: pressing SPACE in the simulator's terminal
  SIGSTOP/SIGCONTs the initiator, pausing/resuming the data flow without
  tearing down the pipeline

### Changed
- Improved code organization with logical modules
- Enhanced error handling throughout codebase
- Better logging in daemon mode
- Refactored daemonization code
- SCA hop tracking: `SOCKET_HOPS_MAP` is now keyed by `(pid << 32) | fd` with a
  sender/receiver role, and `TIMESTAMP_MAP` by `(hop_index << 32) | Protocol`,
  fixing fd-number collisions across processes
- SCA hop discovery now uses `ss -xp` peer-inode pairing (which also finds the
  sender-side connected fds) instead of the lsof pipeline

### Fixed
- Removed unsafe libc::fflush() calls
- Fixed error handling in metrics initialization
- kfree_skb Prometheus counters were inflated by re-adding cumulative map values
  every display interval; they now increment only by the delta since last read
- SCA per-process latency was accumulative (each hop included all downstream
  hops, since a reply is sent only after the downstream reply arrives); the
  downstream hop's latency for the same message is now subtracted
  (`LATENCY_HOP_MAP`), so `sca_avg_latency_per_pname` reports each hop's
  individual contribution
- SCA moving-average window was 20 s instead of the documented 2 s
- SCA process discovery no longer aborts on the first unreadable /proc entry
- SCA moving-average output no longer repeats a PID's last average forever
  after traffic stops; PIDs with no new samples between display ticks are
  dropped from the log output and their Prometheus series are removed

## [0.1.0] - 2026-08-07

### Added
- Initial release
- kfree_skb eBPF program for packet drop tracing
- SCA program for latency measurement
- Prometheus metrics export via HTTP endpoint
- Daemon and interactive modes
- Configuration file support
- Comprehensive README
- Architecture documentation

### Features
- Modular plugin architecture for eBPF programs
- Configurable program loading via TOML
- Prometheus metrics in text format
- Graceful signal handling
- Cross-compilation support (x86_64, ARM64)

---

## How to Upgrade

### From 0.1.0 to 0.2.0 (Unreleased)

No breaking changes. Configuration files remain compatible.

New features:
1. Check out new documentation in `docs/`
2. See deployment examples in `config/` and `examples/`
3. Use development scripts: `./scripts/build.sh`, `./scripts/test.sh`
4. Contributing: see `docs/CONTRIBUTING.md`

## Future Releases

### Planned Features
- [ ] Health check endpoint
- [ ] Async HTTP server (hyper/axum)
- [x] GitHub Actions CI/CD pipeline
- [x] Pre-built release binaries
- [x] Docker image
- [ ] Kubernetes deployment manifests
- [x] Integration tests
- [ ] Security audit
- [ ] Performance benchmarks
- [ ] Extended eBPF programs library
