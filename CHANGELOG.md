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

### Changed
- Improved code organization with logical modules
- Enhanced error handling throughout codebase
- Better logging in daemon mode
- Refactored daemonization code

### Fixed
- Removed unsafe libc::fflush() calls
- Fixed error handling in metrics initialization

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
- [ ] GitHub Actions CI/CD pipeline
- [ ] Pre-built release binaries
- [ ] Docker image
- [ ] Kubernetes deployment manifests
- [ ] Integration tests
- [ ] Security audit
- [ ] Performance benchmarks
- [ ] Extended eBPF programs library
