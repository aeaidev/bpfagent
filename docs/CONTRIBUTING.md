# Contributing to BPF Agent

Thank you for your interest in contributing to BPF Agent! This guide will help you get started.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Development Setup

1. **Install dependencies:**
   ```bash
   ./scripts/setup.sh
   ```

2. **Clone and build:**
   ```bash
   git clone https://github.com/yourusername/bpfagent.git
   cd bpfagent
   cargo build --release
   ```

## Making Changes

### Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `./scripts/test.sh`
5. Commit with clear messages: `git commit -am "Add feature description"`
6. Push to your fork
7. Create a Pull Request

### Code Style

- Follow Rust conventions (enforced by `rustfmt`)
- Run `cargo fmt` before committing
- Run `cargo clippy` to check for common mistakes
- Add doc comments for public APIs

### Testing

- Write tests for new functionality
- Place unit tests in the same file as the code
- Place integration tests in `bpfagent/tests/`
- Ensure all tests pass: `cargo test`

### Documentation

- Update `docs/` files if changing public APIs
- Update `CHANGELOG.md` for user-facing changes
- Add examples for new features

## Adding a New eBPF Program

1. Create the eBPF program in `ebpf/<name>/`
2. Create shared types in `common/<name>/`
3. Create user-space handler in `bpfagent/src/programs/<name>/`
4. Register the program in `bpfagent/src/programs/mod.rs`
5. Add configuration to `config/bpfagent.conf.example`
6. Document in `docs/PLUGINS.md`

See `docs/PLUGINS.md` for detailed instructions.

## Pull Request Process

1. Update documentation
2. Add/update tests
3. Ensure `./scripts/test.sh` passes
4. Provide clear PR description
5. Link related issues
6. Wait for review

## Reporting Issues

- Check existing issues first
- Provide minimal reproduction case
- Include system information (kernel version, Rust version)
- Include error logs or output

## License

By contributing, you agree that your contributions will be licensed under the same MIT OR Apache-2.0 license as the project.
