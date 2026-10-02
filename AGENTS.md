# AGENTS.md

Guidance for AI coding agents working on this repository. Assumes no prior
knowledge of the project.

## Project Overview

**bpfagent** is a generic eBPF program manager and Prometheus metrics exporter,
written in Rust on top of the [Aya](https://github.com/aya-rs/aya) framework
(pinned to the aya git repository, not crates.io). It runs as a root daemon on
Linux, loads multiple eBPF programs into the kernel, periodically reads their
BPF maps, and exposes the collected data as Prometheus metrics over HTTP
(default `0.0.0.0:9101/metrics`).

Six eBPF programs ship with the agent, plus the `my_program` example plugin
(the `docs/PLUGINS.md` worked example, disabled by default):

- **kfree_skb** — counts kernel packet drops by reason at the `skb:kfree_skb`
  tracepoint (kernel `enum skb_drop_reason`).
- **sca** — measures socket communication latency per process across a fixed
  pipeline of Unix domain socket hops (NNG-like REQ/REP); hop endpoints are
  discovered once at load time via `ss -xpH`.
- **irss** — measures UDP-to-raw-IP forwarding latency of the IRSS data flow
  (CRYPTO → IRSS → MAC); datagrams are keyed by their first 4 payload bytes,
  filters are runtime-configurable (`listen_port`, `raw_dest`).
- **iflat** — measures interface-to-interface forwarding latency of
  UDP/TCP/ICMP-echo datagrams (e.g. `eno1` → `tun0`) across nftables NAT;
  an XDP program on the ingress interface and a TC clsact egress classifier
  on the egress interface correlate datagrams by their first 4 payload
  bytes (which NAT does not rewrite); interfaces are required settings
  (`rx_iface`, `tx_iface`), without them the program stays disabled.
- **iflat_uprobe** — measures a pair of latencies for one UDP/TCP datagram:
  ingress on `rx1_iface` (XDP) → ingress on `rx2_iface` (XDP) → the call of
  a function receiving the payload as a parameter (uprobe, e.g.
  `FpgaPciePhy::submitBurst`); datagrams are correlated by their first 4
  payload bytes, the uprobe tag location is runtime-configurable
  (`arg_index`, `payload_ptr_offset`, `tag_offset`); interfaces and the
  attach target are required
  settings (`rx1_iface`, `rx2_iface`, `target`, `symbol`).
- **uprobe** — traces calls to a function in a userspace binary/shared
  library and snapshots its arguments (up to 6 register values, x86_64 SysV
  ABI); the attach target is runtime-configurable (`target`, `symbol`,
  `offset`, `pid`, `string_arg`).
- **my_program** — the worked example plugin from `docs/PLUGINS.md`, kept in
  the tree as a live reference implementation: counts `sys_enter_openat`
  calls per PID and exports the `my_program_events_per_pid` gauge. Disabled
  by default; safe starting point for new plugins.

License: MIT OR Apache-2.0. Rust edition 2021. All documentation and code
comments are in English.

## Repository Layout

Cargo workspace (root `Cargo.toml`) with 15 members. Each eBPF program follows a
strict three-crate pattern:

```
bpfagent/               # Userspace application (lib + thin `bpfagent` binary)
├── src/
│   ├── main.rs         # Thin binary entry point
│   ├── lib.rs          # Library root: app, cli, config, daemon, metrics, programs
│   ├── app.rs          # Program wiring, eBPF loading, Prometheus setup, event loop
│   ├── daemon.rs       # Daemonization (fork, stdio redirect, setsid)
│   ├── cli/            # clap command-line argument definitions
│   ├── config/         # TOML config parsing (loader.rs) and daemon settings
│   ├── metrics/        # Prometheus HTTP server (server.rs)
│   └── programs/       # Program registry, traits, and per-program modules
│       ├── traits.rs       # EbpfProgram, MetricsDisplay, EbpfAccess traits
│       ├── registry.rs     # ProgramRegistry (name -> factory closure)
│       ├── irss/mod.rs     # IRSS userspace handler (metrics, display)
│       ├── kfree_skb/mod.rs
│       ├── sca/mod.rs      # SCA handler (metrics, display, hop discovery)
│       ├── iflat/mod.rs    # IFLAT handler (metrics, display, XDP/TC attach)
│       ├── iflat_uprobe/mod.rs # IFLAT_UPROBE handler (XDP x2 + uprobe attach)
│       ├── uprobe/mod.rs   # uprobe handler (metrics, display, attach config)
│       └── my_program/mod.rs # example plugin from docs/PLUGINS.md
├── examples/
│   ├── irss_sim.rs     # IRSS data-flow simulator for end-to-end testing
│   ├── sca_sim.rs      # SCA pipeline simulator (6 processes, 7 hops)
│   ├── iflat_sim.rs    # IFLAT topology simulator (netns+veth+tun+NAT; root)
│   ├── iflat_uprobe_sim.rs # IFLAT_UPROBE simulator (netns+veth+tun +
│   │                     # TxSlot-mirroring uprobe target; root)
│   └── uprobe_sim.rs   # uprobe test target (calls a known function in a loop)
├── tests/              # Integration tests (no root required)
├── build.rs            # Compiles all eBPF crates via aya-build (see below)
└── Cargo.toml          # Also holds [package.metadata.deb] for cargo-deb

common/<name>/          # Shared types between kernel and userspace
                        # (iflat, iflat_uprobe, irss, kfree_skb, my_program,
                        #  sca, uprobe; no_std-compatible,
                        #  optional `user` feature pulls in aya for userspace)
ebpf/<name>/            # eBPF kernel program source (#![no_std] #![no_main],
                        # compiled to bpfel-unknown-none)

config/                 # bpfagent.conf.example, bpfagent.conf.full,
                        # systemd/bpfagent.service, prometheus/prometheus.yml.example
docs/                   # ARCHITECTURE.md, DEVELOPMENT.md, PLUGINS.md,
                        # PLUGINS_C.md, IRSS.md, SCA_DATA_FLOW.md, bpfagent.1,
                        # templates/ (plugin skeletons)
examples/docker/        # Dockerfile + docker-compose.yml + prometheus.yml
scripts/                # setup.sh, build.sh, test.sh, lint.sh, format.sh, release.sh
bpfagent.conf           # Development config (current dir is a search path)
```

The workspace `default-members` are `bpfagent` + the seven `common/*` crates;
the `ebpf/*` crates are workspace members but are built for the BPF target by
`bpfagent/build.rs`, not by a plain `cargo build`.

## Build System Details

- `bpfagent/build.rs` discovers the `iflat-ebpf`, `iflat_uprobe-ebpf`,
  `irss-ebpf`, `kfree_skb-ebpf`, `my_program-ebpf`, `sca-ebpf`, and
  `uprobe-ebpf` packages from workspace
  metadata and compiles
  them with `aya-build` (nightly toolchain + `bpf-linker` to
  `bpfel-unknown-none`). The
  objects land in `OUT_DIR` under their `[[bin]]` names and are embedded into
  the userspace binary with `aya::include_bytes_aligned!`.
- The same build script transparently compiles every `ebpf/<plugin>/*.c` file
  with `clang -target bpfel -O2 -g -c` into `OUT_DIR/<file-stem>` (no-op when
  no C sources exist). See `docs/PLUGINS_C.md`.
- `.cargo/config.toml` sets `linker = "bpf-linker"` for `bpfel-unknown-none`
  and `runner = "sudo -E"` for all targets — plain `cargo run` executes the
  agent under sudo.
- Root `Cargo.toml` has a release profile tweak for `kfree_skb-ebpf`
  (`debug = 2`, `codegen-units = 1`, `strip = false`).

## Prerequisites

- Linux kernel 5.8+ with BPF support (`CONFIG_BPF=y`); BTF
  (`CONFIG_DEBUG_INFO_BTF=y`) recommended; tracepoints for `skb:kfree_skb`,
  `syscalls:sys_enter_sendmsg`, `syscalls:sys_exit_recvmsg`; kprobe support
  for `udp_recvmsg`.
- Rust stable (default) and nightly with `rust-src`:
  `rustup toolchain install nightly --component rust-src`
- `bpf-linker` (`cargo install bpf-linker`), clang/llvm, libelf.
- For aarch64 cross builds: `rustup target add aarch64-unknown-linux-musl`
  plus `musl-tools`.
- `./scripts/setup.sh` installs all of the above (apt/yum based).

## Build and Run Commands

```bash
./scripts/build.sh release            # release build (x86_64 by default)
./scripts/build.sh debug              # debug build
cargo build --package bpfagent --release
cargo check --all                     # fast compile check of the whole workspace

# Cross-compile for ARM64 (Petalinux 2024.2):
CC=aarch64-linux-musl-gcc cargo build --package bpfagent --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker="aarch64-linux-musl-gcc"

# Debian package (metadata in bpfagent/Cargo.toml; run from repo root):
cargo deb -p bpfagent --target aarch64-unknown-linux-musl
```

Running requires root (eBPF loading). The binary lands at
`target/<triple>/release/bpfagent`:

```bash
sudo ./target/x86_64-unknown-linux-gnu/release/bpfagent          # interactive (default)
sudo ./target/x86_64-unknown-linux-gnu/release/bpfagent -d -f config/bpfagent.conf.example
curl http://localhost:9101/metrics                               # scrape metrics
```

CLI flags: `-d/--daemon`, `-i/--metrics-ip` (default `0.0.0.0`),
`-p/--metrics-port` (default `9101`), `-v/--verbose`, `-f/--config-file`.
In interactive mode statistics print to stdout on the stats interval
(`stats_interval_ms`, default 3000 ms); the same tick drives BPF-map reads
and Prometheus updates (`app.rs` event loop, `tokio::select!` over
SIGINT/SIGTERM + interval).

## Testing

```bash
./scripts/test.sh        # clippy -D warnings, fmt --check, unit + integration + doc tests
cargo test --all --lib   # unit tests (inline in source files)
cargo test --test '*'    # integration tests in bpfagent/tests/
cargo test --doc         # doc tests
```

- Integration tests live in `bpfagent/tests/` (config parsing, metrics HTTP
  handler over loopback TCP, kfree/IRSS delta and window math, SCA parsing /
  endpoint roles / freshness). They do **not** load eBPF programs and do not
  need root.
- `serial_test` and `rand` are dev-dependencies; use `#[serial]` when tests
  mutate shared/global state.
- End-to-end simulators (no root needed for the simulator itself):

```bash
cargo run -p bpfagent --example sca_sim    # start BEFORE the agent: SCA hop
                                           # discovery happens once at load
cargo run -p bpfagent --example irss_sim
cargo run -p bpfagent --example uprobe_sim # prints the path/PID to point the
                                           # uprobe settings at
sudo ./target/debug/bpfagent               # in another terminal
```

  `sca_sim` pauses/resumes the data flow when you press SPACE (SIGSTOP/SIGCONT).

- **Project-specific convention** (from `.agents/skills/SKILL.md`): live
  testing is done on the remote host `fpu117` — build the release binary,
  `scp` it over, and run it there with
  `RUST_LOG=bpfagent::programs::sca=debug,sca=debug`.

## Code Style and Conventions

- Formatting: `cargo fmt --all` (check with `./scripts/format.sh`).
  `rustfmt.toml` uses unstable options (`group_imports = "StdExternalCrate"`,
  `imports_granularity = "Crate"`, `unstable_features = true`) — these only
  take effect with nightly rustfmt (`cargo +nightly fmt`); stable rustfmt
  silently ignores them. Match the resulting style: std imports first, then
  external crates, then local, merged per crate.
- Linting: `cargo clippy --all -- -D warnings` must pass; `./scripts/lint.sh`
  additionally enables `clippy::pedantic` (warn) and runs `cargo audit` /
  `cargo outdated` when installed.
- Error handling: `anyhow::Result` everywhere in userspace; add context with
  `.context(...)`; **no `.expect()` in production code** (tests excepted).
- Doc comments (`//!` / `///`) on all public modules and APIs, with `# Errors`
  sections on fallible trait methods.
- `unsafe` code (daemonization `fork`/`dup2`/`setsid`, eBPF context reads) is
  wrapped in safe abstractions with checked return values and is documented.
- eBPF crates: `#![no_std] #![no_main]`, a `#[panic_handler]` gated on
  `target_arch = "bpf"`, and `LICENSE` static `"Dual MIT/GPL"`. Maps are plain
  shared `aya_ebpf::maps::HashMap` (no per-CPU maps).
- Userspace handlers follow the pattern in `bpfagent/src/programs/*/mod.rs`:
  module-level doc comment describing the measurement, map keying,
  configuration, and Prometheus metrics.
- Update `CHANGELOG.md` (Keep a Changelog format) for user-facing changes.

## Adding a New eBPF Program

Full instructions: `docs/PLUGINS.md` (Rust) and `docs/PLUGINS_C.md` (C);
copy-ready templates in `docs/templates/`. Checklist:

1. `ebpf/<name>/` — eBPF crate (`<name>-ebpf`, `[[bin]] name = "<name>"`; the
   bin name is the file loaded via `include_bytes_aligned!`).
2. `common/<name>/` — shared types crate (`<name>-common`).
3. `bpfagent/src/programs/<name>/mod.rs` — userspace handler implementing
   `EbpfProgram` (+ mandatory `EbpfAccess` supertrait). Programs exporting
   metrics must also implement `MetricsDisplay` **and** override
   `supports_metrics()` → `true` and `as_metrics_mut()` → `Some(self)` — the
   trait defaults silently disable all metrics wiring.
4. `pub mod <name>;` in `bpfagent/src/programs/mod.rs`.
5. `crate::programs::<name>::init(&mut registry);` in `register_programs()`
   in `bpfagent/src/app.rs`.
6. Add `"ebpf/<name>"` and `"common/<name>"` to workspace `members` in the
   root `Cargo.toml` (only `"common/<name>"` also goes into
   `default-members`), the eBPF package name to the match in
   `bpfagent/build.rs`, and `<name>-common = { path = "../common/<name>" }`
   to `[dependencies]` in `bpfagent/Cargo.toml`.
7. Optional per-program settings: override `EbpfProgram::configure()` and read
   the `[ebpf_programs.settings]` TOML table; pass runtime values to the eBPF
   side through a small config map written in `load()` before attaching
   (see `irss` → `RAW_DEST_MAP`).
8. Add an entry to `config/bpfagent.conf.example`, add tests, document.

## Configuration

TOML file; search order: `-f` flag, `/etc/bpfagent.conf`,
`/etc/bpfagent/bpfagent.conf`, `/usr/local/etc/bpfagent.conf`,
`/usr/local/etc/bpfagent/bpfagent.conf`, `~/.bpfagent.conf`,
`~/.config/bpfagent/config.toml`, `./bpfagent.conf` (used in development).
If no `[[ebpf_programs]]` entries exist, all registered programs are enabled.
Reference: `config/bpfagent.conf.full`.

## CI/CD, Release, and Deployment

- `.github/workflows/ci.yml` (push/PR to main/develop): `cargo fmt --check`,
  clippy `-D warnings`, `cargo audit`, build (stable + beta), tests,
  `cargo doc`, tarpaulin coverage.
- `.github/workflows/release.yml` (tags `v*.*.*`): GitHub release, binaries
  for `x86_64-unknown-linux-gnu` and `x86_64-unknown-linux-musl`, Docker image
  from `examples/docker/Dockerfile`.
- Release process (`docs/DEVELOPMENT.md`): bump `bpfagent/Cargo.toml` version,
  update `CHANGELOG.md`, run `./scripts/test.sh`, `git tag vX.Y.Z`, then
  `./scripts/release.sh X.Y.Z` (multi-target binaries + SHA256SUMS in `dist/`).
- Deployment: systemd unit `config/systemd/bpfagent.service` (runs the agent
  in the foreground — no `-d`; with `-d` the fork confuses `Type=simple`
  cgroup cleanup), Docker compose in `examples/docker/`, or the `.deb` package
  (`/usr/local/bin/bpfagent`, `/etc/bpfagent.conf` as conffile, systemd unit).

## Security Considerations

- The agent requires **root** (eBPF program loading); `cargo run` is wrapped
  in `sudo -E` via `.cargo/config.toml`.
- The app bumps the memlock rlimit (`RLIMIT_MEMLOCK` → infinity) for older
  kernels without memcg-based accounting.
- Daemon mode drops to a log file; PID file and log paths come from the config
  file, which is validated on parse.
- The systemd unit enables hardening (`ProtectSystem=strict`, `PrivateTmp`,
  `ProtectHome`, explicit `ReadWritePaths`).
- Never commit secrets; `.gitignore` excludes `.env*`, logs, `dist/`, and
  `target/`.

## Documentation Map

- `README.md` — features, metrics reference, config format, packaging
- `docs/ARCHITECTURE.md` — component design, traits, event loop, lifecycle
- `docs/DEVELOPMENT.md` — build/test/debug workflows
- `docs/PLUGINS.md` / `docs/PLUGINS_C.md` — plugin development (Rust / C)
- `docs/IRSS.md`, `docs/SCA_DATA_FLOW.md`, `docs/IFLAT.md`,
  `docs/IFLAT_UPROBE.md` — per-program data flows
- `docs/UPROBE.md` — uprobe settings, symbol requirements, sim walkthrough
- `docs/bpfagent.1` — man page (`man -l docs/bpfagent.1`)
- `CHANGELOG.md` — version history (Keep a Changelog)
