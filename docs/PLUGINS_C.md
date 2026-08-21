# C Plugin Development Guide

Learn how to create bpfagent plugins whose eBPF kernel program is written in
**C** instead of Rust.

For everything not covered here — the userspace handler, registration,
configuration, metrics — see [PLUGINS.md](PLUGINS.md); it all stays in Rust
and works identically for C-produced eBPF objects.

## Overview

A plugin consists of three parts:

1. **eBPF kernel program** - collects data from kernel (this guide: **in C**)
2. **Shared types** - common structures between kernel and userspace
3. **Userspace handler** - collects and displays metrics (always Rust)

The key insight that makes C possible: the agent loads plugins with
`aya::Ebpf::load()`, which takes any compiled BPF ELF object. aya-build
produces that object from Rust; `clang -target bpfel` produces the same kind
of object from C. Everything downstream — program lookup, attach, maps,
metrics — is unchanged.

A copy-ready template for the C program (step 1) is available at
[`docs/templates/custom_program.c`](templates/custom_program.c).

## Requirements vs the Rust path

| Concern | Rust (aya-ebpf) | C (clang) |
|---|---|---|
| Compiler | nightly rustc + bpf-linker | clang with BPF backend |
| Logging | `aya-log-ebpf` (captured by the agent) | `bpf_trace_printk` → trace pipe only |
| CO-RE | build-time bindings via aya | **not available** (aya applies no CO-RE relocations at load time) |
| Maps | `#[map]` macro | BTF-style `SEC(".maps")` (needs `-g`) or legacy `SEC("maps")` |
| Program name | Rust fn name | C fn name (the ELF symbol) |

Check your clang has the BPF backend:

```bash
clang -print-targets | grep -i bpf   # want: bpfel
```

## Quick Start

### 1. Create the C Program

```bash
mkdir -p ebpf/my_program
cp docs/templates/custom_program.c ebpf/my_program/my_program.c
```

The template is self-contained (no kernel headers or libbpf needed). The
conventions that matter to aya:

- **Section name** decides the program type: `SEC("tracepoint/...")`,
  `SEC("kprobe/...")`, `SEC("xdp")`, `SEC("classifier")`, ...
- **Function name** becomes the aya program name. `bpf_program_name()` in
  your Rust handler and `ebpf.program_mut("my_handler")` must match it.
- **Maps** are defined BTF-style in `SEC(".maps")`; compile with `-g` so the
  BTF aya needs is present.
- **`SEC("license")`** must exist, e.g. `"Dual MIT/GPL"`.
- **Helpers** are declared as function pointers by number
  (`bpf_map_lookup_elem` = 1, `bpf_map_update_elem` = 2,
  `bpf_trace_printk` = 6, ...). Add prototypes as needed from
  `include/uapi/linux/bpf.h`. If you prefer, you can instead include
  `vmlinux.h` + `bpf_helpers.h` from a libbpf checkout — just stay away from
  CO-RE macros (see [Limitations](#limitations)).

### 2. Create Shared Types

Same as in [PLUGINS.md](PLUGINS.md): a `common/my_program` crate with
`#[repr(C)]` Rust structs. With a C kernel program you additionally declare
the matching struct in C and keep the two in sync by hand:

```rust
// common/my_program/src/lib.rs
#[repr(C)]
pub struct MyEvent {
    pub pid: u32,
    pub timestamp: u64,
}
```

```c
// ebpf/my_program/my_program.c (or a shared my_program.h)
struct my_event {
    __u32 pid;
    __u64 timestamp;
};
```

Field order, sizes, and alignment must match exactly — that is the wire
format between kernel and userspace.

### 3. Wire Up the Build

Nothing to do — `cargo build` handles C programs transparently.
`bpfagent/build.rs` discovers every `ebpf/<plugin>/*.c` in the workspace and
compiles it with clang (`-target bpfel -O2 -g`) into `OUT_DIR/<file-stem>`,
where `<file-stem>` is what the userspace handler loads via
`include_bytes_aligned!(concat!(env!("OUT_DIR"), "/<file-stem>"))`. Sources
are rebuilt when they change (`cargo:rerun-if-changed`); with no C files
present the step is a no-op and clang is never invoked.

Notes:

- `bpfel` (little-endian) covers x86_64 and most ARM64 targets.
- `-g` is required for BTF-style maps.
- The output file name (the `.c` file stem, e.g. `my_program.c` →
  `my_program`) plays the role of the `[[bin]]` name in the Rust flow.
- No workspace `Cargo.toml` member or build.rs edit is needed for a C
  program — it is not a crate, just a source file.

### 4. Create the Userspace Handler

Identical to [PLUGINS.md](PLUGINS.md) step 3 — including `load()`. Nothing
in the handler changes because of C. A complete handler matching both the
Rust and C kernel templates is available at
[`docs/templates/custom.rs`](templates/custom.rs); the essentials:

```rust
fn load(&mut self) -> Result<(), anyhow::Error> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/my_program"
    )))?;

    // aya names the program after the C function: my_handler
    let program: &mut aya::programs::TracePoint = ebpf
        .program_mut("my_handler")
        .ok_or_else(|| anyhow::anyhow!("program not found"))?
        .try_into()?;

    program.load()?;
    // category/event of the tracepoint from the SEC() name
    program.attach("syscalls", "sys_enter_openat")?;

    self.ebpf = Some(ebpf);
    Ok(())
}
```

Reading the `counters` map also works the usual way:
`aya::maps::HashMap<_, u32, u64>::try_from(ebpf.map("counters")...)`.

### 5. Register the Program and Configure

Exactly as in [PLUGINS.md](PLUGINS.md) steps 4 and 6:

- `pub mod my_program;` in `bpfagent/src/programs/mod.rs`
- `crate::programs::my_program::init(&mut registry);` in `bpfagent/src/app.rs`
- a `[[ebpf_programs]]` entry in the config

No workspace `Cargo.toml` member is needed for the C program — it is not a
crate, just a source file compiled automatically by build.rs.

## Testing Your Plugin

- Userspace unit/integration tests: unchanged, see [PLUGINS.md](PLUGINS.md).
- The C object can be inspected directly after a build:

```bash
llvm-objdump -h target/*/build/bpfagent-*/out/my_program
# expect: tracepoint/... TEXT section, .maps DATA section, license
```

- Verifier/attach errors surface in the agent log:

```bash
RUST_LOG=debug cargo run --release -- --verbose
```

- `bpf_trace_printk` output is **not** captured by the agent's eBPF log
  viewer; read it from the kernel trace pipe:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

## Limitations

1. **No CO-RE.** aya does not apply CO-RE relocations when loading, so do not
   use `BPF_CORE_READ`, `__ksym` externs, or `bpf_core_field_*`. Tracepoint
   format layouts (e.g. syscall arguments) and UAPI structs are stable ABI
   and safe to read at fixed offsets; kernel-internal struct layouts are not
   portable without CO-RE.
2. **No aya-log.** `bpf_trace_printk` goes to the trace pipe only. If you
   need structured events in userspace, use a map (ring buffer or hash map)
   and read it from the handler.
3. **Endianness.** Match `-target bpfel`/`bpfeb` to the target machine.
4. **Verifier constraints apply as usual:** bounded loops, 512-byte stack,
   no floating point, no unbounded helper calls.
5. **Globals:** prefer maps over mutable globals. If you must, `.data`/`.bss`
   sections load with current aya, but per-CPU semantics differ from libbpf
   expectations — maps are simpler.

## Troubleshooting

### clang: error: unsupported target 'bpf'
Your clang lacks the BPF backend — install a clang/LLVM build that includes
it (check with `clang -print-targets | grep -i bpf`).

### "program not found" at load
The function name in C does not match `program_mut(...)` /
`bpf_program_name()`. List symbols with `llvm-objdump -t <object>`.

### Map creation fails
Usually missing BTF: recompile with `-g`, and confirm a `.BTF` section
exists (`llvm-objdump -h <object> | grep BTF`).

### Verifier rejects the program
Run the agent with `RUST_LOG=debug` to see the verifier log, and check for
unbounded loops, out-of-bounds stack access, or helper prototype mistakes
(wrong helper number).

## Resources

- [PLUGINS.md](PLUGINS.md) - userspace handler, registration, metrics
- [BPF helper functions (kernel docs)](https://www.kernel.org/doc/html/latest/bpf/bpf_helpers.html)
- [Aya Documentation](https://docs.aya-rs.dev/)
- [BPF maps](https://ebpf.io/what-is-ebpf/#maps)
