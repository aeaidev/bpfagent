# uprobe: Userspace Function Call Tracing

The `uprobe` program attaches a uprobe to a function in a userspace binary
or shared library, counts calls per process, and snapshots the function's
arguments.

## What It Measures

On every call to the traced function, the eBPF program updates the calling
process's record in the `CALLS` BPF map (keyed by pid):

- cumulative call count since program load
- timestamp of the most recent call
- the arguments of the most recent call: up to 6 register values
  (x86_64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9)
- the calling thread's command name (`comm`)
- optionally, one argument read as a NUL-terminated C string (up to 64
  bytes) when `string_arg` is configured

Userspace reads the map every display interval (3 s), converts the
cumulative counts to per-interval deltas for the Prometheus counter, and
prints the most recent call's arguments in interactive mode.

Note that arguments are raw register values: integers and pointers are
meaningful, floats (XMM registers) and by-value structs are not captured.
Only function entry is traced, not return values.

## Configuration

The attach target has no sensible default, so `target` and `symbol` are
required; without them the program logs a warning and stays disabled (this
also keeps the "enable all programs" fallback usable when the config lists
no `[[ebpf_programs]]` entries):

```toml
[[ebpf_programs]]
name = "uprobe"
enabled = true

[ebpf_programs.settings]
target = "/path/to/app"     # binary or shared library to instrument (required)
symbol = "function_name"    # function to trace (required)
# offset = 0                # extra byte offset past the symbol
# pid = -1                  # -1 = all processes, or a specific PID
# string_arg = 0            # 1-6: also read this argument as a C string
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `target` | string | — (required) | Path of the binary or shared library to instrument |
| `symbol` | string | — (required) | Function symbol to attach to (ELF symbol table or dynamic symbols) |
| `offset` | integer | `0` | Extra byte offset past the symbol |
| `pid` | integer | `-1` | `-1` traces all processes; a positive value traces only that PID |
| `string_arg` | integer | `0` | `1`-`6`: also read this argument as a C string; `0` disables |

Symbol resolution reads the target's ELF symbols, so stripped binaries are
not traceable by name; attach by file offset instead (find it with
`objdump -d` / `nm`) — in that case set `symbol` to any placeholder and the
real `offset`, noting the current version always resolves the symbol first,
so offset-only attach requires a symbol present. Shared libraries can be
traced by pointing `target` at the library path (e.g.
`/usr/lib/libc.so.6`, symbol `malloc`).

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `uprobe_calls_total` | Counter | `pname` | Total number of calls to the traced function, per calling process (`pname` = "comm (PID n)") |

## Output Example

```
--- uprobe calls to uprobe_sim_target (target/debug/examples/uprobe_sim) ---
  uprobe_sim (PID 42123): 57 calls (+6), last args: [0x38, 0xdeadbeef, 0x7f...], str="hello from uprobe_sim"
```

## End-to-End Test with the Simulator

`bpfagent/examples/uprobe_sim.rs` exports `uprobe_sim_target(u64, u64,
*const u8)` and calls it twice per second. Start it first and note the
printed path and PID:

```bash
cargo run -p bpfagent --example uprobe_sim
# uprobe_sim: PID 42123
# uprobe_sim: attach with target = "/path/to/target/debug/examples/uprobe_sim", ...
```

Then point the agent at it:

```toml
[[ebpf_programs]]
name = "uprobe"
enabled = true

[ebpf_programs.settings]
target = "/path/to/target/debug/examples/uprobe_sim"
symbol = "uprobe_sim_target"
string_arg = 3
pid = 42123     # optional: restrict to the simulator
```

```bash
sudo ./target/debug/bpfagent -f my_uprobe.conf
curl -s http://localhost:9101/metrics | grep uprobe
```

Debug logging from the eBPF side (string reads) is visible with
`RUST_LOG=bpfagent::programs::uprobe=debug`.
