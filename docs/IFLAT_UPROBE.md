# IFLAT_UPROBE

IFLAT_UPROBE measures the latency of UDP, TCP datagrams: how long the kernel holds one datagram 1) from
ingress on the RX interface (e.g. `eno1`) to ingress on the RX interface (e.g. `tun0`) and then 2) from ingress on the RX interface (e.g. `tun0`) to call  C++ function "void FpgaPciePhy::submitBurst(Endpoint from, TxSlot &slot)".
So, the result is pair of latencies:
1. between RX on eno1 and RX on tun0
2. between RX on tun0 and the function call

### Data Flow

```mermaid
flowchart TD
    SRC[Sender] --> |UDP/TCP datagram| RX[eno1 ingress<br/>XDP: store timestamp by payload tag]
    RX --> FWD[APP]
    FWD --> |UDP/TCP datagram|  TX[tun0 ingress<br/>XDP: match tag, accumulate latency]
    TX --> FUNCTION[function call with payload passed as parameter<br/>UPROBE: match tag, accumulate latency]
```

#### Latency Measurement Approach

1. On ingress on eno1: parse Ethernet/IPv4 + UDP/TCP and store `TIMESTAMP1_MAP[tag] = bpf_ktime_get_ns()`
2. On ingress on tun0: parse Ethernet/IPv4 + UDP/TCP and store `TIMESTAMP2_MAP[tag] = bpf_ktime_get_ns()`
3. On every call of function()  look up the tag; on a match remove the record and add the latency to the
   `LATENCY1_SUM`/`LATENCY1_COUNT` accumulators. Do it for both  TIMESTAMP1_MAP, TIMESTAMP2_MAP
4. Userspace turns the accumulators into a periodic moving average

### Measurement Points (as implemented)

The two accumulations happen at different hooks, matching the data-flow
diagram and the latency pair above:

1. **RX1** (`iflat_uprobe_xdp_rx1`, XDP on `rx1_iface`, e.g. `eno1`): parses
   Ethernet/IPv4 + UDP/TCP and stores `TIMESTAMP1_MAP[tag] = bpf_ktime_get_ns()`.
2. **RX2** (`iflat_uprobe_xdp_rx2`, XDP on `rx2_iface`, e.g. `tun0`): parses
   IPv4 + UDP/TCP (a tun device has no L2 header; the parser auto-detects
   it), looks up the tag in `TIMESTAMP1_MAP`; on a match it removes the
   record and accumulates the RX1→RX2 latency into
   `LATENCY1_SUM`/`LATENCY1_COUNT`. It then stores
   `TIMESTAMP2_MAP[tag] = bpf_ktime_get_ns()` unconditionally, so the second
   leg is measured even for datagrams first seen at RX2 (e.g. after a
   mid-flow agent start).
3. **Function call** (`iflat_uprobe_fn_call`, uprobe on `symbol` in
   `target`): rebuilds the tag from the payload passed as a parameter. The
   payload pointer is resolved from the configured argument register
   (`arg_index`, x86_64 SysV ABI) in one of two modes: directly (the
   argument points at the payload), or through the payload-pointer member
   of the struct the argument points to (`payload_ptr_offset`, e.g.
   `slot->payload` at `offsetof(TxSlot, payload)`). The first 4 payload
   bytes at `tag_offset` are read from userspace memory big-endian. On a
   match in `TIMESTAMP2_MAP` it removes the record and accumulates the
   RX2→function-call latency into `LATENCY2_SUM`/`LATENCY2_COUNT`.

### Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `TIMESTAMP1_MAP` | LRU hash (1024) | tag (u32) | RX1 timestamp (ns) | consumed by the RX2 sighting |
| `TIMESTAMP2_MAP` | LRU hash (1024) | tag (u32) | RX2 timestamp (ns) | consumed by the function call |
| `LATENCY1_SUM` / `LATENCY1_COUNT` | hash, 1 entry | 0 | cumulative sum (ns) / count | RX1→RX2 moving average |
| `LATENCY2_SUM` / `LATENCY2_COUNT` | hash, 1 entry | 0 | cumulative sum (ns) / count | RX2→call moving average |
| `UPROBE_CONFIG_MAP` | hash, 1 entry | 0 | `UprobeConfig { arg_index, payload_ptr_offset, tag_offset }` | written by userspace at load time |

### Moving Average and Metrics

The BPF maps hold cumulative accumulators since program load; userspace
converts them to per-tick deltas and averages each tick (`stats_interval_ms`,
default 3000 ms), so the reported latencies reflect recent traffic. A tick
with no matched datagrams reports 0.

- `iflat_uprobe_avg_latency1_us` — average RX1→RX2 latency in microseconds
- `iflat_uprobe_avg_latency2_us` — average RX2→function-call latency in
  microseconds

Interactive mode logs one line per leg and tick with samples:

```
IFLAT_UPROBE RX1->RX2 latency: 8123 us (4 samples, eno1 -> tun0)
IFLAT_UPROBE RX2->submitBurst latency: 1544 us (4 samples)
```

### Configuration

```toml
[[ebpf_programs]]
name = "iflat_uprobe"
enabled = true

[ebpf_programs.settings]
rx1_iface = "eno1"        # first ingress interface (XDP)
rx2_iface = "tun0"        # second ingress interface (XDP)
target = "/path/to/app"   # binary or shared library to instrument
symbol = "function_name"  # function receiving the payload (ELF symbol)
# offset = 0              # extra byte offset past the symbol
# pid = -1                # -1 = all processes, or a specific PID
# arg_index = 3           # SysV argument register leading to the payload
# payload_ptr_offset = -1 # offset of the payload pointer within the
#                           pointed-to struct; -1 = the argument points
#                           directly at the payload
# tag_offset = 0          # byte offset from the resolved payload pointer
#                           to the first payload byte
```

`rx1_iface`, `rx2_iface`, `target` and `symbol` are required; without them
the program logs a warning and stays disabled instead of failing the agent.

`arg_index` counts the six integer/pointer argument registers of the x86_64
SysV ABI (1 = rdi … 6 = r9). For a C++ method the hidden `this` pointer is
register 1, so for `void FpgaPciePhy::submitBurst(Endpoint from, TxSlot &slot)`
with an `Endpoint` that occupies one register (enums do), `slot` is register
3 — the default.

`payload_ptr_offset` selects how the payload address is found (default -1 =
`PAYLOAD_PTR_DIRECT`):

- **-1 (direct mode)**: the argument register points straight at the
  payload; no pointer chase. Use this for functions taking
  `const uint8_t *payload`-style parameters.
- **N (struct mode)**: the argument register points at a struct whose
  member at byte offset N is the payload pointer. For
  `submitBurst(Endpoint from, TxSlot &slot)` the payload address is the
  `payload` member of `TxSlot`, so N = `offsetof(TxSlot, payload)`.

`tag_offset` is added to the resolved payload pointer; 0 keys on the first
4 payload bytes.

#### Locating the payload in TxSlot

For the `TxSlot` layout

```cpp
struct TxSlot {
    std::atomic<TxSlotState> state;   // enum, 4 bytes
    uint32_t index;                   // 4
    Endpoint endpoint;                // enum, 4
    metadata_data_tx_t burst;         // 256 bytes
    uint64_t dispatch_time;           // 8
    uint64_t enqueued_ncr;            // 8
    uint64_t dispatch_ncr;            // 8
    uint8_t *payload;                 // 8  <== points at the payload area
    uint32_t payload_capacity;        // 4
    uint32_t payload_length;          // 4
};
```

the member offsets on x86_64 are `state` = 0, `index` = 4, `endpoint` = 8,
`burst` = 12 (or 16 when `metadata_data_tx_t` is 8-aligned), the three
`uint64_t` counters start at 272 either way, and **`payload` = 296**
(`recordCount()` is a non-virtual member function — no vtable, no stored
members). The matching settings are:

```toml
arg_index = 3             # rdx = slot (rdi = this, rsi = from)
payload_ptr_offset = 296  # offsetof(TxSlot, payload)
tag_offset = 0            # tag = first 4 payload bytes
```

The 296 figure assumes 4-byte enums and `metadata_data_tx_t` alignment of
at most 8; verify against the real build before relying on it — e.g.
`static_assert(offsetof(TxSlot, payload) == 296);` in the target's source,
or `ptype /o TxSlot` in gdb (needs debug info).

C++ symbols are mangled in the ELF; `symbol` must be the mangled name unless
the target exports an unmangled alias. Find it with
`nm -C /path/to/app | grep submitBurst` (or `objdump -T` for shared
libraries) and use the mangled form, e.g.
`_ZN11FpgaPciePhy11submitBurstE8EndpointR6TxSlot`.

### Limitations

- x86_64 only (the argument-register convention is the SysV ABI).
- The configured argument must lead to readable userspace memory holding
  the payload when the function is entered (in struct mode the payload
  pointer member is chased with one extra read); reads happen with
  `bpf_probe_read_user` and failures are skipped silently.
- IPv4 only; UDP and TCP only (no ICMP, no VLAN tags); TCP segments with
  less than 4 payload bytes (e.g. pure ACKs) are skipped.
- XDP attaches in native (driver) mode with a fallback to generic (SKB)
  mode when the NIC driver has no XDP support.
- Tag collisions across in-flight datagrams with identical first 4 payload
  bytes overwrite each other in the LRU timestamp maps; a stale entry can
  produce a bogus sample, which the moving average absorbs.

### Simulator

`bpfagent/examples/iflat_uprobe_sim.rs` builds the whole data flow on one
machine (locally generated packets never pass XDP ingress, so the sender
runs on the far side of a real link — a network namespace connected by a
veth pair):

- the host end of the veth pair (`veth-iu0`, 192.168.101.1/24) plays the
  role of the production RX1 interface; the sender inside the namespace
  (`veth-iu1`, 192.168.101.2/24) emits one UDP datagram per 500 ms carrying
  a random 4-byte tag plus its CLOCK_MONOTONIC send timestamp
- `tun0` (10.200.1.1/24) is RX2: the simulator (playing the forwarding
  application) receives the leg-1 datagrams on a UDP socket and re-injects
  them into the tun fd, so they enter the kernel on tun0 ingress; no NAT or
  routing is involved, the datagrams are addressed to the host itself
- the kernel delivers the re-injected datagrams to the tun-side socket, and
  the simulator calls the exported `iflat_uprobe_sim_submit()` with the
  payload wrapped in a `TxSlotSim` struct that mirrors the production
  TxSlot layout (`payload` pointer at offset 296, checked at compile time);
  the function takes a dummy leading `this` pointer, so `slot` sits in
  argument register 3 like the real C++ method
- per datagram the simulator prints the userspace sender→tun-injection and
  tun-injection→function-call spans — supersets of the agent's gauges (they
  also cover the netns → veth delivery and the socket hops)

```bash
cargo build --example iflat_uprobe_sim
sudo ./target/debug/examples/iflat_uprobe_sim          # needs root, iproute2
sudo ./target/debug/examples/iflat_uprobe_sim 10       # + 10 ms netem delay in the namespace
# agent with the config snippet the sim prints at startup:
sudo ./target/debug/bpfagent -f /path/to/iflat_uprobe.conf
curl http://localhost:9101/metrics | grep iflat_uprobe_avg_latency
```

With a netem delay the sim's userspace span grows by that amount while the
agent's RX1→RX2 span does not (RX1 timestamps the datagram after the
delay) — demonstrating that IFLAT_UPROBE isolates the forwarding path.
