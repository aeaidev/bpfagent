### Testing

## Always do test on 'fpu117'

1. `cd /home/igor/projects/rust/aya/bpfagent && cargo build --package bpfagent --release`

2. `ssh fpu117 'sudo pkill -f bpfagent || true'`

3. `scp target/release/bpfagent fpu117:/tmp/bpfagent_new`

4. `ssh fpu117 'sudo RUST_LOG=bpfagent::programs::sca=debug,sca=debug /tmp/bpfagent_new'`

### SCA Debugging

#### Hop Discovery (ss)

SCA hop endpoints are discovered with `ss -xpH` in `bpfagent/src/programs/sca/mod.rs`:
- Line format: `u_str ESTAB Recv-Q Send-Q <path|*> <inode> * <peer-inode> users:((...))`
- The receiver's accepted socket carries the hop path directly.
- The sender's connected socket has no path (`*`); it is resolved to a hop via
  its peer inode, which is the receiver's accepted socket.
- `SOCKET_HOPS_MAP` key = `(pid << 32) | fd`, value = `HopEndpoint { hop_index, is_sender }`.
  fd numbers are per-process, so the (pid, fd) pair is unambiguous.

#### Timestamp Key

The TIMESTAMP_MAP key combines hop index and NNG Protocol:
- Key = `(hop_index << 32) | Protocol`
- This keeps timestamps per hop and protocol, independent of fd numbers
  (which collide across processes).

#### SCA Simulator

`bpfagent/examples/sca_sim.rs` simulates the full pipeline (6 processes,
7 Unix-socket hops, NNG-like REQ/REP over sendmsg) for end-to-end testing:
`cargo run -p bpfagent --example sca_sim`
Start the simulator BEFORE the agent — hop discovery happens once at load.
