# SCA Re-architecture Implementation Plan

> **Note:** This plan describes the previous fd-based re-architecture and is
> kept for history. The keying has since been redesigned: `SOCKET_HOPS_MAP` is
> keyed by `(pid << 32) | fd` and `TIMESTAMP_MAP` by `(hop_index << 32) | Protocol`.
> See the "Implementation Details" section in SCA_DATA_FLOW.md for the current design.

## Current Architecture
- Uses NNG protocol/MSG Type combined key to match REQ/REP pairs
- Stores timestamp on first send, looks up on second send with key = Protocol + MSG_Type
- Latency measured across process boundaries using protocol matching

## New Architecture (per "### Update" in SCA_DATA_FLOW.md)

### Key Changes
1. **Socket-based tracking**: Instead of NNG protocol keys, track by specific Unix domain socket paths
2. **Hop-based latency**: Measure latency for each hop in the data flow chain
3. **Direct syscall tracing**: Trace `sys_enter_sendmsg` on specific sockets

### New Data Flow (from SCA_DATA_FLOW.md)
```
|       Socket                      | process listening on the socket | Process sending to the socket |
|-----------------------------------|---------------------------------|-------------------------------|
| /tmp/DATA_L3_TO_INTERNAL_ROUTER   | INTERNAL_ROUTER                 |  DATA_SOURCE                  |
| /tmp/DATA_L3_TO_WF_L              | RED_WF_COMM_L                   |  INTERNAL_ROUTER              |
| /tmp/WF_L_TO_FRAG                 | FRAGMENTER                      |  RED_WF_COMM_L                |
| /tmp/FRAG_TO_IRSS_L               | RED_IRSS_COMM_L                 |  FRAGMENTER                   |
```

### New Latency Measurement Approach

For each socket in the chain:
1. When DATA_SOURCE sends to `/tmp/DATA_L3_TO_INTERNAL_ROUTER`:
   - Store timestamp with key = socket_path + "TO"
2. When INTERNAL_ROUTER sends from `/tmp/DATA_L3_TO_INTERNAL_ROUTER`:
   - Look up timestamp with key = socket_path + "FROM"
   - Calculate latency = current_time - stored_time

### Implementation Steps

1. **Update common/sca/src/lib.rs**:
   - Define socket pairs (listening_socket, sending_process, receiving_process)
   - Add socket path to process mapping

2. **Update ebpf/sca/src/main.rs**:
   - Track socket paths being sent to (using msg_name from msghdr)
   - For each send, check if it matches one of our tracked sockets
   - Store timestamp when sending TO a listening socket
   - Look up and calculate latency when sending FROM a listening socket
   - Use socket path + direction (TO/FROM) as key

3. **Update bpfagent/src/programs/sca/mod.rs**:
   - Update populate_socket_fd_map to use new socket configuration
   - Update process names based on new architecture

4. **Update SCA_DATA_FLOW.md**:
   - Document the new architecture

5. **Update README.md**:
   - Document the new latency measurement approach

### Key Technical Challenges

1. **Socket path matching**: Need to read msg_name from user_msghdr to get destination socket path
2. **Direction tracking**: Need to distinguish between "sending to" vs "sending from" a socket
3. **Process identification**: Need to identify which process is sending (using bpf_get_current_comm or similar)