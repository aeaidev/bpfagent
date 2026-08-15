#![no_std]

/// One endpoint of a socket hop, as seen by the eBPF program.
///
/// The SOCKET_HOPS_MAP is keyed by (pid << 32) | fd so that every
/// (process, file descriptor) pair is unambiguous, and the value tells
/// the eBPF program which hop this endpoint belongs to and whether this
/// endpoint is the hop's sender (store timestamp) or receiver (look up
/// timestamp and report latency).
#[derive(Debug, Clone, Copy)]
pub struct HopEndpoint {
    /// Index into DATA_FLOW identifying the hop
    pub hop_index: u32,
    /// 1 if this endpoint is the sending process of the hop, 0 if it is
    /// the receiving (listening) process
    pub is_sender: u32,
}

// Data flow mapping: socket path -> (sending_process_name, receiving_process_name)
// Based on docs/SCA_DATA_FLOW.md
// The index of each entry is the hop identifier used in TIMESTAMP_MAP keys.
pub const DATA_FLOW: &[(&str, &str, &str)] = &[
    (
        "/tmp/DATA_L3_TO_INTERNAL_ROUTER",
        "DATA_SOURCE",
        "INTERNAL_ROUTER",
    ),
    ("/tmp/DATA_L3_TO_WF_L", "INTERNAL_ROUTER", "RED_WF_COMM_L"),
    ("/tmp/WF_L_TO_FRAG", "RED_WF_COMM_L", "FRAGMENTER"),
    ("/tmp/FRAG_TO_IRSS_L", "FRAGMENTER", "RED_IRSS_COMM_L"),
    ("/tmp/IRSS_L_TO_FRAG", "RED_IRSS_COMM_L", "FRAGMENTER"),
    ("/tmp/FRAG_TO_COMM_WF_L", "FRAGMENTER", "RED_WF_COMM_L"),
    ("/tmp/DATA_L_TO_SINK", "RED_WF_COMM_L", "DATA_SINK"),
];

// Implement Pod for HopEndpoint when compiled for userspace with aya
// This is safe because HopEndpoint is a simple struct of u32 fields
#[cfg(feature = "user")]
pub use aya::Pod;

#[cfg(feature = "user")]
unsafe impl Pod for HopEndpoint {}

/// Tracepoint definitions - only send syscalls for latency calculation
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"),
    // ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    // ("sys_enter_write", "syscalls", "sys_enter_write"),
];

/// Socket hops map - shared between eBPF and userspace
/// Key: (pid << 32) | fd
/// Value: HopEndpoint (hop index + sender/receiver role)
/// Each hop contributes up to two entries: the sender's connected fd and
/// the receiver's accepted fd.
pub const SOCKET_HOPS_MAP_MAX_ENTRIES: u32 = 2 * DATA_FLOW.len() as u32;
