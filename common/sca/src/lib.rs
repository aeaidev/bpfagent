#![no_std]

/// Socket hop configuration for eBPF program
/// Each entry defines a hop in the data flow chain:
/// - listening_socket_fd: The socket file descriptor that the receiving process listens on
/// - sending_process_id: The process ID that sends TO this socket
/// - receiving_process_id: The process ID that listens ON this socket
#[derive(Debug, Clone, Copy)]
pub struct SocketHop {
    pub listening_socket_fd: u32,
    pub sending_process_id: u32,
    pub receiving_process_id: u32,
}

// Data flow mapping: socket path -> (sending_process_name, receiving_process_name)
// Based on SCA_DATA_FLOW.md
// Note: This is only used for display/debugging purposes.
// The actual FD/PID filtering is done via SOCKET_HOPS_MAP.
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

// Implement Pod for SocketHop when compiled for userspace with aya
// This is safe because SocketHop is a simple struct of u32 fields
#[cfg(feature = "user")]
pub use aya::Pod;

#[cfg(feature = "user")]
unsafe impl Pod for SocketHop {}

/// Tracepoint definitions - only send syscalls for latency calculation
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"),
    // ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    // ("sys_enter_write", "syscalls", "sys_enter_write"),
];

/// Socket hops map - shared between eBPF and userspace
/// Userspace populates this with FD/PID configurations, eBPF reads from it
/// Default values are zeros (disabled).
pub const SOCKET_HOPS_MAP_MAX_ENTRIES: u32 = DATA_FLOW.len() as u32;
