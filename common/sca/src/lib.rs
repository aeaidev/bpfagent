#![no_std]

/// Socket paths to filter on
pub const SOCKET_PATHS: &[&str] = &[
    "/tmp/DATA_L3_TO_INTERNAL_ROUTER",
    "/tmp/DATA_L3_TO_WF_L",
    "/tmp/WF_L_TO_FRAG",
    "/tmp/FRAG_TO_IRSS_L",
    "/tmp/IRSS_TO_CRYPTO_L",
    "/tmp/IRSS_L_TO_FRAG",
    "/tmp/FRAG_TO_COMM_WF_L",
    "/tmp/DATA_L_TO_SINK",
];

/// Process names to filter on
pub const PROCESS_NAMES: &[&str] = &[
    "INTERNAL_ROUTER",
    "RED_WF_COMM_L",
    "FRAGMENTER",
    "RED_IRSS_COMM_L",
];

/// Tracepoint definitions
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"),
    ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    ("sys_enter_write", "syscalls", "sys_enter_write"),
    ("sys_enter_recvfrom", "syscalls", "sys_enter_recvfrom"),
    ("sys_enter_read", "syscalls", "sys_enter_read"),
    ("sys_enter_readv", "syscalls", "sys_enter_readv"),
];

/// eBPF: Process name to match
#[cfg(not(feature = "user"))]
pub const PROCESS_NAME: &[u8] = b"Relay1";

/// Max entries for socket fd map
pub const SOCKET_FD_MAP_MAX_ENTRIES: u32 = 256;
