#![no_std]

// Shared types between user and eBPF code

/// Tracepoint definitions: (eBPF program name, category, event).
///
/// RX is an enter/exit pair: at sys_enter the receive buffer is still empty,
/// so only the user_msghdr pointer is stashed; the payload tag is read at
/// sys_exit once the kernel has filled the buffer. The `irss_udp_recvmsg`
/// kprobe (KPROBE_FUNCTION) sits between them and vetoes sockets whose local
/// port does not match the configured listen port. TX needs only sys_enter
/// because the data being sent is already in user memory.
pub const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("irss_sys_enter_recvmsg", "syscalls", "sys_enter_recvmsg"),
    ("irss_sys_exit_recvmsg", "syscalls", "sys_exit_recvmsg"),
    ("irss_sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"),
];

/// Kernel function the IRSS RX port filter kprobes on. Its first argument is
/// the struct sock of the receiving socket, whose local port (skc_num) is
/// what the filter checks.
pub const KPROBE_FUNCTION: &str = "udp_recvmsg";

/// Size of the payload tag used as the TIMESTAMP_MAP key: the first 4 bytes
/// of the UDP payload (RX) and of the raw-IP payload (TX), read big-endian.
pub const KEY_SIZE: usize = 4;

/// UDP port the IRSS component listens on (from CRYPTO), from docs/IRSS.md.
/// The RX filter only timestamps datagrams received on this port. Used as the
/// default when userspace does not configure another port in LISTEN_PORT_MAP.
pub const LISTEN_PORT: u16 = 5020;

/// Single key of the LISTEN_PORT_MAP entry holding the configured listen port.
pub const LISTEN_PORT_KEY: u32 = 0;

/// Destination of the raw-IP datagrams (MAC), from docs/IRSS.md. The TX
/// hook only matches sendmsg() calls addressed here, so unrelated sendmsg
/// traffic on the host cannot consume timestamp records. Used as the default
/// when userspace does not configure another address in RAW_DEST_MAP.
pub const RAW_DEST: [u8; 4] = [10, 10, 10, 253];

/// Single key of the RAW_DEST_MAP entry holding the configured raw-IP
/// destination (network-order address bytes as a native u32).
pub const RAW_DEST_KEY: u32 = 0;

/// AF_INET address family (Linux), checked in the sendmsg() destination.
pub const AF_INET: u16 = 2;
