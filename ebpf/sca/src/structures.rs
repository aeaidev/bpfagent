use core::ffi;

/// Define a mirror of the userspace msghdr struct
/// Layout from include/uapi/linux/socket.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UserMsgHdr {
    pub msg_name: *const ffi::c_void,
    pub msg_namelen: u32,
    pub msg_iov: *const IoVec, // Pointer to the array of buffers
    pub msg_iovlen: usize,     // Number of elements in msg_iov
    pub msg_control: *const ffi::c_void,
    pub msg_controllen: usize,
    pub msg_flags: ffi::c_int,
}

/// Define a mirror of the iovec struct
/// Layout from include/uapi/linux/uio.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IoVec {
    pub iov_base: *const ffi::c_void, // Pointer to payload chunk
    pub iov_len: usize,               // Length of payload chunk
}

// HopEndpoint struct for eBPF - we use a local definition here since aya::Pod
// is not available in the eBPF context
// This must match the HopEndpoint in common/sca/src/lib.rs
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HopEndpoint {
    /// Index into DATA_FLOW identifying the hop
    pub hop_index: u32,
    /// 1 if this endpoint is the hop's sending process, 0 if it is the receiver
    pub is_sender: u32,
    /// Unix socket path of the hop (NUL-padded, for logging)
    pub path: [u8; 32],
}

/// Arguments of the sys_enter_sendmsg tracepoint, mirroring
/// /sys/kernel/tracing/events/syscalls/sys_enter_sendmsg/format:
/// 8 bytes of common tracepoint fields, then __syscall_nr, then the
/// syscall arguments as unsigned longs. That layout is a stable kernel
/// ABI, so reading it as a plain struct is safe.
#[repr(C)]
pub struct SysEnterSendmsgArgs {
    pub _common: [u8; 8],
    pub _syscall_nr: u32,
    pub _pad: u32,
    pub fd: u64,
    pub msg: u64,
}

/// One sendmsg() on a tracked hop endpoint: the endpoint, the NNG header
/// fields, and log-friendly process/socket names.
pub struct SendEvent<'a> {
    pub endpoint: &'a HopEndpoint,
    pub pid: u32,
    pub fd: u32,
    pub proc_name: &'a str,
    pub sock_path: &'a str,
    pub protocol: u32,
    pub msg_type: u16,
}
