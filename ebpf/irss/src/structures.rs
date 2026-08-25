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

/// Define a mirror of the sockaddr_in struct (IPv4 only)
/// Layout from include/uapi/linux/in.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16, // big-endian
    pub sin_addr: u32, // big-endian
    pub sin_zero: [u8; 8],
}

/// Arguments of the sys_enter_recvmsg and sys_enter_sendmsg tracepoints
/// (identical argument layout), mirroring
/// /sys/kernel/tracing/events/syscalls/sys_enter_{recvmsg,sendmsg}/format:
/// 8 bytes of common tracepoint fields, then __syscall_nr, then the
/// syscall arguments as unsigned longs. That layout is a stable kernel
/// ABI, so reading it as a plain struct is safe.
#[repr(C)]
pub struct SysEnterMsgArgs {
    pub _common: [u8; 8],
    pub _syscall_nr: u32,
    pub _pad: u32,
    pub fd: u64,
    pub msg: u64,
}

/// Arguments of the sys_exit_recvmsg tracepoint, mirroring
/// /sys/kernel/tracing/events/syscalls/sys_exit_recvmsg/format:
/// 8 bytes of common tracepoint fields, then __syscall_nr, then the return
/// value (bytes received, or a negative errno).
#[repr(C)]
pub struct SysExitArgs {
    pub _common: [u8; 8],
    pub _syscall_nr: i32,
    pub _pad: u32,
    pub ret: i64,
}
