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
