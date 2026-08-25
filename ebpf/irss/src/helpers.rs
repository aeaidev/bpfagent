//! Helpers for the IRSS eBPF program: user-space memory reads and payload
//! tag extraction.

use aya_ebpf::helpers::bpf_probe_read_user;
use irss_common::{AF_INET, KEY_SIZE};

use crate::structures::{IoVec, SockaddrIn, UserMsgHdr};

/// Read a value from user-space memory.
pub unsafe fn read_user<T: Copy>(addr: u64) -> Option<T> {
    bpf_probe_read_user(addr as *const T).ok()
}

/// Read a big-endian u32 from user-space memory.
pub unsafe fn read_be_u32(addr: u64) -> Option<u32> {
    read_user::<u32>(addr).map(u32::from_be)
}

/// Read the iovec at `index` from a user-space iovec array.
pub unsafe fn read_iov_at(iov_array: *const IoVec, index: u64) -> Option<IoVec> {
    let addr = (iov_array as u64).wrapping_add(index * (core::mem::size_of::<IoVec>() as u64));
    read_user(addr)
}

/// Read the destination IPv4 address of a sendmsg() user_msghdr: the
/// sockaddr_in passed as msg_name. Returns None when there is no address
/// (connected socket), it is not AF_INET, or it is unreadable.
pub unsafe fn read_tx_dest(msg_ptr: *const UserMsgHdr) -> Option<u32> {
    let msghdr: UserMsgHdr = read_user(msg_ptr as u64)?;
    if msghdr.msg_name.is_null() || msghdr.msg_namelen < size_of::<SockaddrIn>() as u32 {
        return None;
    }
    let addr: SockaddrIn = read_user(msghdr.msg_name as u64)?;
    if addr.sin_family != AF_INET {
        return None;
    }
    Some(addr.sin_addr)
}

/// Read the message tag from a recvmsg/sendmsg() user_msghdr: the first
/// KEY_SIZE bytes of the payload as a big-endian u32. Returns None when the
/// msghdr or its first iovec is unreadable, or when the first iovec is
/// shorter than the tag.
pub unsafe fn read_payload_key(msg_ptr: *const UserMsgHdr) -> Option<u32> {
    let msghdr: UserMsgHdr = read_user(msg_ptr as u64)?;
    if msghdr.msg_iov.is_null() || msghdr.msg_iovlen == 0 {
        return None;
    }

    let first_iov = read_iov_at(msghdr.msg_iov, 0)?;
    if first_iov.iov_base.is_null() || first_iov.iov_len < KEY_SIZE {
        return None;
    }

    read_be_u32(first_iov.iov_base as u64)
}
