//! Helpers for reading and parsing user-space memory: extracting the NNG
//! header of a sendmsg() message, which may be split across several iovecs.

use aya_ebpf::helpers::bpf_probe_read_user;

use crate::structures::{IoVec, UserMsgHdr};

/// NNG header field sizes
const NNG_SPF_SIZE: usize = 9; // NNG SPF (Socket Protocol Framework) header
const NNG_PROTOCOL_SIZE: usize = 4; // Protocol type (REQ/REP)
const NNG_MSG_TYPE_SIZE: usize = 2; // Message type
/// Total NNG header: SPF | protocol | message type
const NNG_HEADER_SIZE: usize = NNG_SPF_SIZE + NNG_PROTOCOL_SIZE + NNG_MSG_TYPE_SIZE;

/// Read a value from user-space memory.
pub unsafe fn read_user<T: Copy>(addr: u64) -> Option<T> {
    bpf_probe_read_user(addr as *const T).ok()
}

/// Read a big-endian u32 from user-space memory.
pub unsafe fn read_be_u32(addr: u64) -> Option<u32> {
    read_user::<u32>(addr).map(u32::from_be)
}

/// Read a big-endian u16 from user-space memory.
pub unsafe fn read_be_u16(addr: u64) -> Option<u16> {
    read_user::<u16>(addr).map(u16::from_be)
}

/// Read the iovec at `index` from a user-space iovec array.
pub unsafe fn read_iov_at(iov_array: *const IoVec, index: u64) -> Option<IoVec> {
    let addr = (iov_array as u64).wrapping_add(index * (core::mem::size_of::<IoVec>() as u64));
    read_user(addr)
}

/// Read the NNG protocol and message type from a sendmsg() user_msghdr.
/// Returns None when the message does not carry a readable NNG header.
pub unsafe fn read_nng_header(msg_ptr: *const UserMsgHdr) -> Option<(u32, u16)> {
    let msghdr: UserMsgHdr = read_user(msg_ptr as u64)?;
    if msghdr.msg_iov.is_null() || msghdr.msg_iovlen == 0 {
        return None;
    }

    let first_iov = read_iov_at(msghdr.msg_iov, 0)?;
    if first_iov.iov_base.is_null() {
        return None;
    }

    if first_iov.iov_len >= NNG_HEADER_SIZE {
        // The whole NNG header sits in the first iovec.
        read_header_from_single_iov(&first_iov)
    } else {
        // The header is split across iovecs: SPF in the first, protocol in
        // the second, message type in the third.
        read_header_from_split_iovs(msghdr.msg_iov, msghdr.msg_iovlen)
    }
}

/// Read the NNG header from a first iovec that contains it entirely.
pub unsafe fn read_header_from_single_iov(iov: &IoVec) -> Option<(u32, u16)> {
    let base = iov.iov_base as u64;
    let protocol = read_be_u32(base.wrapping_add(NNG_SPF_SIZE as u64))?;
    let msg_type = read_be_u16(base.wrapping_add((NNG_SPF_SIZE + NNG_PROTOCOL_SIZE) as u64))?;
    Some((protocol, msg_type))
}

/// Read the NNG header when it is split across three iovecs:
/// SPF header in the first, protocol in the second, message type in the third.
pub unsafe fn read_header_from_split_iovs(
    iov_array: *const IoVec,
    iov_count: usize,
) -> Option<(u32, u16)> {
    if iov_count < 3 {
        return None;
    }
    let second = read_iov_at(iov_array, 1)?;
    if second.iov_base.is_null() || second.iov_len < NNG_PROTOCOL_SIZE {
        return None;
    }
    let third = read_iov_at(iov_array, 2)?;
    if third.iov_base.is_null() || third.iov_len < NNG_MSG_TYPE_SIZE {
        return None;
    }
    let protocol = read_be_u32(second.iov_base as u64)?;
    let msg_type = read_be_u16(third.iov_base as u64)?;
    Some((protocol, msg_type))
}

/// Copy a NUL-padded buffer (kernel comm, socket path) into a fixed-size,
/// space-padded ASCII string suitable for logging. The loops have fixed trip
/// counts, which keeps the generated code straight-line and the BPF verifier
/// state count low (runtime-length string loops blow the 1M-insn budget).
pub fn buf_to_log_str<'a, const N: usize>(buf: &[u8; N], out: &'a mut [u8; N]) -> &'a str {
    let mut i = 0;
    while i < N {
        let b = buf[i];
        out[i] = if b == 0 || !b.is_ascii() { b' ' } else { b };
        i += 1;
    }
    // SAFETY: every byte of `out` was checked above to be printable ASCII,
    // which is always valid UTF-8.
    unsafe { core::str::from_utf8_unchecked(&out[..]) }
}
