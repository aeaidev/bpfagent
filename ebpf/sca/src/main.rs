#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, trace};
use sca_common::SOCKET_HOPS_MAP_MAX_ENTRIES;

mod structures;
use structures::{IoVec, UserMsgHdr};

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

/// Socket hops map - shared between eBPF and userspace
/// Key: (pid << 32) | fd — unambiguous because fd numbers are per-process
/// Value: HopEndpoint (hop index + sender/receiver role + socket path)
/// Userspace populates this with one entry per hop endpoint:
/// the sender's connected fd and the receiver's accepted fd.
#[map]
pub static SOCKET_HOPS_MAP: HashMap<u64, HopEndpoint> =
    HashMap::with_max_entries(SOCKET_HOPS_MAP_MAX_ENTRIES, 0);

/// Look up the hop endpoint for a given process and file descriptor.
/// Returns a reference into the map value (valid for the program's lifetime).
unsafe fn get_endpoint(pid: u32, fd: u32) -> Option<&'static HopEndpoint> {
    let key = ((pid as u64) << 32) | (fd as u64);
    // SAFETY: Reading from BPF HashMap map is safe
    unsafe { SOCKET_HOPS_MAP.get(&key) }
}

/// Counter map to track if tracepoint is being called
#[map]
pub static TRACEPOINT_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Timestamp map for latency calculation based on NNG Protocol field:
/// Key: (hop_index << 32) | Protocol
/// - When the hop's sending process sends TO the socket: store timestamp
/// - When the hop's receiving process sends FROM the socket: look up timestamp
#[map]
pub static TIMESTAMP_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Sum of latencies per PID for moving average calculation
#[map]
pub static LATENCY_PID_SUM: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

/// Count of samples per PID for moving average calculation
#[map]
pub static LATENCY_PID_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

/// Timestamp of first sample in current window for each PID
#[map]
pub static LATENCY_WINDOW_START: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

/// Moving average window size: 2 seconds in nanoseconds
const WINDOW_SIZE_NS: u64 = 2_000_000_000;

/// NNG header field sizes
const NNG_SPF_SIZE: usize = 9; // NNG SPF (Socket Protocol Framework) header
const NNG_PROTOCOL_SIZE: usize = 4; // Protocol type (REQ/REP)
const NNG_MSG_TYPE_SIZE: usize = 2; // Message type
/// Total NNG header: SPF | protocol | message type
const NNG_HEADER_SIZE: usize = NNG_SPF_SIZE + NNG_PROTOCOL_SIZE + NNG_MSG_TYPE_SIZE;

/// Tracepoint handler macro
macro_rules! tracepoint_handler {
    ($name:ident, $handler:path) => {
        #[tracepoint]
        pub fn $name(ctx: TracePointContext) -> u32 {
            match $handler(ctx) {
                Ok(ret) | Err(ret) => ret,
            }
        }
    };
}

// Send syscalls - we only trace send operations for latency calculation
tracepoint_handler!(sys_enter_sendmsg, sys_enter_sendmsg_handler);
// tracepoint_handler!(sys_enter_sendto, generic_send);
// tracepoint_handler!(sys_enter_write, generic_send);

/// Tracepoint handler for sys_enter_sendmsg
/// Measures per-hop latency using the NNG Protocol field, with socket filtering
/// based on (pid, fd) endpoint lookup.
///
/// For each tracked socket hop:
/// - When the hop's sending process sends TO the socket: store timestamp with
///   (hop_index << 32) | Protocol as key
/// - When the hop's receiving process sends FROM the socket (response): look up
///   the timestamp with the same key and calculate the latency
fn sys_enter_sendmsg_handler(ctx: TracePointContext) -> Result<u32, u32> {
    // Syscall arguments (see /sys/kernel/tracing/events/syscalls/sys_enter_sendmsg/format):
    // fd at offset 16, msg (struct user_msghdr *) at offset 24, flags at offset 32
    unsafe {
        if let Some(count) = TRACEPOINT_COUNTER.get(&0) {
            TRACEPOINT_COUNTER.insert(&0, &(count + 1), 0).ok();
        } else {
            TRACEPOINT_COUNTER.insert(&0, &1, 0).ok();
        }
    }

    let fd = unsafe { ctx.read_at::<u64>(16).ok() };
    let msg_ptr = unsafe { ctx.read_at::<u64>(24).ok() };

    if let (Some(fd), Some(msg_ptr)) = (fd, msg_ptr) {
        let fd = fd as u32;

        // Get current process ID; PID is in the upper 32 bits
        let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        // Get current process name (comm) for human-readable logging
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        let mut name_buf = [0u8; 16];
        let proc_name = buf_to_log_str(&comm, &mut name_buf);

        // Look up the hop endpoint by (pid, fd). fd numbers are per-process,
        // so the pair is unambiguous even when two processes use the same
        // numeric fd for different sockets.
        let endpoint = match unsafe { get_endpoint(current_pid, fd) } {
            Some(ep) => ep,
            None => return Ok(0), // Not a tracked endpoint, skip
        };
        let mut path_buf = [0u8; 32];
        let sock_path = buf_to_log_str(&endpoint.path, &mut path_buf);

        // Read the NNG header to get the protocol and message type
        let (protocol, msg_type) = match unsafe { read_nng_header(msg_ptr as *const UserMsgHdr) } {
            Some((p, t)) => (p, t),
            None => return Ok(0), // Not an NNG packet, skip
        };

        if endpoint.is_sender == 1 {
            // This process is sending TO the listening socket (REQ): store timestamp
            debug!(
                &ctx,
                "REQ: {} (pid {}) sent request to {} (fd {}): protocol=0x{:x}, msg_type=0x{:x}",
                proc_name,
                current_pid,
                sock_path,
                fd,
                protocol,
                msg_type
            );
            unsafe {
                store_timestamp_with_protocol(&ctx, endpoint.hop_index, protocol);
            }
        } else {
            // This process is sending FROM the listening socket (REP):
            // look up the timestamp and calculate latency
            let latency =
                unsafe { lookup_timestamp_with_protocol(&ctx, endpoint.hop_index, protocol) };
            if latency > 0 {
                let current_time = unsafe { bpf_ktime_get_ns() };
                unsafe { update_moving_average(&ctx, current_pid, latency, current_time) }
                debug!(
                    &ctx,
                    "REP: {} (pid {}) send reply from {} (fd {}): matched protocol=0x{:x}, msg_type=0x{:x}, latency={} ns",
                    proc_name,
                    current_pid,
                    sock_path,
                    fd,
                    protocol,
                    msg_type,
                    latency
                );
            }
        }
    }
    Ok(0)
}

/// Read a value from user-space memory.
unsafe fn read_user<T: Copy>(addr: u64) -> Option<T> {
    bpf_probe_read_user(addr as *const T).ok()
}

/// Read a big-endian u32 from user-space memory.
unsafe fn read_be_u32(addr: u64) -> Option<u32> {
    let mut buf = [0u8; NNG_PROTOCOL_SIZE];
    bpf_probe_read_user_buf(addr as *const u8, &mut buf).ok()?;
    Some(u32::from_be_bytes(buf))
}

/// Read a big-endian u16 from user-space memory.
unsafe fn read_be_u16(addr: u64) -> Option<u16> {
    let mut buf = [0u8; NNG_MSG_TYPE_SIZE];
    bpf_probe_read_user_buf(addr as *const u8, &mut buf).ok()?;
    Some(u16::from_be_bytes(buf))
}

/// Read the iovec at `index` from a user-space iovec array.
unsafe fn read_iov_at(iov_array: *const IoVec, index: u64) -> Option<IoVec> {
    let addr = (iov_array as u64).wrapping_add(index * (core::mem::size_of::<IoVec>() as u64));
    read_user(addr)
}

/// Read the NNG protocol and message type from a sendmsg() user_msghdr.
/// Returns None when the message does not carry a readable NNG header.
unsafe fn read_nng_header(msg_ptr: *const UserMsgHdr) -> Option<(u32, u16)> {
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
unsafe fn read_header_from_single_iov(iov: &IoVec) -> Option<(u32, u16)> {
    let base = iov.iov_base as u64;
    let protocol = read_be_u32(base.wrapping_add(NNG_SPF_SIZE as u64))?;
    let msg_type = read_be_u16(base.wrapping_add((NNG_SPF_SIZE + NNG_PROTOCOL_SIZE) as u64))?;
    Some((protocol, msg_type))
}

/// Read the NNG header when it is split across three iovecs:
/// SPF header in the first, protocol in the second, message type in the third.
unsafe fn read_header_from_split_iovs(
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
fn buf_to_log_str<'a, const N: usize>(buf: &[u8; N], out: &'a mut [u8; N]) -> &'a str {
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

/// Store the send timestamp for a (hop, protocol) pair.
unsafe fn store_timestamp_with_protocol(ctx: &TracePointContext, hop_index: u32, protocol: u32) {
    let key = ((hop_index as u64) << 32) | (protocol as u64);
    let timestamp = bpf_ktime_get_ns();

    trace!(
        ctx,
        "Storing timestamp for hop={}, protocol=0x{:x}",
        hop_index,
        protocol
    );
    let _ = TIMESTAMP_MAP.insert(&key, &timestamp, 0);
}

/// Look up and remove the timestamp for a (hop, protocol) pair.
/// Returns the latency since the stored send, or 0 if there is no match.
unsafe fn lookup_timestamp_with_protocol(
    ctx: &TracePointContext,
    hop_index: u32,
    protocol: u32,
) -> u64 {
    let key = ((hop_index as u64) << 32) | (protocol as u64);

    trace!(
        &ctx,
        "Looking up timestamp for hop={}, protocol=0x{:x}",
        hop_index,
        protocol
    );
    if let Some(stored_time) = TIMESTAMP_MAP.get(&key) {
        let current_time = bpf_ktime_get_ns();
        let latency = current_time - *stored_time;
        let _ = TIMESTAMP_MAP.remove(&key);
        trace!(&ctx, "Found latency={}", latency);
        latency
    } else {
        trace!(
            &ctx,
            "Timestamp not found for hop={}, protocol=0x{:x}",
            hop_index,
            protocol
        );
        0
    }
}

/// Update moving average for PID
/// Maintains a sliding window sum and count to calculate average over time
unsafe fn update_moving_average(
    ctx: &TracePointContext,
    pid: u32,
    latency: u64,
    current_time: u64,
) {
    // Get current sum
    let mut sum = LATENCY_PID_SUM.get(&pid).copied().unwrap_or(0);

    // Get current count
    let mut count = LATENCY_PID_COUNT.get(&pid).copied().unwrap_or(0);

    // Get window start time
    let window_start = LATENCY_WINDOW_START.get(&pid).copied().unwrap_or(0);

    // Check if we need to slide the window (more than WINDOW_SIZE_NS has passed)
    if current_time - window_start > WINDOW_SIZE_NS {
        // Reset the window
        sum = 0;
        count = 0;
        LATENCY_WINDOW_START.insert(&pid, &current_time, 0).ok();
        trace!(
            ctx,
            "Sliding window reset for PID {} at time {}",
            pid,
            current_time
        );
    } else if count == 0 {
        // First sample in window
        LATENCY_WINDOW_START.insert(&pid, &current_time, 0).ok();
    }

    // Add new latency to sum and increment count
    sum += latency;
    count += 1;

    // Update the sum and count
    LATENCY_PID_SUM.insert(&pid, &sum, 0).ok();
    LATENCY_PID_COUNT.insert(&pid, &count, 0).ok();

    trace!(
        ctx,
        "Moving average for PID {}: sum={}, count={}, latency={}",
        pid,
        sum,
        count,
        latency
    );
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
