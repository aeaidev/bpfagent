#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_buf},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, error, trace};
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
}

/// Socket hops map - shared between eBPF and userspace
/// Key: (pid << 32) | fd — unambiguous because fd numbers are per-process
/// Value: HopEndpoint (hop index + sender/receiver role)
/// Userspace populates this with one entry per hop endpoint:
/// the sender's connected fd and the receiver's accepted fd.
#[map]
pub static SOCKET_HOPS_MAP: HashMap<u64, HopEndpoint> =
    HashMap::with_max_entries(SOCKET_HOPS_MAP_MAX_ENTRIES, 0);

/// Look up the hop endpoint for a given process and file descriptor.
/// Returns None if this (pid, fd) pair is not part of any tracked hop.
unsafe fn get_endpoint(pid: u32, fd: u32) -> Option<HopEndpoint> {
    let key = ((pid as u64) << 32) | (fd as u64);
    // SAFETY: Reading from BPF HashMap map is safe
    match unsafe { SOCKET_HOPS_MAP.get(&key) } {
        Some(ep) => Some(HopEndpoint {
            hop_index: ep.hop_index,
            is_sender: ep.is_sender,
        }),
        None => None,
    }
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

/// NNG header sizes
const NNG_SPF_SIZE: usize = 9; // NNG SPF (Socket Protocol Framework) header
const NNG_PROTOCOL_SIZE: usize = 4; // Protocol type (REQ/REP)
const NNG_MSG_TYPE_SIZE: usize = 2; // Message type

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
    trace!(&ctx, "sys_enter_sendmsg_handler() - ENTERED");

    // cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendmsg/format
    // Argument 0: fd (int) at offset 16
    // Argument 1: msg (struct user_msghdr __user *) at offset 24
    // Argument 2: flags (int) at offset 32

    // Increment counter to track if tracepoint is being called
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

        // Look up the hop endpoint by (pid, fd). fd numbers are per-process,
        // so the pair is unambiguous even when two processes use the same
        // numeric fd for different sockets.
        let endpoint = match unsafe { get_endpoint(current_pid, fd) } {
            Some(ep) => ep,
            None => return Ok(0), // Not a tracked endpoint, skip
        };
        debug!(
            &ctx,
            "Found endpoint: pid={}, fd={}, hop={}, is_sender={}",
            current_pid,
            fd,
            endpoint.hop_index,
            endpoint.is_sender
        );

        // Read NNG header to get Protocol and Message Type
        let (protocol, msg_type) = match unsafe {
            read_nng_protocol_msg_type_from_msghdr(&ctx, msg_ptr as *const UserMsgHdr)
        } {
            Some((p, t)) => (p, t),
            None => return Ok(0), // Not an NNG packet, skip
        };

        if endpoint.is_sender == 1 {
            // This process is sending TO the listening socket: store timestamp
            unsafe {
                store_timestamp_with_protocol(&ctx, endpoint.hop_index, protocol);
            }
        } else {
            // This process is sending FROM the listening socket (response):
            // look up the timestamp and calculate latency
            let latency =
                unsafe { lookup_timestamp_with_protocol(&ctx, endpoint.hop_index, protocol) };
            if latency > 0 {
                let current_time = unsafe { bpf_ktime_get_ns() };
                unsafe { update_moving_average(&ctx, current_pid, latency, current_time) }
                debug!(
                    &ctx,
                    "Latency for hop={}, protocol=0x{:x}, msg_type=0x{:x}, {} ns",
                    endpoint.hop_index,
                    protocol,
                    msg_type,
                    latency
                );
            }
        }
    }
    Ok(0)
}

/// Read a value from user space memory
unsafe fn bpf_probe_read_user_val<T: Copy>(addr: u64) -> Option<T> {
    let ptr = addr as *const T;
    match aya_ebpf::helpers::bpf_probe_read_user(ptr) {
        Ok(val) => Some(val),
        Err(_) => None,
    }
}

/// Read NNG protocol and message type directly from user_msghdr
/// Returns None if buffer is too small or read fails
unsafe fn read_nng_protocol_msg_type_from_msghdr(
    ctx: &TracePointContext,
    msg_ptr: *const UserMsgHdr,
) -> Option<(u32, u16)> {
    let msg_ptr_addr = msg_ptr as u64;

    // Read msg_iov from user_msghdr (offset 16: msg_name=0, msg_namelen=4, padding=4, msg_iov=16)
    let msg_iov: *const IoVec = match bpf_probe_read_user_val(msg_ptr_addr + 16) {
        Some(val) => val,
        None => return None,
    };

    // Read msg_iovlen from user_msghdr (offset 24)
    let msg_iovlen: usize = match bpf_probe_read_user_val(msg_ptr_addr + 24) {
        Some(val) => val,
        None => return None,
    };

    if msg_iov.is_null() || msg_iovlen == 0 {
        return None;
    }

    // Read the first iovec to get the buffer pointer and size
    let iov: IoVec = match bpf_probe_read_user_val(msg_iov as u64) {
        Some(val) => val,
        None => return None,
    };

    if iov.iov_base.is_null() {
        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - iov.iov_base is null, iov_len: {}",
            iov.iov_len
        );
        return None;
    }

    trace!(
        &ctx,
        "read_nng_protocol_msg_type_from_msghdr() - iov_base addr: {}, iov_len: {}, msg_iovlen: {}",
        iov.iov_base as u64,
        iov.iov_len,
        msg_iovlen
    );

    // Check if first iovec has enough data for the full NNG header
    let header_in_first_iov = iov.iov_len >= NNG_SPF_SIZE + NNG_PROTOCOL_SIZE + NNG_MSG_TYPE_SIZE;

    if !header_in_first_iov {
        // Header is not in first iov, try multi iov approach
        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - full header not in first iov, iov_len: {} (need {})",
            iov.iov_len,
            NNG_SPF_SIZE + NNG_PROTOCOL_SIZE + NNG_MSG_TYPE_SIZE
        );

        // Check if we have multiple iovecs and try to read from second one
        if msg_iovlen < 2 {
            trace!(&ctx, "read_nng_protocol_msg_type_from_msghdr() - only 1 iov, cannot read header from second iov");
            return None;
        }

        // Read second iovec
        let second_iov_addr = (msg_iov as u64).wrapping_add(core::mem::size_of::<IoVec>() as u64);
        let second_iov: IoVec = match bpf_probe_read_user_val(second_iov_addr) {
            Some(val) => val,
            None => {
                trace!(
                    &ctx,
                    "read_nng_protocol_msg_type_from_msghdr() - failed to read second iov"
                );
                return None;
            }
        };

        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - using second iov, iov_len: {}",
            second_iov.iov_len
        );

        // Check if second iovec has the protocol
        if second_iov.iov_len < NNG_PROTOCOL_SIZE {
            trace!(
                &ctx,
                "read_nng_protocol_msg_type_from_msghdr() - second iov too small for protocol: {}",
                second_iov.iov_len
            );
            return None;
        }

        // Read protocol from second iovec (at offset 0)
        let protocol_ptr = second_iov.iov_base as *const u8;
        let mut protocol_buf: [u8; 4] = [0; 4];
        if bpf_probe_read_user_buf(protocol_ptr, &mut protocol_buf).is_err() {
            error!(ctx, "Failed to read protocol from second iov");
            return None;
        }
        let protocol = u32::from_be_bytes(protocol_buf);

        // Check if we have a third iovec for message type
        if msg_iovlen < 3 {
            trace!(
                &ctx,
                "read_nng_protocol_msg_type_from_msghdr() - need third iov for msg_type, only {} iovs",
                msg_iovlen
            );
            return None;
        }

        // Read third iovec
        let third_iov_addr =
            (msg_iov as u64).wrapping_add((core::mem::size_of::<IoVec>() as u64).saturating_mul(2));
        let third_iov: IoVec = match bpf_probe_read_user_val(third_iov_addr) {
            Some(val) => val,
            None => {
                trace!(
                    &ctx,
                    "read_nng_protocol_msg_type_from_msghdr() - failed to read third iov"
                );
                return None;
            }
        };

        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - third iov, iov_len: {}",
            third_iov.iov_len
        );

        // Check if third iovec has message type (at least 2 bytes)
        if third_iov.iov_len < NNG_MSG_TYPE_SIZE {
            trace!(
                &ctx,
                "read_nng_protocol_msg_type_from_msghdr() - third iov too small for msg_type: {}",
                third_iov.iov_len
            );
            return None;
        }

        // Read message type from third iovec (at offset 0)
        let msg_type_ptr = third_iov.iov_base as *const u8;
        let mut msg_type_buf: [u8; 2] = [0; 2];
        if bpf_probe_read_user_buf(msg_type_ptr, &mut msg_type_buf).is_err() {
            error!(ctx, "Failed to read message type from third iov");
            return None;
        }
        let msg_type = u16::from_be_bytes(msg_type_buf);

        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - protocol=0x{:x}, msg_type=0x{:x}",
            protocol,
            msg_type
        );

        Some((protocol, msg_type))
    } else {
        // Header is in first iov, read from offset 9 (after SPF header)
        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - full header in first iov, iov_len: {}",
            iov.iov_len
        );

        // Read protocol (4 bytes at offset 9 in NNG header)
        let protocol_ptr = (iov.iov_base as *const u8).wrapping_add(NNG_SPF_SIZE);
        let mut protocol_buf: [u8; 4] = [0; 4];
        if bpf_probe_read_user_buf(protocol_ptr, &mut protocol_buf).is_err() {
            error!(ctx, "Failed to read protocol");
            return None;
        }
        let protocol = u32::from_be_bytes(protocol_buf);

        // Read message type (2 bytes at offset 13 in NNG header)
        let msg_type_ptr =
            (iov.iov_base as *const u8).wrapping_add(NNG_SPF_SIZE + NNG_PROTOCOL_SIZE);
        let mut msg_type_buf: [u8; 2] = [0; 2];
        if bpf_probe_read_user_buf(msg_type_ptr, &mut msg_type_buf).is_err() {
            error!(ctx, "Failed to read message type");
            return None;
        }
        let msg_type = u16::from_be_bytes(msg_type_buf);

        trace!(
            &ctx,
            "read_nng_protocol_msg_type_from_msghdr() - from first iov: protocol=0x{:x}, msg_type=0x{:x}",
            protocol,
            msg_type
        );

        Some((protocol, msg_type))
    }
}

unsafe fn store_timestamp_with_protocol(_ctx: &TracePointContext, hop_index: u32, protocol: u32) {
    let key = ((hop_index as u64) << 32) | (protocol as u64);
    let timestamp = bpf_ktime_get_ns();

    debug!(
        _ctx,
        "Storing timestamp for hop={}, protocol=0x{:x}, key={}", hop_index, protocol, key
    );
    let _ = TIMESTAMP_MAP.insert(&key, &timestamp, 0);
}

unsafe fn lookup_timestamp_with_protocol(
    ctx: &TracePointContext,
    hop_index: u32,
    protocol: u32,
) -> u64 {
    let key = ((hop_index as u64) << 32) | (protocol as u64);

    debug!(
        &ctx,
        "Looking up timestamp for hop={}, protocol=0x{:x}, key={}", hop_index, protocol, key
    );
    if let Some(stored_time) = TIMESTAMP_MAP.get(&key) {
        let current_time = bpf_ktime_get_ns();
        let latency = current_time - *stored_time;
        let _ = TIMESTAMP_MAP.remove(&key);
        debug!(&ctx, "Found latency={}", latency);
        latency
    } else {
        debug!(
            &ctx,
            "Timestamp not found for hop={}, protocol=0x{:x}", hop_index, protocol
        );
        0
    }
}

/// Update moving average for PID
/// Maintains a sliding window sum and count to calculate average over time
unsafe fn update_moving_average(
    _ctx: &TracePointContext,
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
        // debug!(
        //     ctx,
        //     "Sliding window reset for PID {} at time {}", pid, current_time
        // );
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

    // debug!(
    //     ctx,
    //     "Moving average for PID {}: sum={}, count={}, latency={}", pid, sum, count, latency
    // );
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
