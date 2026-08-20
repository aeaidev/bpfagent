#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, trace};
use sca_common::SOCKET_HOPS_MAP_MAX_ENTRIES;

mod helpers;
mod structures;

use helpers::{buf_to_log_str, pair_key, read_nng_header};
use structures::{HopEndpoint, SendEvent, SysEnterSendmsgArgs, UserMsgHdr};

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
    SOCKET_HOPS_MAP.get(&pair_key(pid, fd))
}

/// Timestamp map for latency calculation based on NNG Protocol field:
/// Key: (hop_index << 32) | Protocol
/// - When the hop's sending process sends TO the socket: store timestamp
/// - When the hop's receiving process sends FROM the socket: look up timestamp
#[map]
pub static TIMESTAMP_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Completed raw (accumulated) latency per (hop, protocol) message:
/// Key: (hop_index << 32) | Protocol
/// A receiver's REP only goes out after the downstream hop has completed
/// (lockstep REQ/REP chain), so when hop i completes, hop i+1's latency for
/// the same message is already published here. Hop i subtracts it to get its
/// individual latency contribution and publishes its own raw latency for
/// hop i-1. Entries are consumed by the upstream hop; hop 0 has no upstream
/// and is never stored, so the map cannot fill up with stale entries.
#[map]
pub static LATENCY_HOP_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

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

// Send syscalls - we only trace send operations for latency calculation
#[tracepoint]
pub fn sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    match sys_enter_sendmsg_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// Tracepoint handler for sys_enter_sendmsg
/// Measures per-hop latency using the NNG Protocol field, with socket filtering
/// based on (pid, fd) endpoint lookup: a send by the hop's sender stores a
/// timestamp (REQ), a send by the hop's receiver computes the latency (REP).
fn sys_enter_sendmsg_handler(ctx: TracePointContext) -> Result<u32, u32> {
    let Some(args) = (unsafe { ctx.read_at::<SysEnterSendmsgArgs>(0).ok() }) else {
        return Ok(0);
    };
    let fd = args.fd as u32;
    let msg_ptr = args.msg;

    // PID is in the upper 32 bits of pid_tgid
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // fd numbers are per-process, so (pid, fd) is unambiguous even when two
    // processes use the same numeric fd for different sockets.
    let Some(endpoint) = (unsafe { get_endpoint(pid, fd) }) else {
        return Ok(0); // Not a tracked endpoint, skip
    };

    // Read the NNG header to get the protocol and message type
    let Some((protocol, msg_type)) = (unsafe { read_nng_header(msg_ptr as *const UserMsgHdr) })
    else {
        return Ok(0); // Not an NNG packet, skip
    };

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut name_buf = [0u8; 16];
    let mut path_buf = [0u8; 32];
    let event = SendEvent {
        endpoint,
        pid,
        fd,
        proc_name: buf_to_log_str(&comm, &mut name_buf),
        sock_path: buf_to_log_str(&endpoint.path, &mut path_buf),
        protocol,
        msg_type,
    };

    if endpoint.is_sender == 1 {
        handle_request(&ctx, &event);
    } else {
        handle_response(&ctx, &event);
    }
    Ok(0)
}

/// REQ arm: the hop's sender sent TO the socket — store the send timestamp
/// for the (hop, protocol) pair.
fn handle_request(ctx: &TracePointContext, ev: &SendEvent) {
    debug!(
        ctx,
        "REQ: {} (pid {}) sent request to {} (fd {}): protocol=0x{:x}, msg_type=0x{:x}",
        ev.proc_name,
        ev.pid,
        ev.sock_path,
        ev.fd,
        ev.protocol,
        ev.msg_type
    );
    unsafe {
        store_timestamp_with_protocol(ctx, ev.endpoint.hop_index, ev.protocol);
    }
}

/// REP arm: the hop's receiver sent FROM the socket — compute the latency
/// since the matching REQ. The raw value accumulates all downstream hops
/// (the REP goes out only after the downstream REP arrived), so subtract the
/// downstream hop's latency to report this hop's individual contribution.
fn handle_response(ctx: &TracePointContext, ev: &SendEvent) {
    let hop = ev.endpoint.hop_index;
    let latency = unsafe { lookup_timestamp_with_protocol(ctx, hop, ev.protocol) };
    if latency == 0 {
        return;
    }
    let individual = unsafe { subtract_downstream_latency(hop, ev.protocol, latency) };
    let current_time = unsafe { bpf_ktime_get_ns() };
    unsafe { update_moving_average(ctx, ev.pid, individual, current_time) };
    debug!(
        ctx,
        "REP: {} (pid {}) send reply from {} (fd {}): matched protocol=0x{:x}, msg_type=0x{:x}, latency={} ns",
        ev.proc_name, ev.pid, ev.sock_path, ev.fd, ev.protocol, ev.msg_type, individual
    );
}

/// Store the send timestamp for a (hop, protocol) pair.
unsafe fn store_timestamp_with_protocol(ctx: &TracePointContext, hop_index: u32, protocol: u32) {
    let key = pair_key(hop_index, protocol);
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
    let key = pair_key(hop_index, protocol);
    trace!(
        &ctx,
        "Looking up timestamp for hop={}, protocol=0x{:x}",
        hop_index,
        protocol
    );

    let Some(stored_time) = TIMESTAMP_MAP.get(&key) else {
        trace!(
            &ctx,
            "Timestamp not found for hop={}, protocol=0x{:x}",
            hop_index,
            protocol
        );
        return 0;
    };
    let latency = bpf_ktime_get_ns() - *stored_time;
    let _ = TIMESTAMP_MAP.remove(&key);
    trace!(&ctx, "Found latency={}", latency);
    latency
}

/// Turn an accumulated hop latency into this hop's individual contribution.
///
/// Hops are indexed in data-flow order, so the downstream of hop `hop_index`
/// is `hop_index + 1`, and the lockstep REQ/REP cascade guarantees the
/// downstream hop's latency for the same message (same NNG protocol id) has
/// already been published in LATENCY_HOP_MAP when this hop completes. The
/// raw latency is published for the upstream hop first; hop 0 has no
/// upstream, so it is not stored (its protocol-keyed entries would never be
/// consumed). Falls back to the raw latency when there is no downstream hop
/// (terminal hop) or no matching downstream sample (first message of a
/// cycle, evicted entry).
unsafe fn subtract_downstream_latency(hop_index: u32, protocol: u32, latency: u64) -> u64 {
    let key = pair_key(hop_index, protocol);
    if hop_index > 0 {
        let _ = LATENCY_HOP_MAP.insert(&key, &latency, 0);
    }
    let next = hop_index + 1;
    if next < sca_common::DATA_FLOW.len() as u32 {
        let next_key = pair_key(next, protocol);
        if let Some(downstream) = LATENCY_HOP_MAP.get(&next_key) {
            let individual = latency.saturating_sub(*downstream);
            let _ = LATENCY_HOP_MAP.remove(&next_key);
            return individual;
        }
    }
    latency
}

/// Update moving average for PID
/// Maintains a sliding window sum and count to calculate average over time
unsafe fn update_moving_average(
    ctx: &TracePointContext,
    pid: u32,
    latency: u64,
    current_time: u64,
) {
    let mut sum = LATENCY_PID_SUM.get(&pid).copied().unwrap_or(0);
    let mut count = LATENCY_PID_COUNT.get(&pid).copied().unwrap_or(0);
    let window_start = LATENCY_WINDOW_START.get(&pid).copied().unwrap_or(0);

    // Slide the window once it expires; anchor it at the first sample.
    if current_time - window_start > WINDOW_SIZE_NS {
        sum = 0;
        count = 0;
        trace!(
            ctx,
            "Sliding window reset for PID {} at time {}",
            pid,
            current_time
        );
    }
    if count == 0 {
        LATENCY_WINDOW_START.insert(&pid, &current_time, 0).ok();
    }

    sum += latency;
    count += 1;
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
