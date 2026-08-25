#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, tracepoint},
    maps::HashMap,
    programs::{ProbeContext, TracePointContext},
};
use aya_log_ebpf::{debug, trace};
use irss_common::{KEY_SIZE, LISTEN_PORT, LISTEN_PORT_KEY, RAW_DEST, RAW_DEST_KEY};

mod helpers;
mod structures;

use helpers::{read_payload_key, read_tx_dest};
use structures::{SysEnterMsgArgs, SysExitArgs, UserMsgHdr};

/// Scratch map handing the user_msghdr pointer from sys_enter_recvmsg to
/// sys_exit_recvmsg: the receive buffer is only filled by the time the
/// syscall exits, so the payload tag cannot be read at sys_enter. The
/// udp_recvmsg kprobe vetoes entries whose socket local port does not match
/// the configured listen port.
/// Key: pid_tgid. Value: user_msghdr pointer.
#[map]
pub static RECV_MSG_PTR: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// RX timestamps of incoming UDP datagrams (from CRYPTO to port 5020).
/// Key: payload tag (first 4 bytes of the payload, big-endian).
/// Value: receipt timestamp in ns. Entries are consumed by the matching TX.
#[map]
pub static TIMESTAMP_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Cumulative sum of matched forwarding latencies (ns) for the periodic
/// moving average; single accumulator at ACCUM_KEY, consumed by userspace.
#[map]
pub static LATENCY_SUM: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Cumulative count of matched latency samples; single entry at ACCUM_KEY.
#[map]
pub static LATENCY_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Configured raw-IP destination address (MAC) for the TX filter, written
/// by userspace at load time; single entry at RAW_DEST_KEY holding the
/// network-order address bytes as a native u32. Falls back to the compiled-in
/// RAW_DEST default when unset.
#[map]
pub static RAW_DEST_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// Configured UDP listen port for the RX filter, written by userspace at
/// load time; single entry at LISTEN_PORT_KEY. Falls back to the compiled-in
/// LISTEN_PORT default when unset.
#[map]
pub static LISTEN_PORT_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// Single key of the LATENCY_SUM/LATENCY_COUNT accumulators.
const ACCUM_KEY: u32 = 0;

/// Offset of skc_num (the socket's local port, host byte order) in
/// `struct sock`: it is the u16 at offset 14 of the embedded
/// `struct sock_common` (skc_daddr 0-3, skc_rcv_saddr 4-7, skc_hash 8-11,
/// skc_dport 12-13, skc_num 14-15). That layout has been stable for decades.
const SK_NUM_OFFSET: usize = 14;

/// The raw-IP destination the TX filter currently matches on.
fn raw_dest() -> u32 {
    unsafe {
        RAW_DEST_MAP
            .get(&RAW_DEST_KEY)
            .copied()
            .unwrap_or(u32::from_ne_bytes(RAW_DEST))
    }
}

/// The UDP listen port the RX filter currently accepts.
fn listen_port() -> u32 {
    unsafe {
        LISTEN_PORT_MAP
            .get(&LISTEN_PORT_KEY)
            .copied()
            .unwrap_or(LISTEN_PORT as u32)
    }
}

#[tracepoint]
pub fn irss_sys_enter_recvmsg(ctx: TracePointContext) -> u32 {
    match sys_enter_recvmsg_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[kprobe]
pub fn irss_udp_recvmsg(ctx: ProbeContext) -> u32 {
    match udp_recvmsg_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[tracepoint]
pub fn irss_sys_exit_recvmsg(ctx: TracePointContext) -> u32 {
    match sys_exit_recvmsg_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[tracepoint]
pub fn irss_sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    match sys_enter_sendmsg_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// sys_enter_recvmsg: stash the user_msghdr pointer for the exit handler.
/// The udp_recvmsg kprobe may still veto it (see below).
fn sys_enter_recvmsg_handler(ctx: TracePointContext) -> Result<u32, u32> {
    let Some(args) = (unsafe { ctx.read_at::<SysEnterMsgArgs>(0).ok() }) else {
        return Ok(0);
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = RECV_MSG_PTR.insert(&pid_tgid, &args.msg, 0);
    Ok(0)
}

/// udp_recvmsg kprobe: the RX port filter. Runs between sys_enter_recvmsg
/// and sys_exit_recvmsg in the same thread; its first argument is the struct
/// sock of the receiving socket (the kernel-internal msghdr copy in arg 2 is
/// deliberately not used — only user pointers are read elsewhere). When the
/// socket's local port does not match the configured listen port, the staged
/// msghdr pointer is dropped so the exit handler skips the datagram.
fn udp_recvmsg_handler(ctx: ProbeContext) -> Result<u32, u32> {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return Ok(0);
    };

    // Read sk->sk_num (local port, host byte order) and filter on it.
    let port: u16 = unsafe {
        bpf_probe_read_kernel((sk as usize + SK_NUM_OFFSET) as *const u16).map_err(|e| e as u32)?
    };
    if port as u32 != listen_port() {
        trace!(
            &ctx,
            "IRSS RX skip: socket local port={} != configured {}",
            port,
            listen_port()
        );
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = RECV_MSG_PTR.remove(&pid_tgid);
    }
    Ok(0)
}

/// sys_exit_recvmsg: the receive buffer is now filled — read the payload tag
/// of the incoming UDP datagram and store its receipt timestamp.
fn sys_exit_recvmsg_handler(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(msg_ptr) = (unsafe { RECV_MSG_PTR.get(&pid_tgid).copied() }) else {
        return Ok(0); // Not a recvmsg we tracked, skip
    };
    let _ = RECV_MSG_PTR.remove(&pid_tgid);

    let Some(args) = (unsafe { ctx.read_at::<SysExitArgs>(0).ok() }) else {
        return Ok(0);
    };
    if args.ret < KEY_SIZE as i64 {
        return Ok(0); // Failed or too short to carry a tag, skip
    }

    let Some(key) = (unsafe { read_payload_key(msg_ptr as *const UserMsgHdr) }) else {
        return Ok(0); // Unreadable payload, skip
    };

    let timestamp = unsafe { bpf_ktime_get_ns() };
    let _ = TIMESTAMP_MAP.insert(&key, &timestamp, 0);
    trace!(
        &ctx,
        "IRSS RX: stored timestamp for tag=0x{:x}, ts={}",
        key,
        timestamp
    );
    Ok(0)
}

/// sys_enter_sendmsg: the outgoing raw-IP datagram (to 10.10.10.253) — match
/// its payload tag against the stored RX timestamps. On a match, compute the
/// forwarding latency, accumulate it for the periodic moving average, and
/// drop the timestamp record. sendmsg() calls addressed elsewhere are not
/// part of the IRSS data flow and are skipped before any map access.
fn sys_enter_sendmsg_handler(ctx: TracePointContext) -> Result<u32, u32> {
    let Some(args) = (unsafe { ctx.read_at::<SysEnterMsgArgs>(0).ok() }) else {
        return Ok(0);
    };

    let want = raw_dest();
    match unsafe { read_tx_dest(args.msg as *const UserMsgHdr) } {
        Some(dest) if dest == want => {}
        Some(dest) => {
            trace!(
                &ctx,
                "IRSS TX skip: dest=0x{:x} != configured 0x{:x}",
                dest,
                want
            );
            return Ok(0); // Not addressed to the raw-IP target, skip
        }
        None => return Ok(0), // No AF_INET destination, skip
    }

    let Some(key) = (unsafe { read_payload_key(args.msg as *const UserMsgHdr) }) else {
        return Ok(0); // Unreadable payload, skip
    };

    let Some(rx_timestamp) = (unsafe { TIMESTAMP_MAP.get(&key).copied() }) else {
        return Ok(0); // Not a forwarded datagram, skip
    };
    let _ = TIMESTAMP_MAP.remove(&key);

    let latency = unsafe { bpf_ktime_get_ns() }.saturating_sub(rx_timestamp);
    accumulate_latency(latency);
    debug!(
        &ctx,
        "IRSS TX: matched tag=0x{:x}, latency={} ns", key, latency
    );
    Ok(0)
}

/// Add one matched latency to the cumulative (sum, count) accumulators that
/// userspace turns into a periodic moving average.
fn accumulate_latency(latency: u64) {
    let sum = unsafe { LATENCY_SUM.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let count = unsafe { LATENCY_COUNT.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let _ = LATENCY_SUM.insert(&ACCUM_KEY, &(sum + latency), 0);
    let _ = LATENCY_COUNT.insert(&ACCUM_KEY, &(count + 1), 0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
