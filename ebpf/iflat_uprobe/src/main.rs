//! iflat_uprobe eBPF program: measures the two legs of a UDP/TCP datagram's
//! journey from ingress on one interface to a call of a configured userspace
//! function.
//!
//! Leg 1 (RX1 -> RX2): two XDP programs timestamp the datagram on ingress of
//! two interfaces (e.g. eno1 and tun0), keyed by the tag in the first 4
//! payload bytes. The RX2 program matches the tag against TIMESTAMP1_MAP,
//! accumulates the RX1->RX2 latency, and stores its own timestamp in
//! TIMESTAMP2_MAP.
//!
//! Leg 2 (RX2 -> function call): a uprobe on the configured function (e.g.
//! `FpgaPciePhy::submitBurst`) resolves the payload pointer from the
//! configured argument register (UPROBE_CONFIG_MAP) — either directly, or
//! through the payload-pointer member of the struct the argument points to
//! (e.g. `TxSlot &slot` -> `slot->payload`) — rebuilds the tag from the
//! first 4 payload bytes, and matches it against TIMESTAMP2_MAP,
//! accumulating the RX2->function-call latency.
//!
//! Userspace turns the LATENCY1/LATENCY2 (sum, count) accumulators into
//! periodic moving averages.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_probe_read_user},
    macros::{map, uprobe, xdp},
    maps::{HashMap, LruHashMap},
    programs::{ProbeContext, XdpContext},
};
use aya_log_ebpf::{debug, trace};
use iflat_uprobe_common::{
    UprobeConfig, KEY_SIZE, MAX_ARGS, PAYLOAD_PTR_DIRECT, UPROBE_CONFIG_KEY,
};

/// RX1 timestamps of datagrams seen on the first ingress interface (XDP on
/// rx1_iface, e.g. eno1). Key: payload tag (first KEY_SIZE bytes of the
/// UDP/TCP payload, big-endian). Value: receive timestamp in ns. Entries are
/// consumed by the matching RX2 sighting; the map is LRU so unmatched
/// traffic cannot fill it.
#[map]
pub static TIMESTAMP1_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

/// RX2 timestamps of datagrams seen on the second ingress interface (XDP on
/// rx2_iface, e.g. tun0). Same keying as TIMESTAMP1_MAP; entries are consumed
/// by the matching function call.
#[map]
pub static TIMESTAMP2_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

/// Cumulative sum of matched RX1->RX2 latencies (ns) for the periodic moving
/// average; single accumulator at ACCUM_KEY, consumed by userspace.
#[map]
pub static LATENCY1_SUM: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Cumulative count of matched RX1->RX2 latency samples; single entry at
/// ACCUM_KEY.
#[map]
pub static LATENCY1_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Cumulative sum of matched RX2->function-call latencies (ns); single
/// accumulator at ACCUM_KEY, consumed by userspace.
#[map]
pub static LATENCY2_SUM: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Cumulative count of matched RX2->function-call latency samples; single
/// entry at ACCUM_KEY.
#[map]
pub static LATENCY2_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Runtime configuration of the uprobe side (which argument register leads
/// to the payload, whether the payload pointer sits inside the pointed-to
/// struct, byte offset of the tag from the resolved payload pointer),
/// written by userspace at load time; single entry at UPROBE_CONFIG_KEY.
#[map]
pub static UPROBE_CONFIG_MAP: HashMap<u32, UprobeConfig> = HashMap::with_max_entries(1, 0);

/// Single key of the LATENCY*_SUM/LATENCY*_COUNT accumulators.
const ACCUM_KEY: u32 = 0;

/// Ethernet header length (no VLAN tags are parsed).
const ETH_HLEN: usize = 14;
/// EtherType for IPv4.
const ETH_P_IP: u16 = 0x0800;
/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// IP protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// UDP header length.
const UDP_HLEN: usize = 8;

#[xdp]
pub fn iflat_uprobe_xdp_rx1(ctx: XdpContext) -> u32 {
    match xdp_rx1_handler(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[xdp]
pub fn iflat_uprobe_xdp_rx2(ctx: XdpContext) -> u32 {
    match xdp_rx2_handler(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[uprobe]
pub fn iflat_uprobe_fn_call(ctx: ProbeContext) -> u32 {
    match fn_call_handler(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// RX1 side (XDP on the first ingress interface, e.g. eno1): parse IPv4 +
/// UDP/TCP and store the receipt timestamp keyed on the payload tag.
fn xdp_rx1_handler(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let end = ctx.data_end();

    let Some(tag) = parse_payload_tag(data, end) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let timestamp = unsafe { bpf_ktime_get_ns() };
    let _ = TIMESTAMP1_MAP.insert(&tag, &timestamp, 0);
    trace!(
        ctx,
        "IFLAT_UPROBE RX1: stored timestamp for tag=0x{:x}, ts={}",
        tag,
        timestamp
    );
    Ok(xdp_action::XDP_PASS)
}

/// RX2 side (XDP on the second ingress interface, e.g. tun0): match the tag
/// against TIMESTAMP1_MAP; on a match remove the record and accumulate the
/// RX1->RX2 latency. Then store the RX2 timestamp keyed on the tag for the
/// uprobe side (unconditionally: the RX2->function-call leg is measured even
/// for datagrams first seen at RX2, e.g. after a mid-flow agent start).
fn xdp_rx2_handler(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let end = ctx.data_end();

    let Some(tag) = parse_payload_tag(data, end) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(ts1) = unsafe { TIMESTAMP1_MAP.get(&tag).copied() } {
        let _ = TIMESTAMP1_MAP.remove(&tag);
        let latency = now.saturating_sub(ts1);
        accumulate_latency1(latency);
        debug!(
            ctx,
            "IFLAT_UPROBE RX2: matched tag=0x{:x}, latency={} ns", tag, latency
        );
    }
    let _ = TIMESTAMP2_MAP.insert(&tag, &now, 0);
    trace!(
        ctx,
        "IFLAT_UPROBE RX2: stored timestamp for tag=0x{:x}, ts={}",
        tag,
        now
    );
    Ok(xdp_action::XDP_PASS)
}

/// Function-call side (uprobe): resolve the payload pointer from the
/// configured argument register — directly, or through the payload-pointer
/// member of the struct the argument points to (e.g. `TxSlot &slot` ->
/// `slot->payload` at payload_ptr_offset) — rebuild the payload tag and
/// match it against TIMESTAMP2_MAP; on a match remove the record and
/// accumulate the RX2->function-call latency.
fn fn_call_handler(ctx: &ProbeContext) -> Result<u32, u32> {
    let Some(config) = (unsafe { UPROBE_CONFIG_MAP.get(&UPROBE_CONFIG_KEY).copied() }) else {
        return Ok(0); // Not configured, skip
    };
    if config.arg_index < 1 || config.arg_index as usize > MAX_ARGS {
        return Ok(0);
    }
    let base = ctx.arg::<u64>((config.arg_index - 1) as usize).unwrap_or(0);
    if base == 0 {
        return Ok(0);
    }

    // Resolve the payload pointer. Direct mode (PAYLOAD_PTR_DIRECT): the
    // argument points at the payload. Struct mode: the argument points at a
    // struct whose member at payload_ptr_offset is the payload pointer
    // (e.g. TxSlot::payload).
    let payload = if config.payload_ptr_offset == PAYLOAD_PTR_DIRECT {
        base
    } else {
        let member = (base + u64::from(config.payload_ptr_offset)) as *const u64;
        match unsafe { bpf_probe_read_user(member) } {
            Ok(ptr) => ptr,
            Err(_) => return Ok(0), // Struct not readable, skip
        }
    };
    if payload == 0 {
        return Ok(0);
    }

    // Rebuild the tag the XDP side keyed on: the first KEY_SIZE payload
    // bytes, big-endian. Byte-wise reads keep endianness explicit.
    let ptr = (payload + u64::from(config.tag_offset)) as *const u8;
    let mut tag: u32 = 0;
    for i in 0..KEY_SIZE {
        let Ok(byte) = (unsafe { bpf_probe_read_user(ptr.add(i)) }) else {
            return Ok(0); // Payload not readable, skip
        };
        tag = (tag << 8) | u32::from(byte);
    }

    let Some(ts2) = (unsafe { TIMESTAMP2_MAP.get(&tag).copied() }) else {
        return Ok(0); // Not a datagram we timestamped, skip
    };
    let _ = TIMESTAMP2_MAP.remove(&tag);

    let latency = unsafe { bpf_ktime_get_ns() }.saturating_sub(ts2);
    accumulate_latency2(latency);
    debug!(
        ctx,
        "IFLAT_UPROBE FN: matched tag=0x{:x}, latency={} ns", tag, latency
    );
    Ok(0)
}

/// Read one packet byte at `off` bytes from `data`, bounds-checked against
/// `data_end` with the canonical `data + off + 1 > data_end` idiom the
/// verifier tracks. Byte-wise reads keep alignment requirements trivial.
#[inline(always)]
fn read_u8(data: usize, end: usize, off: usize) -> Option<u8> {
    if data + off + 1 > end {
        return None;
    }
    Some(unsafe { *((data + off) as *const u8) })
}

/// Read a big-endian u16 from the packet at `off`.
#[inline(always)]
fn read_be_u16(data: usize, end: usize, off: usize) -> Option<u16> {
    let hi = read_u8(data, end, off)?;
    let lo = read_u8(data, end, off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Extract the payload tag of a UDP or TCP datagram: the first KEY_SIZE
/// payload bytes, big-endian. Returns None for non-IPv4, other protocols, or
/// truncated packets, and for TCP segments with less than KEY_SIZE payload
/// bytes (e.g. pure ACKs).
///
/// The attach points are ingress of arbitrary interfaces: physical NIC frames
/// carry an Ethernet header, TUN frames start at the IP header. An
/// Ethernet+IPv4 frame carries EtherType 0x0800 at offset 12 and the IPv4
/// version nibble at offset 14; on a TUN frame bytes 12-13 are the first two
/// source-address bytes (which can alias 0x0800), so the version nibble
/// decides.
fn parse_payload_tag(data: usize, end: usize) -> Option<u32> {
    if read_be_u16(data, end, 12) == Some(ETH_P_IP)
        && read_u8(data, end, ETH_HLEN).is_some_and(|v| v >> 4 == 4)
    {
        return parse_ipv4_tag(data, end, ETH_HLEN);
    }
    parse_ipv4_tag(data, end, 0)
}

/// Parse the IPv4 header starting `l3` bytes from `data` and return the tag
/// of a UDP/TCP datagram.
///
/// All bounds checks use aggregate `data + N > data_end` comparisons: the
/// verifier refines packet-pointer ranges from this (JGT) comparison shape,
/// while the `data >= data_end` fold LLVM emits for a `+1` check is not
/// refined.
fn parse_ipv4_tag(data: usize, end: usize, l3: usize) -> Option<u32> {
    // One check covers the fixed-size IPv4 header fields read below.
    if data + l3 + 20 > end {
        return None;
    }
    let version_ihl = unsafe { *((data + l3) as *const u8) };
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let protocol = unsafe { *((data + l3 + 9) as *const u8) };

    // L4 header length: fixed for UDP, taken from the data-offset field for
    // TCP. The L4 header itself is not inspected beyond the TCP data offset.
    let l4 = l3 + ihl;
    let l4_hlen = match protocol {
        IPPROTO_UDP => UDP_HLEN,
        IPPROTO_TCP => {
            if data + l4 + 20 > end {
                return None;
            }
            let data_offset = unsafe { *((data + l4 + 12) as *const u8) };
            let hlen = usize::from(data_offset >> 4) * 4;
            if hlen < 20 {
                return None;
            }
            hlen
        }
        _ => return None,
    };

    // One aggregate check covers the whole tag, so the four single-byte
    // reads below are provably inside the packet (a per-byte check inside
    // the loop compiles to pointer min() arithmetic the verifier cannot
    // track).
    let payload_off = l4 + l4_hlen;
    if data + payload_off + KEY_SIZE > end {
        return None;
    }
    let base = data + payload_off;
    let mut tag: u32 = 0;
    for i in 0..KEY_SIZE {
        tag = (tag << 8) | u32::from(unsafe { *((base + i) as *const u8) });
    }
    Some(tag)
}

/// Add one matched RX1->RX2 latency to the cumulative (sum, count)
/// accumulators that userspace turns into a periodic moving average.
fn accumulate_latency1(latency: u64) {
    let sum = unsafe { LATENCY1_SUM.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let count = unsafe { LATENCY1_COUNT.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let _ = LATENCY1_SUM.insert(&ACCUM_KEY, &(sum + latency), 0);
    let _ = LATENCY1_COUNT.insert(&ACCUM_KEY, &(count + 1), 0);
}

/// Add one matched RX2->function-call latency to the cumulative (sum, count)
/// accumulators that userspace turns into a periodic moving average.
fn accumulate_latency2(latency: u64) {
    let sum = unsafe { LATENCY2_SUM.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let count = unsafe { LATENCY2_COUNT.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let _ = LATENCY2_SUM.insert(&ACCUM_KEY, &(sum + latency), 0);
    let _ = LATENCY2_COUNT.insert(&ACCUM_KEY, &(count + 1), 0);
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
