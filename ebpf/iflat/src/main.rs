#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, xdp},
    maps::{HashMap, LruHashMap},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::{debug, trace};
use iflat_common::KEY_SIZE;

/// RX timestamps of datagrams seen on the ingress interface (XDP hook).
/// Key: payload tag (first KEY_SIZE bytes of the UDP payload, big-endian).
/// Value: receive timestamp in ns. Entries are consumed by the matching TX
/// sighting; the map is LRU so unmatched traffic cannot fill it.
#[map]
pub static TIMESTAMP_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(1024, 0);

/// Cumulative sum of matched forwarding latencies (ns) for the periodic
/// moving average; single accumulator at ACCUM_KEY, consumed by userspace.
#[map]
pub static LATENCY_SUM: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Cumulative count of matched latency samples; single entry at ACCUM_KEY.
#[map]
pub static LATENCY_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Single key of the LATENCY_SUM/LATENCY_COUNT accumulators.
const ACCUM_KEY: u32 = 0;

/// Ethernet header length (no VLAN tags are parsed).
const ETH_HLEN: usize = 14;
/// EtherType for IPv4.
const ETH_P_IP: u16 = 0x0800;
/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// IP protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IP protocol number for ICMP.
const IPPROTO_ICMP: u8 = 1;
/// UDP header length.
const UDP_HLEN: usize = 8;
/// ICMP echo request/reply header length (the only ICMP messages with a
/// payload worth tagging).
const ICMP_HLEN: usize = 8;
/// ICMP echo reply / echo request type numbers.
const ICMP_ECHOREPLY: u8 = 0;
const ICMP_ECHO: u8 = 8;

/// TC return code: let the packet continue unaffected (observe-only).
const TC_ACT_OK: i32 = 0;

#[xdp]
pub fn iflat_xdp_rx(ctx: XdpContext) -> u32 {
    match xdp_rx_handler(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

#[classifier]
pub fn iflat_tc_tx(ctx: TcContext) -> i32 {
    match tc_tx_handler(&ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// RX side (XDP on the ingress interface, e.g. eno1): the frame still carries
/// its Ethernet header. Parse IPv4 + UDP/TCP/ICMP-echo and store the receipt
/// timestamp keyed on the payload tag. Runs before routing and netfilter,
/// i.e. pre-NAT.
fn xdp_rx_handler(ctx: &XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let end = ctx.data_end();

    let Some(eth_proto) = read_be_u16(data, end, 12) else {
        return Ok(xdp_action::XDP_PASS);
    };
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let Some(tag) = parse_payload_tag(data, end, ETH_HLEN) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let timestamp = unsafe { bpf_ktime_get_ns() };
    let _ = TIMESTAMP_MAP.insert(&tag, &timestamp, 0);
    trace!(
        ctx,
        "IFLAT RX: stored timestamp for tag=0x{:x}, ts={}",
        tag,
        timestamp
    );
    Ok(xdp_action::XDP_PASS)
}

/// TX side (TC clsact egress on the egress interface, e.g. tun0): a tun
/// device has no L2 header, so the packet starts at the IP header. Runs after
/// routing and netfilter POSTROUTING, i.e. post-NAT — masquerading rewrote
/// addresses and ports but not the payload, so the tag still matches. TSO
/// super-packets (if the NIC segments later) still carry the tag at the same
/// payload offset, so they match once.
fn tc_tx_handler(ctx: &TcContext) -> Result<i32, i32> {
    let data = ctx.data();
    let end = ctx.data_end();

    let Some(tag) = parse_payload_tag(data, end, 0) else {
        return Ok(TC_ACT_OK);
    };

    let Some(rx_timestamp) = (unsafe { TIMESTAMP_MAP.get(&tag).copied() }) else {
        return Ok(TC_ACT_OK); // Not a forwarded datagram we timestamped, skip
    };
    let _ = TIMESTAMP_MAP.remove(&tag);

    let latency = unsafe { bpf_ktime_get_ns() }.saturating_sub(rx_timestamp);
    accumulate_latency(latency);
    debug!(
        ctx,
        "IFLAT TX: matched tag=0x{:x}, latency={} ns", tag, latency
    );
    Ok(TC_ACT_OK)
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

/// Extract the payload tag of a UDP, TCP or ICMP-echo datagram whose IPv4
/// header starts `l3` bytes from `data`: the first KEY_SIZE payload bytes,
/// big-endian. Returns None for non-IPv4, other protocols, non-echo ICMP, or
/// truncated packets, and for TCP segments with less than KEY_SIZE payload
/// bytes (e.g. pure ACKs).
///
/// All bounds checks use aggregate `data + N > data_end` comparisons: the
/// verifier refines packet-pointer ranges from this (JGT) comparison shape,
/// while the `data >= data_end` fold LLVM emits for a `+1` check is not
/// refined (seen on sched_cls: "R1 min value is outside of the allowed
/// memory range").
fn parse_payload_tag(data: usize, end: usize, l3: usize) -> Option<u32> {
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

    // L4 header length: fixed for UDP and ICMP echo, taken from the
    // data-offset field for TCP. The L4 header itself is not inspected
    // beyond the TCP data offset and the ICMP type.
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
        IPPROTO_ICMP => {
            if data + l4 + ICMP_HLEN > end {
                return None;
            }
            // Only echo request/reply carry a taggable payload. NAT rewrites
            // the echo identifier (conntrack treats it like a port), so the
            // tag must come from the payload, never from id/seq.
            let icmp_type = unsafe { *((data + l4) as *const u8) };
            if icmp_type != ICMP_ECHO && icmp_type != ICMP_ECHOREPLY {
                return None;
            }
            ICMP_HLEN
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

/// Add one matched latency to the cumulative (sum, count) accumulators that
/// userspace turns into a periodic moving average.
fn accumulate_latency(latency: u64) {
    let sum = unsafe { LATENCY_SUM.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let count = unsafe { LATENCY_COUNT.get(&ACCUM_KEY).copied().unwrap_or(0) };
    let _ = LATENCY_SUM.insert(&ACCUM_KEY, &(sum + latency), 0);
    let _ = LATENCY_COUNT.insert(&ACCUM_KEY, &(count + 1), 0);
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
