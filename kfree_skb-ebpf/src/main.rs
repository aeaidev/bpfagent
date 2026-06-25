#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, info};
use kfree_skb_common::SkbDropReason;

// The kfree_skb tracepoint format (from /sys/kernel/tracing/events/skb/kfree_skb/format):
// field:unsigned short protocol;  offset:32; size:2; signed:0;
// field:enum skb_drop_reason reason; offset:36; size:4; signed:0;

// Map to count drops by reason - using interior mutability
#[map]
pub static DROP_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(131, 0);

#[tracepoint]
pub fn kfree_skb(ctx: TracePointContext) -> u32 {
    match unsafe { try_kfree_skb(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kfree_skb(ctx: TracePointContext) -> Result<u32, u32> {
    // Read the reason field at offset 36 using bpf_probe_read_kernel
    // The tracepoint format has reason at offset 36
    let reason_ptr = unsafe { ctx.as_ptr().add(36) } as *const u32;

    // Use bpf_probe_read_kernel to safely read the value
    let reason_raw: u32 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(reason_ptr).map_err(|e| e as u32)? };

    // Convert to our SkbDropReason enum
    let reason: SkbDropReason = reason_raw.into();

    debug!(
        &ctx,
        "kfree_skb called with reason: {} ({})",
        reason_raw,
        reason_name(reason)
    );

    // Increment the counter for this reason
    // The HashMap uses interior mutability, so we don't need mutable reference
    match unsafe { DROP_COUNTS.get(&reason_raw) } {
        Some(count) => {
            // Counter exists, increment it
            let new_count = count.wrapping_add(1);
            DROP_COUNTS
                .insert(&reason_raw, &new_count, 0)
                .map_err(|e| e as u32)?;
        }
        None => {
            // Counter doesn't exist, create it
            DROP_COUNTS
                .insert(&reason_raw, &1u64, 0)
                .map_err(|e| e as u32)?;
        }
    }

    Ok(0)
}

/// Reason name lookup - matches the user-space version
fn reason_name(reason: SkbDropReason) -> &'static str {
    match reason {
        SkbDropReason::NotSpecified => "NOT_SPECIFIED",
        SkbDropReason::Consumed => "CONSUMED",
        SkbDropReason::NotSpecifiedReason => "NOT_SPECIFIED",
        SkbDropReason::NoSocket => "NO_SOCKET",
        SkbDropReason::SocketClose => "SOCKET_CLOSE",
        SkbDropReason::SocketFilter => "SOCKET_FILTER",
        SkbDropReason::SocketRcvbuff => "SOCKET_RCVBUFF",
        SkbDropReason::UnixDisconnect => "UNIX_DISCONNECT",
        SkbDropReason::UnixSkipOob => "UNIX_SKIP_OOB",
        SkbDropReason::PktTooSmall => "PKT_TOO_SMALL",
        SkbDropReason::TcpCsum => "TCP_CSUM",
        SkbDropReason::UdpCsum => "UDP_CSUM",
        SkbDropReason::NetfilterDrop => "NETFILTER_DROP",
        SkbDropReason::OtherHost => "OTHERHOST",
        SkbDropReason::IpCsum => "IP_CSUM",
        SkbDropReason::IpInhdr => "IP_INHDR",
        SkbDropReason::IpRpfilter => "IP_RPFILTER",
        SkbDropReason::UnicastInL2Multicast => "UNICAST_IN_L2_MULTICAST",
        SkbDropReason::XfrmPolicy => "XFRM_POLICY",
        SkbDropReason::IpNoProto => "IP_NOPROTO",
        SkbDropReason::ProtoMem => "PROTO_MEM",
        SkbDropReason::TcpAuthHdr => "TCP_AUTH_HDR",
        SkbDropReason::TcpMd5NotFound => "TCP_MD5NOTFOUND",
        SkbDropReason::TcpMd5Unexpected => "TCP_MD5UNEXPECTED",
        SkbDropReason::TcpMd5Failure => "TCP_MD5FAILURE",
        SkbDropReason::TcpAoNotFound => "TCP_AONOTFOUND",
        SkbDropReason::TcpAoUnexpected => "TCP_AOUNEXPECTED",
        SkbDropReason::TcpAoKeyNotFound => "TCP_AOKEYNOTFOUND",
        SkbDropReason::TcpAoFailure => "TCP_AOFAILURE",
        SkbDropReason::SocketBacklog => "SOCKET_BACKLOG",
        SkbDropReason::TcpFlags => "TCP_FLAGS",
        SkbDropReason::TcpAbortOnData => "TCP_ABORT_ON_DATA",
        SkbDropReason::TcpZeroWindow => "TCP_ZEROWINDOW",
        SkbDropReason::TcpOldData => "TCP_OLD_DATA",
        SkbDropReason::TcpOverWindow => "TCP_OVERWINDOW",
        SkbDropReason::TcpOfoMerge => "TCP_OFOMERGE",
        SkbDropReason::TcpRfc7323Paws => "TCP_RFC7323_PAWS",
        SkbDropReason::TcpRfc7323PawsAck => "TCP_RFC7323_PAWS_ACK",
        SkbDropReason::TcpRfc7323TwPaws => "TCP_RFC7323_TW_PAWS",
        SkbDropReason::TcpRfc7323Tsecr => "TCP_RFC7323_TSECR",
        SkbDropReason::TcpListenOverflow => "TCP_LISTEN_OVERFLOW",
        SkbDropReason::TcpOldSequence => "TCP_OLD_SEQUENCE",
        SkbDropReason::TcpInvalidSequence => "TCP_INVALID_SEQUENCE",
        SkbDropReason::TcpInvalidEndSequence => "TCP_INVALID_END_SEQUENCE",
        SkbDropReason::TcpInvalidAckSequence => "TCP_INVALID_ACK_SEQUENCE",
        SkbDropReason::TcpReset => "TCP_RESET",
        SkbDropReason::TcpInvalidSyn => "TCP_INVALID_SYN",
        SkbDropReason::TcpClose => "TCP_CLOSE",
        SkbDropReason::TcpFastOpen => "TCP_FASTOPEN",
        SkbDropReason::TcpOldAck => "TCP_OLD_ACK",
        SkbDropReason::TcpTooOldAck => "TCP_TOO_OLD_ACK",
        SkbDropReason::TcpAckUnsentData => "TCP_ACK_UNSENT_DATA",
        SkbDropReason::TcpOfoQueuePrune => "TCP_OFO_QUEUE_PRUNE",
        SkbDropReason::TcpOfoDrop => "TCP_OFO_DROP",
        SkbDropReason::IpOutNoRoutes => "IP_OUTNOROUTES",
        SkbDropReason::BpfCgroupEgress => "BPF_CGROUP_EGRESS",
        SkbDropReason::Ipv6Disabled => "IPV6DISABLED",
        SkbDropReason::NeighCreateFail => "NEIGH_CREATEFAIL",
        SkbDropReason::NeighFailed => "NEIGH_FAILED",
        SkbDropReason::NeighQueueFull => "NEIGH_QUEUEFULL",
        SkbDropReason::NeighDead => "NEIGH_DEAD",
        SkbDropReason::NeighHhFillFail => "NEIGH_HH_FILLFAIL",
        SkbDropReason::TcEgress => "TC_EGRESS",
        SkbDropReason::SecurityHook => "SECURITY_HOOK",
        SkbDropReason::QdiscDrop => "QDISC_DROP",
        SkbDropReason::QdiscBurstDrop => "QDISC_BURST_DROP",
        SkbDropReason::QdiscOverlimit => "QDISC_OVERLIMIT",
        SkbDropReason::QdiscCongested => "QDISC_CONGESTED",
        SkbDropReason::CakeFlood => "CAKE_FLOOD",
        SkbDropReason::FqBandLimit => "FQ_BAND_LIMIT",
        SkbDropReason::FqHorizonLimit => "FQ_HORIZON_LIMIT",
        SkbDropReason::FqFlowLimit => "FQ_FLOW_LIMIT",
        SkbDropReason::CpuBacklog => "CPU_BACKLOG",
        SkbDropReason::Xdp => "XDP",
        SkbDropReason::TcIngress => "TC_INGRESS",
        SkbDropReason::UnhandledProto => "UNHANDLED_PROTO",
        SkbDropReason::SkbCsum => "SKB_CSUM",
        SkbDropReason::SkbGsoSeg => "SKB_GSO_SEG",
        SkbDropReason::SkbBadGso => "SKB_BAD_GSO",
        SkbDropReason::SkbUcopyFault => "SKB_UCOPY_FAULT",
        SkbDropReason::DevHdr => "DEV_HDR",
        SkbDropReason::DevReady => "DEV_READY",
        SkbDropReason::FullRing => "FULL_RING",
        SkbDropReason::NoMem => "NOMEM",
        SkbDropReason::HdrTrunc => "HDR_TRUNC",
        SkbDropReason::TapFilter => "TAP_FILTER",
        SkbDropReason::TapTxFilter => "TAP_TXFILTER",
        SkbDropReason::IcmpCsum => "ICMP_CSUM",
        SkbDropReason::InvalidProto => "INVALID_PROTO",
        SkbDropReason::IpInaddrErrors => "IP_INADDRERRORS",
        SkbDropReason::IpInNoRoutes => "IP_INNOROUTES",
        SkbDropReason::IpLocalSource => "IP_LOCAL_SOURCE",
        SkbDropReason::IpInvalidSource => "IP_INVALID_SOURCE",
        SkbDropReason::IpLocalnet => "IP_LOCALNET",
        SkbDropReason::IpInvalidDest => "IP_INVALID_DEST",
        SkbDropReason::PktTooBig => "PKT_TOO_BIG",
        SkbDropReason::DupFrag => "DUP_FRAG",
        SkbDropReason::FragReasmTimeout => "FRAG_REASM_TIMEOUT",
        SkbDropReason::FragTooFar => "FRAG_TOO_FAR",
        SkbDropReason::TcpMinTtl => "TCP_MINTTL",
        SkbDropReason::Ipv6BadExthdr => "IPV6_BAD_EXTHDR",
        SkbDropReason::Ipv6NdiscFrag => "IPV6_NDISC_FRAG",
        SkbDropReason::Ipv6NdiscHopLimit => "IPV6_NDISC_HOP_LIMIT",
        SkbDropReason::Ipv6NdiscBadCode => "IPV6_NDISC_BAD_CODE",
        SkbDropReason::Ipv6NdiscBadOptions => "IPV6_NDISC_BAD_OPTIONS",
        SkbDropReason::Ipv6NdiscNsOtherhost => "IPV6_NDISC_NS_OTHERHOST",
        SkbDropReason::QueuePurge => "QUEUE_PURGE",
        SkbDropReason::TcCookieError => "TC_COOKIE_ERROR",
        SkbDropReason::PacketSocketError => "PACKET_SOCK_ERROR",
        SkbDropReason::TcChainNotFound => "TC_CHAIN_NOTFOUND",
        SkbDropReason::TcReclassifyLoop => "TC_RECLASSIFY_LOOP",
        SkbDropReason::VxlanInvalidHdr => "VXLAN_INVALID_HDR",
        SkbDropReason::VxlanVniNotFound => "VXLAN_VNI_NOT_FOUND",
        SkbDropReason::MacInvalidSource => "MAC_INVALID_SOURCE",
        SkbDropReason::VxlanEntryExists => "VXLAN_ENTRY_EXISTS",
        SkbDropReason::NoTxTarget => "NO_TX_TARGET",
        SkbDropReason::IpTunnelEcn => "IP_TUNNEL_ECN",
        SkbDropReason::TunnelTxinfo => "TUNNEL_TXINFO",
        SkbDropReason::LocalMac => "LOCAL_MAC",
        SkbDropReason::ArpPvlanDisable => "ARP_PVLAN_DISABLE",
        SkbDropReason::MacIeeeMacControl => "MAC_IEEE_MAC_CONTROL",
        SkbDropReason::BridgeIngressStpState => "BRIDGE_INGRESS_STP_STATE",
        SkbDropReason::CanRxInvalidFrame => "CAN_RX_INVALID_FRAME",
        SkbDropReason::CanfdRxInvalidFrame => "CANFD_RX_INVALID_FRAME",
        SkbDropReason::CanxlRxInvalidFrame => "CANXL_RX_INVALID_FRAME",
        SkbDropReason::PmemAlloc => "PFMEMALLOC",
        SkbDropReason::DualPi2StepDrop => "DUALPI2_STEP_DROP",
        SkbDropReason::PspInput => "PSP_INPUT",
        SkbDropReason::PspOutput => "PSP_OUTPUT",
        SkbDropReason::RecursionLimit => "RECURSION_LIMIT",
        SkbDropReason::Max => "MAX",
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
