#![no_std]

// Shared types between user and eBPF code

/// Drop reason enum matching the kernel's `enum skb_drop_reason`.
/// This is a simplified version - in production you might want to include all reasons.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SkbDropReason {
    /// Not dropped yet
    NotSpecified = 0,
    /// Packet has been consumed
    Consumed = 1,
    /// Drop reason is not specified
    NotSpecifiedReason = 2,
    /// No valid socket found
    NoSocket = 3,
    /// Socket is closed
    SocketClose = 4,
    /// Dropped by socket filter
    SocketFilter = 5,
    /// Socket receive buffer is full
    SocketRcvbuff = 6,
    /// Unix socket disconnect
    UnixDisconnect = 7,
    /// Unix socket OOB skipped
    UnixSkipOob = 8,
    /// Packet size too small
    PktTooSmall = 9,
    /// TCP checksum error
    TcpCsum = 10,
    /// UDP checksum error
    UdpCsum = 11,
    /// Dropped by netfilter
    NetfilterDrop = 12,
    /// Packet doesn't belong to current host
    OtherHost = 13,
    /// IP checksum error
    IpCsum = 14,
    /// IP header error
    IpInhdr = 15,
    /// IP reverse path filter failed
    IpRpfilter = 16,
    /// L2 multicast with L3 unicast
    UnicastInL2Multicast = 17,
    /// XFRM policy check failed
    XfrmPolicy = 18,
    /// IP protocol not supported
    IpNoProto = 19,
    /// Protocol memory limitation
    ProtoMem = 20,
    /// TCP auth header error
    TcpAuthHdr = 21,
    /// TCP MD5 hash not found
    TcpMd5NotFound = 22,
    /// TCP MD5 hash unexpected
    TcpMd5Unexpected = 23,
    /// TCP MD5 hash wrong
    TcpMd5Failure = 24,
    /// TCP AO hash not found
    TcpAoNotFound = 25,
    /// TCP AO hash unexpected
    TcpAoUnexpected = 26,
    /// TCP AO key not found
    TcpAoKeyNotFound = 27,
    /// TCP AO failure
    TcpAoFailure = 28,
    /// Socket backlog failed
    SocketBacklog = 29,
    /// TCP flags invalid
    TcpFlags = 30,
    /// TCP abort on data
    TcpAbortOnData = 31,
    /// TCP zero window
    TcpZeroWindow = 32,
    /// TCP old data
    TcpOldData = 33,
    /// TCP over window
    TcpOverWindow = 34,
    /// TCP OFO merge
    TcpOfoMerge = 35,
    /// TCP PAWS
    TcpRfc7323Paws = 36,
    /// TCP PAWS ACK
    TcpRfc7323PawsAck = 37,
    /// TCP TW PAWS
    TcpRfc7323TwPaws = 38,
    /// TCP TS ECR
    TcpRfc7323Tsecr = 39,
    /// TCP listen overflow
    TcpListenOverflow = 40,
    /// TCP old sequence
    TcpOldSequence = 41,
    /// TCP invalid sequence
    TcpInvalidSequence = 42,
    /// TCP invalid end sequence
    TcpInvalidEndSequence = 43,
    /// TCP invalid ACK sequence
    TcpInvalidAckSequence = 44,
    /// TCP reset
    TcpReset = 45,
    /// TCP invalid SYN
    TcpInvalidSyn = 46,
    /// TCP close
    TcpClose = 47,
    /// TCP fast open
    TcpFastOpen = 48,
    /// TCP old ACK
    TcpOldAck = 49,
    /// TCP too old ACK
    TcpTooOldAck = 50,
    /// TCP ACK unsent data
    TcpAckUnsentData = 51,
    /// TCP OFO queue prune
    TcpOfoQueuePrune = 52,
    /// TCP OFO drop
    TcpOfoDrop = 53,
    /// IP no routes
    IpOutNoRoutes = 54,
    /// BPF cgroup egress
    BpfCgroupEgress = 55,
    /// IPv6 disabled
    Ipv6Disabled = 56,
    /// Neighbor create failed
    NeighCreateFail = 57,
    /// Neighbor failed
    NeighFailed = 58,
    /// Neighbor queue full
    NeighQueueFull = 59,
    /// Neighbor dead
    NeighDead = 60,
    /// Neighbor HH fill failed
    NeighHhFillFail = 61,
    /// TC egress
    TcEgress = 62,
    /// Security hook
    SecurityHook = 63,
    /// Qdisc drop
    QdiscDrop = 64,
    /// Qdisc burst drop
    QdiscBurstDrop = 65,
    /// Qdisc overlimit
    QdiscOverlimit = 66,
    /// Qdisc congested
    QdiscCongested = 67,
    /// MACVLAN broadcast backlog
    MacvlanBroadcastBacklog = 68,
    /// IPvlan multicast backlog
    IpvlanMulticastBacklog = 69,
    /// XDP
    Xdp = 70,
    /// TC ingress
    TcIngress = 71,
    /// Unhandled protocol
    UnhandledProto = 72,
    /// SKB checksum
    SkbCsum = 73,
    /// SKB GSO segment
    SkbGsoSeg = 74,
    /// SKB bad GSO
    SkbBadGso = 75,
    /// SKB ucopy fault
    SkbUcopyFault = 76,
    /// Device header
    DevHdr = 77,
    /// Device ready
    DevReady = 78,
    /// Full ring
    FullRing = 79,
    /// No memory
    NoMem = 80,
    /// Header truncate
    HdrTrunc = 81,
    /// TAP filter
    TapFilter = 82,
    /// TAP TX filter
    TapTxFilter = 83,
    /// ICMP checksum
    IcmpCsum = 84,
    /// Invalid protocol
    InvalidProto = 85,
    /// IP address errors
    IpInaddrErrors = 86,
    /// IP no routes
    IpInNoRoutes = 87,
    /// IP local source
    IpLocalSource = 88,
    /// IP invalid source
    IpInvalidSource = 89,
    /// IP localnet
    IpLocalnet = 90,
    /// IP invalid dest
    IpInvalidDest = 91,
    /// Packet too big
    PktTooBig = 92,
    /// Duplicate fragment
    DupFrag = 93,
    /// Fragment reassembly timeout
    FragReasmTimeout = 94,
    /// Fragment too far
    FragTooFar = 95,
    /// TCP minimum TTL
    TcpMinTtl = 96,
    /// IPv6 bad ext header
    Ipv6BadExthdr = 97,
    /// IPv6 too many ext hdrs
    Ipv6TooManyExthdrs = 98,
    /// IPv6 NDISC frag
    Ipv6NdiscFrag = 99,
    /// IPv6 NDISC hop limit
    Ipv6NdiscHopLimit = 100,
    /// IPv6 NDISC bad code
    Ipv6NdiscBadCode = 101,
    /// IPv6 NDISC bad options
    Ipv6NdiscBadOptions = 102,
    /// IPv6 NDISC NS otherhost
    Ipv6NdiscNsOtherhost = 103,
    /// Queue purge
    QueuePurge = 104,
    /// TC cookie error
    TcCookieError = 105,
    /// Packet socket error
    PacketSocketError = 106,
    /// TC chain not found
    TcChainNotFound = 107,
    /// TC reclassify loop
    TcReclassifyLoop = 108,
    /// VXLAN invalid header
    VxlanInvalidHdr = 109,
    /// VXLAN VNI not found
    VxlanVniNotFound = 110,
    /// MAC invalid source
    MacInvalidSource = 111,
    /// VXLAN entry exists
    VxlanEntryExists = 112,
    /// No TX target
    NoTxTarget = 113,
    /// IP tunnel ECN
    IpTunnelEcn = 114,
    /// Tunnel TX info
    TunnelTxinfo = 115,
    /// Local MAC
    LocalMac = 116,
    /// ARP PVLAN disable
    ArpPvlanDisable = 117,
    /// MAC IEEE MAC control
    MacIeeeMacControl = 118,
    /// Bridge ingress STP state
    BridgeIngressStpState = 119,
    /// CAN RX invalid frame
    CanRxInvalidFrame = 120,
    /// CAN FD RX invalid frame
    CanfdRxInvalidFrame = 121,
    /// CAN XL RX invalid frame
    CanxlRxInvalidFrame = 122,
    /// PFMEMALLOC
    PmemAlloc = 123,
    /// PSP input
    PspInput = 124,
    /// PSP output
    PspOutput = 125,
    /// Recursion limit
    RecursionLimit = 126,
    /// MAX
    Max = 127,
}

impl From<u32> for SkbDropReason {
    fn from(val: u32) -> Self {
        match val {
            0 => SkbDropReason::NotSpecified,
            1 => SkbDropReason::Consumed,
            2 => SkbDropReason::NotSpecifiedReason,
            3 => SkbDropReason::NoSocket,
            4 => SkbDropReason::SocketClose,
            5 => SkbDropReason::SocketFilter,
            6 => SkbDropReason::SocketRcvbuff,
            7 => SkbDropReason::UnixDisconnect,
            8 => SkbDropReason::UnixSkipOob,
            9 => SkbDropReason::PktTooSmall,
            10 => SkbDropReason::TcpCsum,
            11 => SkbDropReason::UdpCsum,
            12 => SkbDropReason::NetfilterDrop,
            13 => SkbDropReason::OtherHost,
            14 => SkbDropReason::IpCsum,
            15 => SkbDropReason::IpInhdr,
            16 => SkbDropReason::IpRpfilter,
            17 => SkbDropReason::UnicastInL2Multicast,
            18 => SkbDropReason::XfrmPolicy,
            19 => SkbDropReason::IpNoProto,
            20 => SkbDropReason::ProtoMem,
            21 => SkbDropReason::TcpAuthHdr,
            22 => SkbDropReason::TcpMd5NotFound,
            23 => SkbDropReason::TcpMd5Unexpected,
            24 => SkbDropReason::TcpMd5Failure,
            25 => SkbDropReason::TcpAoNotFound,
            26 => SkbDropReason::TcpAoUnexpected,
            27 => SkbDropReason::TcpAoKeyNotFound,
            28 => SkbDropReason::TcpAoFailure,
            29 => SkbDropReason::SocketBacklog,
            30 => SkbDropReason::TcpFlags,
            31 => SkbDropReason::TcpAbortOnData,
            32 => SkbDropReason::TcpZeroWindow,
            33 => SkbDropReason::TcpOldData,
            34 => SkbDropReason::TcpOverWindow,
            35 => SkbDropReason::TcpOfoMerge,
            36 => SkbDropReason::TcpRfc7323Paws,
            37 => SkbDropReason::TcpRfc7323PawsAck,
            38 => SkbDropReason::TcpRfc7323TwPaws,
            39 => SkbDropReason::TcpRfc7323Tsecr,
            40 => SkbDropReason::TcpListenOverflow,
            41 => SkbDropReason::TcpOldSequence,
            42 => SkbDropReason::TcpInvalidSequence,
            43 => SkbDropReason::TcpInvalidEndSequence,
            44 => SkbDropReason::TcpInvalidAckSequence,
            45 => SkbDropReason::TcpReset,
            46 => SkbDropReason::TcpInvalidSyn,
            47 => SkbDropReason::TcpClose,
            48 => SkbDropReason::TcpFastOpen,
            49 => SkbDropReason::TcpOldAck,
            50 => SkbDropReason::TcpTooOldAck,
            51 => SkbDropReason::TcpAckUnsentData,
            52 => SkbDropReason::TcpOfoQueuePrune,
            53 => SkbDropReason::TcpOfoDrop,
            54 => SkbDropReason::IpOutNoRoutes,
            55 => SkbDropReason::BpfCgroupEgress,
            56 => SkbDropReason::Ipv6Disabled,
            57 => SkbDropReason::NeighCreateFail,
            58 => SkbDropReason::NeighFailed,
            59 => SkbDropReason::NeighQueueFull,
            60 => SkbDropReason::NeighDead,
            61 => SkbDropReason::NeighHhFillFail,
            62 => SkbDropReason::TcEgress,
            63 => SkbDropReason::SecurityHook,
            64 => SkbDropReason::QdiscDrop,
            65 => SkbDropReason::QdiscBurstDrop,
            66 => SkbDropReason::QdiscOverlimit,
            67 => SkbDropReason::QdiscCongested,
            68 => SkbDropReason::MacvlanBroadcastBacklog,
            69 => SkbDropReason::IpvlanMulticastBacklog,
            70 => SkbDropReason::Xdp,
            71 => SkbDropReason::TcIngress,
            72 => SkbDropReason::UnhandledProto,
            73 => SkbDropReason::SkbCsum,
            74 => SkbDropReason::SkbGsoSeg,
            75 => SkbDropReason::SkbBadGso,
            76 => SkbDropReason::SkbUcopyFault,
            77 => SkbDropReason::DevHdr,
            78 => SkbDropReason::DevReady,
            79 => SkbDropReason::FullRing,
            80 => SkbDropReason::NoMem,
            81 => SkbDropReason::HdrTrunc,
            82 => SkbDropReason::TapFilter,
            83 => SkbDropReason::TapTxFilter,
            84 => SkbDropReason::IcmpCsum,
            85 => SkbDropReason::InvalidProto,
            86 => SkbDropReason::IpInaddrErrors,
            87 => SkbDropReason::IpInNoRoutes,
            88 => SkbDropReason::IpLocalSource,
            89 => SkbDropReason::IpInvalidSource,
            90 => SkbDropReason::IpLocalnet,
            91 => SkbDropReason::IpInvalidDest,
            92 => SkbDropReason::PktTooBig,
            93 => SkbDropReason::DupFrag,
            94 => SkbDropReason::FragReasmTimeout,
            95 => SkbDropReason::FragTooFar,
            96 => SkbDropReason::TcpMinTtl,
            97 => SkbDropReason::Ipv6BadExthdr,
            98 => SkbDropReason::Ipv6TooManyExthdrs,
            99 => SkbDropReason::Ipv6NdiscFrag,
            100 => SkbDropReason::Ipv6NdiscHopLimit,
            101 => SkbDropReason::Ipv6NdiscBadCode,
            102 => SkbDropReason::Ipv6NdiscBadOptions,
            103 => SkbDropReason::Ipv6NdiscNsOtherhost,
            104 => SkbDropReason::QueuePurge,
            105 => SkbDropReason::TcCookieError,
            106 => SkbDropReason::PacketSocketError,
            107 => SkbDropReason::TcChainNotFound,
            108 => SkbDropReason::TcReclassifyLoop,
            109 => SkbDropReason::VxlanInvalidHdr,
            110 => SkbDropReason::VxlanVniNotFound,
            111 => SkbDropReason::MacInvalidSource,
            112 => SkbDropReason::VxlanEntryExists,
            113 => SkbDropReason::NoTxTarget,
            114 => SkbDropReason::IpTunnelEcn,
            115 => SkbDropReason::TunnelTxinfo,
            116 => SkbDropReason::LocalMac,
            117 => SkbDropReason::ArpPvlanDisable,
            118 => SkbDropReason::MacIeeeMacControl,
            119 => SkbDropReason::BridgeIngressStpState,
            120 => SkbDropReason::CanRxInvalidFrame,
            121 => SkbDropReason::CanfdRxInvalidFrame,
            122 => SkbDropReason::CanxlRxInvalidFrame,
            123 => SkbDropReason::PmemAlloc,
            124 => SkbDropReason::PspInput,
            125 => SkbDropReason::PspOutput,
            126 => SkbDropReason::RecursionLimit,
            127 => SkbDropReason::Max,
            _ => SkbDropReason::Max,
        }
    }
}

/// Reason name lookup
pub fn reason_name(reason: SkbDropReason) -> &'static str {
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
        SkbDropReason::MacvlanBroadcastBacklog => "MACVLAN_BROADCAST_BACKLOG",
        SkbDropReason::IpvlanMulticastBacklog => "IPVLAN_MULTICAST_BACKLOG",
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
        SkbDropReason::Ipv6TooManyExthdrs => "IPV6_TOO_MANY_EXTHDRS",
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
        SkbDropReason::PspInput => "PSP_INPUT",
        SkbDropReason::PspOutput => "PSP_OUTPUT",
        SkbDropReason::RecursionLimit => "RECURSION_LIMIT",
        SkbDropReason::Max => "MAX",
    }
}
