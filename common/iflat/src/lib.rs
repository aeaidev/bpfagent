#![no_std]

// Shared types between user and eBPF code

/// Size of the payload tag used as the TIMESTAMP_MAP key: the first 4 bytes
/// of the UDP/TCP/ICMP payload, read big-endian. NAT rewrites addresses,
/// ports and checksums but never the payload, so the tag correlates the
/// pre-NAT (RX interface) and post-NAT (TX interface) sightings of one
/// datagram.
pub const KEY_SIZE: usize = 4;
