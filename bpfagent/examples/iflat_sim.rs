//! IFLAT system simulator — end-to-end test rig for the bpfagent IFLAT eBPF
//! program. It builds a self-contained copy of the production data flow
//!
//!   sender --(UDP/TCP)--> RX iface --(route + nftables masquerade)--> tun0
//!
//! on one machine and measures the latency twice, independently:
//! - in userspace: each datagram carries its send timestamp (CLOCK_MONOTONIC)
//!   in the payload; the simulator reads the forwarded datagrams from the tun
//!   file descriptor and prints the total send-to-receive latency;
//! - by the agent: IFLAT timestamps the datagram at XDP ingress on the RX
//!   interface and again at TC egress on tun0 — the in-kernel forwarding
//!   span, which is a subset of the userspace number.
//!
//! Locally generated packets never pass XDP ingress, so the sender must run
//! on the far side of a real link: the simulator creates a network namespace
//! connected by a veth pair and re-executes itself inside it. The host end
//! of the pair (veth-iflat0) plays the role of the production RX interface
//! (eno1); nftables masquerade towards tun0 mirrors /etc/nftables.conf.
//!
//! The sender alternates one UDP datagram and one TCP segment per cycle.
//! Nothing at the destination answers, so TCP cannot go through a real
//! connection: the segments are crafted statelessly on a raw socket (SYN
//! with payload, fresh source port per segment, proper checksum) so
//! conntrack accepts and masquerades them without any handshake.
//!
//! Usage (requires root; iproute2 and nftables must be installed):
//!   sudo ./target/debug/examples/iflat_sim [NETEM_DELAY_MS]
//! NETEM_DELAY_MS optionally delays the datagrams inside the namespace with
//! tc-netem: the userspace latency grows by that amount while the agent's
//! in-kernel span does not, showing that IFLAT isolates the forwarding path.
//! Then start the agent with the config snippet printed at startup and watch
//! `iflat_avg_latency_us` in /metrics. SIGINT tears the whole topology down.

use std::{
    os::unix::io::RawFd,
    process::{exit, Child, Command},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Name of the network namespace the sender runs in.
const NETNS: &str = "iflat-sim";
/// Host end of the veth pair: the RX interface the agent attaches XDP to.
const VETH_HOST: &str = "veth-iflat0";
/// Namespace end of the veth pair.
const VETH_NS: &str = "veth-iflat1";
/// Host address on the veth link; also the sender's default gateway.
const VETH_HOST_IP: &str = "192.168.100.1";
/// Sender address inside the namespace.
const VETH_NS_IP: &str = "192.168.100.2";
/// Address assigned to tun0 (masquerade source).
const TUN_IP: &str = "10.200.0.1";
/// Destination of the test datagrams: routes out tun0, needs no listener.
const DEST: &str = "10.200.0.2:5000";
/// Destination IP/port of the test datagrams, used to filter the packets read
/// back from the tun fd: the host's own multicast chatter (mDNS/LLMNR to
/// 224.0.0.0/24) is also routed out tun0 and must be ignored.
const DEST_IP: [u8; 4] = [10, 200, 0, 2];
const DEST_PORT: u16 = 5000;
/// Destination port of the crafted TCP segments (UDP uses DEST_PORT); also
/// used as the receiver-side filter.
const TCP_DEST_PORT: u16 = 5001;
/// Sender address inside the namespace as octets (for crafting IP packets).
const VETH_NS_IP_OCTETS: [u8; 4] = [192, 168, 100, 2];
/// IP protocol numbers used when parsing/crafting packets.
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;
/// nftables table holding the masquerade rule; deleted whole on teardown.
const NFT_TABLE: &str = "iflat-sim";

/// Interval between test datagrams.
const SEND_INTERVAL: Duration = Duration::from_millis(500);
/// poll() timeout on the tun fd so the shutdown flag is checked periodically.
const POLL_TIMEOUT_MS: libc::c_int = 500;
/// Datagram size: 4-byte tag + 8-byte send timestamp + filler.
const MSG_SIZE: usize = 64;

/// IFF_TUN | IFF_NO_PI for TUNSETIFF (no extra packet-information header, so
/// reads from the fd return plain IP packets).
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    let handler = handle_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("iflat_sim: FATAL: {}", msg);
    exit(1);
}

/// CLOCK_MONOTONIC in nanoseconds; the sender (namespace) and the receiver
/// (host) run on the same machine, so this one clock serves both ends.
fn monotonic_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Run a setup command, fatally reporting its stderr on failure.
fn run(cmd: &str, args: &[&str]) {
    let output = match Command::new(cmd).args(args).output() {
        Ok(o) => o,
        Err(e) => fatal(&format!(
            "failed to run {}: {} (installed? in PATH?)",
            cmd, e
        )),
    };
    if !output.status.success() {
        fatal(&format!(
            "{} {} failed: {}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
}

/// Run a command best-effort (used for cleanup of possibly-absent objects).
fn run_ignore(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// Create the tun interface and return its fd. The device is not persistent:
/// it disappears when the fd is closed, so even a SIGKILL leaves no residue.
fn create_tun(name: &str) -> RawFd {
    let fd = unsafe {
        libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
        )
    };
    if fd < 0 {
        fatal(&format!(
            "open /dev/net/tun failed (need root, TUN module loaded): {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    // Writing the flags member of the ifr_ifru union needs no unsafe.
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
    if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } < 0 {
        fatal(&format!(
            "TUNSETIFF {} failed: {}",
            name,
            std::io::Error::last_os_error()
        ));
    }
    fd
}

/// Remove leftover objects from a previous run (best-effort).
fn cleanup_stale() {
    run_ignore("nft", &["delete", "table", "inet", NFT_TABLE]);
    run_ignore("ip", &["netns", "delete", NETNS]);
    run_ignore("ip", &["link", "delete", VETH_HOST]);
}

/// Build the whole topology: tun0 + veth pair + namespace + forwarding + NAT.
fn setup(netem_delay_ms: u64) {
    // Namespace link playing the role of the production RX interface (eno1).
    run("ip", &["netns", "add", NETNS]);
    run(
        "ip",
        &[
            "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS,
        ],
    );
    run("ip", &["link", "set", VETH_NS, "netns", NETNS]);
    run(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/24", VETH_HOST_IP),
            "dev",
            VETH_HOST,
        ],
    );
    run("ip", &["link", "set", VETH_HOST, "up"]);
    run(
        "ip",
        &["netns", "exec", NETNS, "ip", "link", "set", "lo", "up"],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            NETNS,
            "ip",
            "addr",
            "add",
            &format!("{}/24", VETH_NS_IP),
            "dev",
            VETH_NS,
        ],
    );
    run(
        "ip",
        &["netns", "exec", NETNS, "ip", "link", "set", VETH_NS, "up"],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            NETNS,
            "ip",
            "route",
            "add",
            "default",
            "via",
            VETH_HOST_IP,
        ],
    );
    if netem_delay_ms > 0 {
        run(
            "ip",
            &[
                "netns",
                "exec",
                NETNS,
                "tc",
                "qdisc",
                "add",
                "dev",
                VETH_NS,
                "root",
                "netem",
                "delay",
                &format!("{}ms", netem_delay_ms),
            ],
        );
    }

    // Kernel forwarding + nftables masquerade towards tun0, mirroring the
    // production /etc/nftables.conf setup.
    if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n") {
        fatal(&format!("failed to enable ip_forward: {}", e));
    }
    run("nft", &["add", "table", "inet", NFT_TABLE]);
    run(
        "nft",
        &[&format!(
            "add chain inet {} postrouting {{ type nat hook postrouting priority 100 ; }}",
            NFT_TABLE
        )],
    );
    run(
        "nft",
        &[&format!(
            "add rule inet {} postrouting oifname \"tun0\" masquerade",
            NFT_TABLE
        )],
    );
}

/// Tear down everything setup() created (the tun fd dies with the process).
fn teardown() {
    run_ignore("nft", &["delete", "table", "inet", NFT_TABLE]);
    run_ignore("ip", &["netns", "delete", NETNS]);
}

/// Spawn the sender: this same binary re-executed inside the namespace.
fn spawn_sender() -> Child {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => fatal(&format!("current_exe failed: {}", e)),
    };
    match Command::new("ip")
        .args(["netns", "exec", NETNS])
        .arg(exe)
        .arg("--sender")
        .spawn()
    {
        Ok(child) => child,
        Err(e) => fatal(&format!("failed to spawn sender: {}", e)),
    }
}

/// Accumulate 16-bit big-endian words of `data` into the running one's
/// complement sum (a trailing odd byte counts as its high half).
fn add_checksum_words(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        *sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [b] = chunks.remainder() {
        *sum += u32::from(*b) << 8;
    }
}

/// TCP checksum (RFC 793): one's complement of the one's-complement sum over
/// the pseudo-header (src, dst, protocol, TCP length) and the TCP segment.
/// Computed properly so conntrack accepts the crafted segments; NAT adjusts
/// it incrementally when masquerading.
fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    add_checksum_words(&mut sum, &src_ip);
    add_checksum_words(&mut sum, &dst_ip);
    sum += u32::from(IPPROTO_TCP);
    sum += segment.len() as u32;
    add_checksum_words(&mut sum, segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build one crafted TCP segment (IPv4 + TCP + payload) in `pkt`, returning
/// its length: SYN flag, random ephemeral source port and sequence number,
/// payload carrying the 4-byte tag and the 8-byte send timestamp in the same
/// layout as the UDP datagrams.
///
/// A fresh source port per segment makes every segment a brand-new
/// connection for conntrack, so no handshake or window tracking is needed
/// (nothing at the destination answers); a SYN with payload is legal and
/// passes conntrack's checks, so masquerade applies.
fn craft_tcp_segment(pkt: &mut [u8], tag: u32, sent_ns: u64) -> usize {
    const IP_HLEN: usize = 20;
    const TCP_HLEN: usize = 20;
    let total = IP_HLEN + TCP_HLEN + MSG_SIZE;

    // IPv4 header; the kernel fills the header checksum (IP_HDRINCL).
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // TOS
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_TCP;
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // header checksum
    pkt[12..16].copy_from_slice(&VETH_NS_IP_OCTETS);
    pkt[16..20].copy_from_slice(&DEST_IP);

    // TCP header.
    let tcp = IP_HLEN;
    let sport = rand::random::<u16>() | 0x4000; // ephemeral
    pkt[tcp..tcp + 2].copy_from_slice(&sport.to_be_bytes());
    pkt[tcp + 2..tcp + 4].copy_from_slice(&TCP_DEST_PORT.to_be_bytes());
    pkt[tcp + 4..tcp + 8].copy_from_slice(&rand::random::<u32>().to_be_bytes()); // seq
    pkt[tcp + 8..tcp + 12].copy_from_slice(&0u32.to_be_bytes()); // ack_seq
    pkt[tcp + 12] = ((TCP_HLEN / 4) as u8) << 4; // data offset
    pkt[tcp + 13] = 0x02; // SYN
    pkt[tcp + 14..tcp + 16].copy_from_slice(&64240u16.to_be_bytes()); // window
    pkt[tcp + 16..tcp + 18].copy_from_slice(&0u16.to_be_bytes()); // checksum
    pkt[tcp + 18..tcp + 20].copy_from_slice(&0u16.to_be_bytes()); // urg ptr

    // Payload: same tag + timestamp layout as the UDP datagrams.
    let payload = tcp + TCP_HLEN;
    pkt[payload..payload + 4].copy_from_slice(&tag.to_be_bytes());
    pkt[payload + 4..payload + 12].copy_from_slice(&sent_ns.to_be_bytes());

    let cksum = tcp_checksum(
        VETH_NS_IP_OCTETS,
        DEST_IP,
        &pkt[tcp..tcp + TCP_HLEN + MSG_SIZE],
    );
    pkt[tcp + 16..tcp + 18].copy_from_slice(&cksum.to_be_bytes());

    total
}

/// Sender role (runs inside the namespace): alternates one UDP datagram and
/// one crafted TCP segment every SEND_INTERVAL, each carrying a random
/// 4-byte tag (the agent's correlation key) and its CLOCK_MONOTONIC send
/// timestamp (the simulator's key).
fn run_sender() {
    let udp = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => fatal(&format!("sender UDP bind failed: {}", e)),
    };
    // Raw socket for the crafted TCP segments (IP_HDRINCL is implied by
    // IPPROTO_RAW): nothing at the destination answers, so real TCP
    // connections cannot be used.
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if raw_fd < 0 {
        fatal(&format!(
            "sender raw socket() failed (need root/CAP_NET_RAW): {}",
            std::io::Error::last_os_error()
        ));
    }
    let raw_dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(DEST_IP).to_be(),
        },
        sin_zero: [0; 8],
    };

    let mut cycle: u64 = 0;
    loop {
        let tag = rand::random::<u32>();
        let sent_ns = monotonic_ns();
        if cycle % 2 == 0 {
            let mut buf = [0u8; MSG_SIZE];
            buf[..4].copy_from_slice(&tag.to_be_bytes());
            buf[4..12].copy_from_slice(&sent_ns.to_be_bytes());
            if let Err(e) = udp.send_to(&buf, DEST) {
                eprintln!("iflat_sim[sender]: UDP send_to({}) failed: {}", DEST, e);
            }
        } else {
            let mut pkt = [0u8; 128];
            let len = craft_tcp_segment(&mut pkt, tag, sent_ns);
            let sent = unsafe {
                libc::sendto(
                    raw_fd,
                    pkt.as_ptr() as *const libc::c_void,
                    len,
                    0,
                    &raw_dest as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                eprintln!(
                    "iflat_sim[sender]: TCP sendto failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        cycle += 1;
        if cycle.is_multiple_of(10) {
            eprintln!("iflat_sim[sender]: {} datagrams sent", cycle);
        }
        std::thread::sleep(SEND_INTERVAL);
    }
}

/// Extract (tag, send timestamp, protocol name) from a raw IP packet read
/// off the tun fd. Returns None for anything that is not one of our test
/// datagrams: foreign UDP traffic also leaves via tun0 (the host's
/// mDNS/LLMNR announcements appear as soon as the interface comes up), so
/// check the destination address and port before trusting the payload
/// layout.
fn parse_packet(pkt: &[u8]) -> Option<(u32, u64, &'static str)> {
    let version_ihl = *pkt.first()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    if pkt.get(16..20)? != DEST_IP {
        return None;
    }
    let protocol = *pkt.get(9)?;
    let dport = u16::from_be_bytes(pkt.get(ihl + 2..ihl + 4)?.try_into().ok()?);
    let (l4_hlen, name) = match protocol {
        IPPROTO_UDP if dport == DEST_PORT => (8, "udp"),
        IPPROTO_TCP if dport == TCP_DEST_PORT => {
            let hlen = usize::from(pkt.get(ihl + 12)? >> 4) * 4;
            if hlen < 20 {
                return None;
            }
            (hlen, "tcp")
        }
        _ => return None,
    };
    let payload = pkt.get(ihl + l4_hlen..)?;
    let tag = u32::from_be_bytes(payload.get(0..4)?.try_into().ok()?);
    let ts = u64::from_be_bytes(payload.get(4..12)?.try_into().ok()?);
    Some((tag, ts, name))
}

/// Receiver role: read forwarded datagrams from the tun fd and report the
/// userspace send-to-receive latency.
fn run_receiver(tun_fd: RawFd) {
    let mut buf = [0u8; 2048];
    let (mut samples, mut sum_us, mut min_us, mut max_us) = (0u64, 0u64, u64::MAX, 0u64);
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
        if ready <= 0 {
            continue; // timeout: re-check SHUTDOWN
        }
        let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            continue;
        }
        let Some((tag, sent_ns, proto)) = parse_packet(&buf[..n as usize]) else {
            continue; // not a test datagram (foreign traffic on tun0), skip
        };
        let latency_us = monotonic_ns().saturating_sub(sent_ns) / 1_000;
        samples += 1;
        sum_us += latency_us;
        min_us = min_us.min(latency_us);
        max_us = max_us.max(latency_us);
        eprintln!(
            "iflat_sim[recv]: {} tag=0x{:08x} userspace latency={} us (avg={} us, min={} us, max={} us, {} samples)",
            proto,
            tag,
            latency_us,
            sum_us / samples,
            min_us,
            max_us,
            samples
        );
    }
}

fn main() {
    install_signal_handlers();

    // Internal mode: run as the sender inside the namespace.
    if std::env::args().any(|a| a == "--sender") {
        run_sender();
        return;
    }

    let netem_delay_ms: u64 = match std::env::args().nth(1) {
        None => 0,
        Some(arg) => match arg.parse() {
            Ok(ms) => ms,
            Err(_) => fatal(&format!("invalid NETEM_DELAY_MS '{}'", arg)),
        },
    };

    if unsafe { libc::geteuid() } != 0 {
        fatal("must run as root (creates netns/veth/tun and nftables rules)");
    }

    cleanup_stale();

    let tun_fd = create_tun("tun0");
    run(
        "ip",
        &["addr", "add", &format!("{}/24", TUN_IP), "dev", "tun0"],
    );
    run("ip", &["link", "set", "tun0", "up"]);

    setup(netem_delay_ms);

    eprintln!(
        "iflat_sim: sender in netns '{}' alternates UDP to {} and crafted TCP to 10.200.0.2:{} every {:?};",
        NETNS, DEST, TCP_DEST_PORT, SEND_INTERVAL
    );
    eprintln!(
        "iflat_sim: datagrams arrive on {}, get NATed towards tun0 ({}) and are read back from the tun fd",
        VETH_HOST, TUN_IP
    );
    if netem_delay_ms > 0 {
        eprintln!(
            "iflat_sim: netem delay of {} ms applies inside the namespace (userspace latency only)",
            netem_delay_ms
        );
    }
    eprintln!("iflat_sim: start the agent with:");
    eprintln!("    [[ebpf_programs]]");
    eprintln!("    name = \"iflat\"");
    eprintln!("    enabled = true");
    eprintln!("    [ebpf_programs.settings]");
    eprintln!("    rx_iface = \"{}\"", VETH_HOST);
    eprintln!("    tx_iface = \"tun0\"");
    eprintln!("iflat_sim: then watch iflat_avg_latency_us in /metrics");

    let mut sender = spawn_sender();
    run_receiver(tun_fd);

    eprintln!("iflat_sim: shutting down");
    let _ = sender.kill();
    let _ = sender.wait();
    teardown();
    unsafe {
        libc::close(tun_fd);
    }
}
