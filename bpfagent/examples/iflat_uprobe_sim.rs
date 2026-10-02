//! IFLAT_UPROBE system simulator — end-to-end test rig for the bpfagent
//! IFLAT_UPROBE eBPF program. It builds a self-contained copy of the
//! production data flow
//!
//!   sender --(UDP)--> RX1 iface --(app)--> RX2 iface (tun0) --(UDP)--> submit()
//!
//! on one machine: a network-namespace sender emits UDP datagrams that enter
//! the host on the RX1 interface, the simulator (playing the forwarding
//! application) receives them on a UDP socket, re-injects them into a tun
//! device (RX2 ingress), and — when the kernel delivers them to the tun-side
//! socket — calls an exported function with the payload wrapped in a
//! TxSlot-mirroring struct: the uprobe's attach point.
//!
//! Latency is measured twice, independently:
//! - by the agent: XDP on RX1 stores TIMESTAMP1_MAP[tag], XDP on tun0 (RX2)
//!   matches it (latency 1) and stores TIMESTAMP2_MAP[tag], and the uprobe
//!   on `iflat_uprobe_sim_submit` matches that (latency 2);
//! - in userspace: each datagram carries its CLOCK_MONOTONIC send timestamp
//!   in the payload; the simulator prints the sender→tun-injection and
//!   tun-injection→function-call spans for comparison. The sim's spans are
//!   supersets of the agent's numbers (they also cover the netns → veth
//!   delivery and the app/socket processing).
//!
//! Locally generated packets never pass XDP ingress, so the sender must run
//! on the far side of a real link: the simulator creates a network namespace
//! connected by a veth pair and re-executes itself inside it. The host end
//! of the pair (veth-iu0) plays the role of the production RX1 interface
//! (eno1); the tun fd write path plays RX2 (tun0). No NAT or routing is
//! involved: the datagrams are addressed to the host itself.
//!
//! Usage (requires root; iproute2 must be installed):
//!   sudo ./target/debug/examples/iflat_uprobe_sim [NETEM_DELAY_MS]
//! NETEM_DELAY_MS optionally delays the datagrams inside the namespace with
//! tc-netem: the sim's userspace span grows by that amount while the agent's
//! RX1→RX2 span does not (RX1 timestamps the datagram after the delay),
//! showing that IFLAT_UPROBE isolates the forwarding path. Then start the
//! agent with the config snippet printed at startup and watch
//! `iflat_uprobe_avg_latency1_us` / `iflat_uprobe_avg_latency2_us` in
//! /metrics. SIGINT tears the whole topology down.

use std::{
    collections::HashMap,
    os::unix::io::{AsRawFd, RawFd},
    process::{exit, Child, Command},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Name of the network namespace the sender runs in.
const NETNS: &str = "iu-sim";
/// Host end of the veth pair: the RX1 interface the agent attaches XDP to.
const VETH_HOST: &str = "veth-iu0";
/// Namespace end of the veth pair.
const VETH_NS: &str = "veth-iu1";
/// Host address on the veth link: the leg-1 datagram destination.
const VETH_HOST_IP: &str = "192.168.101.1";
/// Sender address inside the namespace.
const VETH_NS_IP: &str = "192.168.101.2";
/// Address assigned to tun0: the leg-2 datagram destination (local delivery).
const TUN_IP: &str = "10.200.1.1";
/// Source address of the crafted leg-2 datagrams (on-link on tun0's /24).
const TUN_SRC_IP: [u8; 4] = [10, 200, 1, 2];
/// tun0's address as octets (for crafting IP packets).
const TUN_IP_OCTETS: [u8; 4] = [10, 200, 1, 1];
/// UDP port the leg-1 receiver socket listens on (on VETH_HOST_IP).
const LEG1_PORT: u16 = 5000;
/// UDP port the leg-2 receiver socket listens on (on TUN_IP).
const LEG2_PORT: u16 = 5001;
/// Source port of the crafted leg-2 datagrams (nothing bound there; no
/// replies are ever sent back).
const CRAFTED_SPORT: u16 = 5002;
/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// Interval between test datagrams.
const SEND_INTERVAL: Duration = Duration::from_millis(500);
/// poll() timeout so the shutdown flag is checked periodically.
const POLL_TIMEOUT_MS: libc::c_int = 500;
/// Datagram payload size: 4-byte tag + 8-byte send timestamp + filler.
const MSG_SIZE: usize = 64;

/// offsetof(TxSlot, payload) in the production layout the sim mirrors:
/// state(4) + index(4) + endpoint(4) + burst(256) lands the three u64
/// counters at 272 after alignment, so the payload pointer sits at 296.
const SIM_PAYLOAD_PTR_OFFSET: usize = 296;

/// IFF_TUN | IFF_NO_PI for TUNSETIFF (no extra packet-information header, so
/// writes to the fd are plain IP packets).
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
    eprintln!("iflat_uprobe_sim: FATAL: {}", msg);
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

/// Mirror of the production TxSlot layout the uprobe chases through: the
/// payload address is a pointer member, not inline data, so the agent reads
/// it at payload_ptr_offset (= offsetof(TxSlot, payload)) and follows it.
/// The 256-byte burst stands in for metadata_data_tx_t.
#[repr(C)]
pub struct TxSlotSim {
    state: u32,         // std::atomic<TxSlotState> — enum, 4 bytes
    index: u32,         // 4
    endpoint: u32,      // Endpoint — enum, 4
    burst: [u8; 256],   // metadata_data_tx_t
    dispatch_time: u64, // 8-aligned: lands at 272
    enqueued_ncr: u64,  // 280
    dispatch_ncr: u64,  // 288
    payload: *mut u8,   // 296: pool arena, `payload_capacity` bytes
    payload_capacity: u32,
    payload_length: u32,
}

// The sim's config snippet hardcodes payload_ptr_offset = 296; pin the
// struct layout to the production offset it mirrors.
const _: () = assert!(
    std::mem::offset_of!(TxSlotSim, payload) == SIM_PAYLOAD_PTR_OFFSET,
    "TxSlotSim payload offset must match the production TxSlot layout"
);

/// Function the uprobe program attaches to, mirroring
/// `void FpgaPciePhy::submitBurst(Endpoint from, TxSlot &slot)`: the leading
/// dummy `_this` pointer plays the role of the C++ method's hidden `this`,
/// so `slot` lands in rdx — argument register 3, the agent's default
/// `arg_index`. Exported under its plain C name so no demangling is needed;
/// `inline(never)` guarantees a real call instruction (the attach point).
///
/// Reads the payload through the slot pointer so all parameters are
/// observably used and the pointer chase the eBPF program performs (slot ->
/// slot->payload -> first 4 payload bytes) stays valid.
#[no_mangle]
#[inline(never)]
pub extern "C" fn iflat_uprobe_sim_submit(
    _this: *const libc::c_void,
    from: u32,
    slot: *const TxSlotSim,
) -> u64 {
    if slot.is_null() {
        return 0;
    }
    // SAFETY: the call site passes a valid slot whose payload points at
    // payload_length readable bytes; both outlive the call.
    let slot = unsafe { &*slot };
    let mut acc = u64::from(from) ^ u64::from(slot.state) ^ slot.dispatch_time;
    if !slot.payload.is_null() {
        let len = (slot.payload_length as usize).min(slot.payload_capacity as usize);
        for i in 0..len {
            acc = acc.rotate_left(5) ^ u64::from(unsafe { *slot.payload.add(i) });
        }
    }
    acc
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
    run_ignore("ip", &["netns", "delete", NETNS]);
    run_ignore("ip", &["link", "delete", VETH_HOST]);
}

/// Build the topology: netns + veth pair; the sender's datagrams are
/// addressed to the host, so no forwarding or NAT is needed.
fn setup(netem_delay_ms: u64) {
    // Namespace link playing the role of the production RX1 interface (eno1).
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
}

/// Tear down everything setup() created (the tun fd dies with the process,
/// the veth pair dies with the namespace).
fn teardown() {
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

/// Internet checksum (RFC 1071) over `data`.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    add_checksum_words(&mut sum, data);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build one crafted IPv4 + UDP packet in `pkt` carrying `payload`,
/// returning its length: TUN_SRC_IP:CRAFTED_SPORT -> TUN_IP:LEG2_PORT. The
/// packet is written to the tun fd, so it enters the kernel on tun0 ingress
/// (the agent's RX2 hook) and is then delivered locally to the leg-2 socket.
/// The IP header checksum must be correct (the kernel verifies it); the UDP
/// checksum is 0, which is legal for IPv4.
fn craft_tun_packet(pkt: &mut [u8], payload: &[u8]) -> usize {
    const IP_HLEN: usize = 20;
    const UDP_HLEN: usize = 8;
    let total = IP_HLEN + UDP_HLEN + payload.len();

    // IPv4 header.
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // TOS
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_UDP;
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // header checksum
    pkt[12..16].copy_from_slice(&TUN_SRC_IP);
    pkt[16..20].copy_from_slice(&TUN_IP_OCTETS);

    // UDP header, checksum 0 = "not computed" (valid for IPv4).
    let udp = IP_HLEN;
    pkt[udp..udp + 2].copy_from_slice(&CRAFTED_SPORT.to_be_bytes());
    pkt[udp + 2..udp + 4].copy_from_slice(&LEG2_PORT.to_be_bytes());
    pkt[udp + 4..udp + 6].copy_from_slice(&((UDP_HLEN + payload.len()) as u16).to_be_bytes());
    pkt[udp + 6..udp + 8].copy_from_slice(&0u16.to_be_bytes());

    pkt[udp + UDP_HLEN..udp + UDP_HLEN + payload.len()].copy_from_slice(payload);

    let cksum = internet_checksum(&pkt[..IP_HLEN]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());

    total
}

/// Sender role (runs inside the namespace): every SEND_INTERVAL sends one
/// UDP datagram to the host's veth address carrying a random 4-byte tag (the
/// agent's correlation key) and its CLOCK_MONOTONIC send timestamp (the
/// simulator's key).
fn run_sender() {
    let udp = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => fatal(&format!("sender UDP bind failed: {}", e)),
    };
    let dest = format!("{}:{}", VETH_HOST_IP, LEG1_PORT);

    let mut cycle: u64 = 0;
    loop {
        let tag = rand::random::<u32>();
        let sent_ns = monotonic_ns();
        let mut buf = [0u8; MSG_SIZE];
        buf[..4].copy_from_slice(&tag.to_be_bytes());
        buf[4..12].copy_from_slice(&sent_ns.to_be_bytes());
        if let Err(e) = udp.send_to(&buf, &dest) {
            eprintln!(
                "iflat_uprobe_sim[sender]: UDP send_to({}) failed: {}",
                dest, e
            );
        }
        cycle += 1;
        if cycle.is_multiple_of(10) {
            eprintln!("iflat_uprobe_sim[sender]: {} datagrams sent", cycle);
        }
        std::thread::sleep(SEND_INTERVAL);
    }
}

/// Receiver role (host, plays the forwarding application): receive leg-1
/// datagrams from the veth link, re-inject them into tun0 (RX2 ingress),
/// and on local delivery from the tun side hand the payload to
/// iflat_uprobe_sim_submit() — the uprobe's function call. Prints the
/// userspace latency spans for comparison with the agent's gauges.
fn run_receiver(leg1: std::net::UdpSocket, leg2: std::net::UdpSocket, tun_fd: RawFd) {
    for sock in [&leg1, &leg2] {
        if let Err(e) = sock.set_nonblocking(true) {
            fatal(&format!("set_nonblocking failed: {}", e));
        }
    }
    let leg1_fd = leg1.as_raw_fd();
    let leg2_fd = leg2.as_raw_fd();

    let mut buf = [0u8; 2048];
    let mut pkt = [0u8; 2048];
    // Tag -> tun-injection timestamp, for the per-leg userspace spans. The
    // flow is sequential at 500 ms intervals, so a handful of entries at
    // most are outstanding; the map is cleared defensively if leg 2 stops.
    let mut injections: HashMap<u32, u64> = HashMap::new();
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let mut fds = [
            libc::pollfd {
                fd: leg1_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: leg2_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 3, POLL_TIMEOUT_MS) };
        if ready <= 0 {
            continue; // timeout: re-check SHUTDOWN
        }

        // Leg 1: datagram from the namespace arrived on veth-iu0; forward it
        // by writing a fresh IP packet with the same payload to the tun fd.
        if fds[0].revents & libc::POLLIN != 0 {
            match leg1.recv(&mut buf) {
                Ok(n) if n == MSG_SIZE => {
                    let tag = u32::from_be_bytes(buf[..4].try_into().unwrap_or([0; 4]));
                    let len = craft_tun_packet(&mut pkt, &buf[..n]);
                    let inject_ns = monotonic_ns();
                    let written =
                        unsafe { libc::write(tun_fd, pkt.as_ptr() as *const libc::c_void, len) };
                    if written < 0 {
                        eprintln!(
                            "iflat_uprobe_sim[recv]: tun write failed: {}",
                            std::io::Error::last_os_error()
                        );
                    } else {
                        injections.insert(tag, inject_ns);
                    }
                }
                Ok(_) => {} // not a test datagram, skip
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("iflat_uprobe_sim[recv]: leg-1 recv failed: {}", e),
            }
        }

        // Leg 2: the kernel delivered the re-injected datagram locally; hand
        // the payload to the instrumented function through the TxSlot mirror.
        if fds[1].revents & libc::POLLIN != 0 {
            match leg2.recv(&mut buf) {
                Ok(n) if n == MSG_SIZE => {
                    let tag = u32::from_be_bytes(buf[..4].try_into().unwrap_or([0; 4]));
                    let sent_ns = u64::from_be_bytes(buf[4..12].try_into().unwrap_or([0; 8]));
                    let injected_ns = injections.remove(&tag);

                    let mut arena = buf[..n].to_vec();
                    let slot = TxSlotSim {
                        state: 1,
                        index: 0,
                        endpoint: 0,
                        burst: [0; 256],
                        dispatch_time: 0,
                        enqueued_ncr: 0,
                        dispatch_ncr: 0,
                        payload: arena.as_mut_ptr(),
                        payload_capacity: arena.len() as u32,
                        payload_length: arena.len() as u32,
                    };
                    let fn_ns = monotonic_ns();
                    let _ = iflat_uprobe_sim_submit(std::ptr::null(), 0, &slot);

                    let total_us = fn_ns.saturating_sub(sent_ns) / 1_000;
                    match injected_ns {
                        Some(inj) => eprintln!(
                            "iflat_uprobe_sim[recv]: tag=0x{:08x} sender->tun={} us, tun->fn={} us (total={} us)",
                            tag,
                            inj.saturating_sub(sent_ns) / 1_000,
                            fn_ns.saturating_sub(inj) / 1_000,
                            total_us
                        ),
                        None => eprintln!(
                            "iflat_uprobe_sim[recv]: tag=0x{:08x} total={} us (no injection timestamp)",
                            tag, total_us
                        ),
                    }
                }
                Ok(_) => {} // not a test datagram, skip
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("iflat_uprobe_sim[recv]: leg-2 recv failed: {}", e),
            }
        }

        // Drain the tun fd (ICMP errors and any host traffic routed out
        // tun0) so the queue never fills.
        if fds[2].revents & libc::POLLIN != 0 {
            let _ = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        }

        if injections.len() > 1024 {
            injections.clear();
        }
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
        fatal("must run as root (creates netns/veth/tun)");
    }

    cleanup_stale();

    let tun_fd = create_tun("tun0");
    run(
        "ip",
        &["addr", "add", &format!("{}/24", TUN_IP), "dev", "tun0"],
    );
    run("ip", &["link", "set", "tun0", "up"]);

    setup(netem_delay_ms);

    // Leg-1 socket receives the namespace datagrams on the veth link; leg-2
    // socket receives the re-injected datagrams the kernel delivers locally
    // on tun0's address.
    let leg1 = match std::net::UdpSocket::bind(format!("{}:{}", VETH_HOST_IP, LEG1_PORT)) {
        Ok(s) => s,
        Err(e) => fatal(&format!("leg-1 UDP bind failed: {}", e)),
    };
    let leg2 = match std::net::UdpSocket::bind(format!("{}:{}", TUN_IP, LEG2_PORT)) {
        Ok(s) => s,
        Err(e) => fatal(&format!("leg-2 UDP bind failed: {}", e)),
    };

    eprintln!(
        "iflat_uprobe_sim: sender in netns '{}' sends UDP to {}:{} every {:?};",
        NETNS, VETH_HOST_IP, LEG1_PORT, SEND_INTERVAL
    );
    eprintln!(
        "iflat_uprobe_sim: datagrams arrive on {} (RX1), get re-injected into tun0 ({}) and call iflat_uprobe_sim_submit()",
        VETH_HOST, TUN_IP
    );
    if netem_delay_ms > 0 {
        eprintln!(
            "iflat_uprobe_sim: netem delay of {} ms applies inside the namespace (userspace span only)",
            netem_delay_ms
        );
    }
    eprintln!("iflat_uprobe_sim: start the agent with:");
    eprintln!("    [[ebpf_programs]]");
    eprintln!("    name = \"iflat_uprobe\"");
    eprintln!("    enabled = true");
    eprintln!("    [ebpf_programs.settings]");
    eprintln!("    rx1_iface = \"{}\"", VETH_HOST);
    eprintln!("    rx2_iface = \"tun0\"");
    eprintln!(
        "    target = \"{}\"",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<this binary>".to_string())
    );
    eprintln!("    symbol = \"iflat_uprobe_sim_submit\"");
    eprintln!("    pid = {}", std::process::id());
    eprintln!("    arg_index = 3");
    eprintln!("    payload_ptr_offset = {}", SIM_PAYLOAD_PTR_OFFSET);
    eprintln!("    tag_offset = 0");
    eprintln!(
        "iflat_uprobe_sim: then watch iflat_uprobe_avg_latency1_us / iflat_uprobe_avg_latency2_us in /metrics"
    );

    let mut sender = spawn_sender();
    run_receiver(leg1, leg2, tun_fd);

    eprintln!("iflat_uprobe_sim: shutting down");
    let _ = sender.kill();
    let _ = sender.wait();
    teardown();
    unsafe {
        libc::close(tun_fd);
    }
}
