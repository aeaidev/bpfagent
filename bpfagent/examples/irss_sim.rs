//! IRSS system simulator — simulates the data flow described in
//! docs/IRSS.md for testing the bpfagent IRSS eBPF program:
//!
//!   CRYPTO --(UDP to port 5020)--> IRSS --(raw IP to 10.10.10.253)--> MAC
//!
//! A single process runs both ends as threads:
//! - the CRYPTO thread sends a UDP datagram every CYCLE_INTERVAL, each
//!   carrying a random 4-byte tag in its first payload bytes;
//! - the IRSS thread receives datagrams on UDP port 5020 with recvmsg(),
//!   waits PROCESSING_DELAY (simulated component work), then forwards the
//!   payload with sendmsg() over a raw IP socket towards 10.10.10.253.
//!
//! The agent's eBPF program hooks sys_enter_recvmsg/sys_exit_recvmsg and
//! sys_enter_sendmsg, so all I/O here uses recvmsg()/sendmsg(). The raw
//! socket uses protocol 253 (experimental) without IP_HDRINCL, so the kernel
//! builds the IP header and the first payload bytes stay the datagram tag.
//! The sys_enter_sendmsg tracepoint fires before routing, so the latency
//! measurement works even when 10.10.10.253 is unreachable; send errors are
//! logged and the flow continues.
//!
//! Usage (raw sockets require CAP_NET_RAW):
//!   sudo ./target/debug/examples/irss_sim [RAW_DEST_IP] [LISTEN_PORT]
//! RAW_DEST_IP defaults to 10.10.10.253 (irss_common::RAW_DEST) and
//! LISTEN_PORT to 5020 (irss_common::LISTEN_PORT); pass overrides to test
//! custom `raw_dest`/`listen_port` settings in bpfagent.conf.
//! Then start bpfagent and watch `irss_avg_latency_us` in /metrics.

use std::{
    net::{Ipv4Addr, UdpSocket},
    process::exit,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use irss_common::{LISTEN_PORT, RAW_DEST};

/// Experimental IP protocol number for the raw socket (kernel builds the
/// IP header; any value other than IPPROTO_RAW works).
const RAW_PROTOCOL: i32 = 253;

/// Fixed datagram size: 4-byte tag + filler.
const MSG_SIZE: usize = 64;
/// Interval between CRYPTO datagrams.
const CYCLE_INTERVAL: Duration = Duration::from_millis(1000);
/// Simulated IRSS processing time per datagram.
const PROCESSING_DELAY: Duration = Duration::from_millis(12);
/// recvmsg timeout so the shutdown flag is checked periodically.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

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
    eprintln!("irss_sim: FATAL: {}", msg);
    exit(1);
}

/// CRYPTO role: send one UDP datagram with a random 4-byte tag every cycle.
fn run_crypto(dest: String) {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => fatal(&format!("CRYPTO bind failed: {}", e)),
    };
    let mut cycle: u64 = 0;
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let mut buf = [0u8; MSG_SIZE];
        // The first 4 bytes are the tag the agent keys the datagram on.
        let tag = rand::random::<u32>();
        buf[..4].copy_from_slice(&tag.to_be_bytes());
        if let Err(e) = sock.send_to(&buf, &dest) {
            eprintln!("irss_sim[CRYPTO]: send_to({}) failed: {}", dest, e);
        }
        cycle += 1;
        if cycle.is_multiple_of(10) {
            eprintln!("irss_sim[CRYPTO]: {} datagrams sent", cycle);
        }
        std::thread::sleep(CYCLE_INTERVAL);
    }
}

/// IRSS role: receive UDP datagrams and forward them as raw-IP payloads.
fn run_irss(raw_dest_ip: [u8; 4], listen_port: u16) {
    let udp = match UdpSocket::bind(("0.0.0.0", listen_port)) {
        Ok(s) => s,
        Err(e) => fatal(&format!("IRSS bind UDP :{} failed: {}", listen_port, e)),
    };
    if let Err(e) = udp.set_read_timeout(Some(RECV_TIMEOUT)) {
        fatal(&format!("IRSS set_read_timeout failed: {}", e));
    }
    let udp_fd = {
        use std::os::unix::io::AsRawFd;
        udp.as_raw_fd()
    };

    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, RAW_PROTOCOL) };
    if raw_fd < 0 {
        fatal(&format!(
            "IRSS raw socket() failed (need root/CAP_NET_RAW): {}",
            std::io::Error::last_os_error()
        ));
    }
    let raw_dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(raw_dest_ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    eprintln!(
        "irss_sim[IRSS]: forwarding UDP :{} -> raw IP {}",
        listen_port,
        Ipv4Addr::from(raw_dest_ip)
    );
    let mut buf = [0u8; 512];
    while !SHUTDOWN.load(Ordering::SeqCst) {
        // recvmsg(): the syscall pair the IRSS eBPF program hooks for RX.
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut hdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(udp_fd, &mut hdr, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue; // recv timeout: re-check SHUTDOWN
            }
            eprintln!("irss_sim[IRSS]: recvmsg failed: {}", err);
            continue;
        }
        let len = n as usize;

        std::thread::sleep(PROCESSING_DELAY); // simulated component work

        // sendmsg() on the raw socket: the syscall the eBPF hooks for TX.
        let mut out_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: len,
        };
        let out_hdr = libc::msghdr {
            msg_name: &raw_dest as *const libc::sockaddr_in as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut out_iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let sent = unsafe { libc::sendmsg(raw_fd, &out_hdr, 0) };
        if sent < 0 {
            // The sys_enter_sendmsg tracepoint already fired, so the agent
            // measured this datagram even though the send itself failed
            // (e.g. no route to 10.10.10.253 on a test machine).
            eprintln!(
                "irss_sim[IRSS]: raw sendmsg failed (measurement still recorded): {}",
                std::io::Error::last_os_error()
            );
        }
    }
    unsafe {
        libc::close(raw_fd);
    }
}

fn main() {
    install_signal_handlers();

    // Optional overrides (defaults: irss_common::RAW_DEST, irss_common::LISTEN_PORT).
    let raw_dest_ip: [u8; 4] = match std::env::args().nth(1) {
        None => RAW_DEST,
        Some(arg) => match arg.parse::<Ipv4Addr>() {
            Ok(ip) => ip.octets(),
            Err(e) => fatal(&format!("invalid RAW_DEST_IP '{}': {}", arg, e)),
        },
    };
    let listen_port: u16 = match std::env::args().nth(2) {
        None => LISTEN_PORT,
        Some(arg) => match arg.parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => fatal(&format!("invalid LISTEN_PORT '{}'", arg)),
        },
    };

    let dest = format!("127.0.0.1:{}", listen_port);
    eprintln!(
        "irss_sim: CRYPTO sends UDP to {} every {:?}; IRSS forwards to raw IP {}",
        dest,
        CYCLE_INTERVAL,
        Ipv4Addr::from(raw_dest_ip)
    );
    eprintln!("irss_sim: start bpfagent now and watch irss_avg_latency_us");

    std::thread::spawn(move || run_crypto(dest));
    run_irss(raw_dest_ip, listen_port);

    eprintln!("irss_sim: shutting down");
}
