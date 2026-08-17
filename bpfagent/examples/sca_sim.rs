//! SCA system simulator — simulates the data flow pipeline described in
//! docs/SCA_DATA_FLOW.md for testing the bpfagent SCA eBPF program.
//!
//! Spawns one OS process per component (DATA_SOURCE, INTERNAL_ROUTER,
//! RED_WF_COMM_L, FRAGMENTER, RED_IRSS_COMM_L, DATA_SINK) with the process
//! name (comm) set exactly as in sca_common::DATA_FLOW, and wires them with
//! Unix stream sockets at the same paths:
//!
//!   TX: DATA_SOURCE -> INTERNAL_ROUTER -> RED_WF_COMM_L -> FRAGMENTER -> RED_IRSS_COMM_L
//!   RX: RED_IRSS_COMM_L -> FRAGMENTER -> RED_WF_COMM_L -> DATA_SINK
//!
//! Each hop is a lockstep REQ/REP exchange over a persistent connection:
//! the sender uses sendmsg() to push a message in the NNG-like wire format
//! (9B SPF | 4B protocol | 2B msg type | 2B size | payload), the receiver
//! replies on the same connection, also with sendmsg(). The protocol field and
//! msg type are randomly generated per message; the reply echoes the protocol
//! id and answers with msg type + 1, as in the real NNG REQ/REP flow. Only
//! sendmsg is used for sending because the SCA eBPF program hooks
//! sys_enter_sendmsg only.
//!
//! Usage:
//!   sca_sim            # launcher: spawns all roles, waits, cleans up on exit
//!   sca_sim <ROLE>     # run a single role (used internally by the launcher)
//!
//! While the launcher runs, pressing SPACE in its terminal pauses sending
//! (SIGSTOP on the initiator) and pressing it again resumes (SIGCONT). All
//! simulator processes stay alive; only the data flow stops.

use std::ffi::CString;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Wire protocol constants (must match what the eBPF program parses).
const NNG_SPF_SIZE: usize = 9;
/// Fixed message size so recv side can read exact frames on a stream socket.
const MSG_SIZE: usize = 64;

const CYCLE_INTERVAL: Duration = Duration::from_millis(1000);
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);
const CONNECT_RETRIES: u32 = 200; // ~20s worst case

/// One hop session of a middle component: receive on `listen_path`,
/// forward to `out_path`, wait reply, reply upstream.
/// `out_path == ""` means: reply immediately without forwarding (DATA_SINK).
struct Session {
    listen_path: &'static str,
    out_path: &'static str,
}

struct Role {
    /// Process name as it appears in /proc/<pid>/comm (max 15 chars).
    name: &'static str,
    sessions: &'static [Session],
    /// If set, this role initiates the chain: connect to this path and
    /// send a fresh request every CYCLE_INTERVAL.
    initiator_out: Option<&'static str>,
    /// Simulated per-component processing latency, applied to every request.
    delay: Duration,
}

const ROLES: &[Role] = &[
    Role {
        name: "DATA_SOURCE",
        sessions: &[],
        initiator_out: Some("/tmp/DATA_L3_TO_INTERNAL_ROUTER"),
        delay: Duration::ZERO,
    },
    Role {
        name: "INTERNAL_ROUTER",
        sessions: &[Session {
            listen_path: "/tmp/DATA_L3_TO_INTERNAL_ROUTER",
            out_path: "/tmp/DATA_L3_TO_WF_L",
        }],
        initiator_out: None,
        delay: Duration::from_millis(5),
    },
    Role {
        name: "RED_WF_COMM_L",
        sessions: &[
            Session {
                listen_path: "/tmp/DATA_L3_TO_WF_L",
                out_path: "/tmp/WF_L_TO_FRAG",
            },
            Session {
                listen_path: "/tmp/FRAG_TO_COMM_WF_L",
                out_path: "/tmp/DATA_L_TO_SINK",
            },
        ],
        initiator_out: None,
        delay: Duration::from_millis(8),
    },
    Role {
        name: "FRAGMENTER",
        sessions: &[
            Session {
                listen_path: "/tmp/WF_L_TO_FRAG",
                out_path: "/tmp/FRAG_TO_IRSS_L",
            },
            Session {
                listen_path: "/tmp/IRSS_L_TO_FRAG",
                out_path: "/tmp/FRAG_TO_COMM_WF_L",
            },
        ],
        initiator_out: None,
        delay: Duration::from_millis(11),
    },
    Role {
        name: "RED_IRSS_COMM_L",
        sessions: &[Session {
            listen_path: "/tmp/FRAG_TO_IRSS_L",
            out_path: "/tmp/IRSS_L_TO_FRAG",
        }],
        initiator_out: None,
        delay: Duration::from_millis(14),
    },
    Role {
        name: "DATA_SINK",
        sessions: &[Session {
            listen_path: "/tmp/DATA_L_TO_SINK",
            out_path: "",
        }],
        initiator_out: None,
        delay: Duration::from_millis(3),
    },
];

/// All socket paths used by the simulation (for cleanup).
const ALL_PATHS: &[&str] = &[
    "/tmp/DATA_L3_TO_INTERNAL_ROUTER",
    "/tmp/DATA_L3_TO_WF_L",
    "/tmp/WF_L_TO_FRAG",
    "/tmp/FRAG_TO_IRSS_L",
    "/tmp/IRSS_L_TO_FRAG",
    "/tmp/FRAG_TO_COMM_WF_L",
    "/tmp/DATA_L_TO_SINK",
];

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Original terminal settings, saved when the launcher switches stdin to
/// keypress mode so they can be restored on exit.
static ORIG_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    let handler = handle_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGHUP, handler);
    }
}

// ---------------------------------------------------------------------------
// Pause control (space bar toggles sending)
// ---------------------------------------------------------------------------

extern "C" fn restore_terminal() {
    if let Ok(mut saved) = ORIG_TERMIOS.lock() {
        if let Some(term) = saved.take() {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term);
            }
        }
    }
}

/// Switch stdin to noncanonical, no-echo mode so a space keypress is
/// delivered immediately, without Enter. Restored at exit via atexit.
fn enable_keypress_mode() {
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
            log(
                "launcher",
                "stdin is not a TTY: use space + Enter to pause/resume",
            );
            return;
        }
        let mut raw = term;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
            return;
        }
        if let Ok(mut saved) = ORIG_TERMIOS.lock() {
            *saved = Some(term);
        }
        libc::atexit(restore_terminal);
    }
}

/// Block on stdin; every space toggles SIGSTOP/SIGCONT on the initiator
/// processes (DATA_SOURCE), pausing/resuming the flow of new requests while
/// all simulator processes stay alive.
fn watch_pause_key(initiator_pids: Vec<u32>) {
    let mut paused = false;
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                byte.as_mut_ptr() as *mut libc::c_void,
                1,
            )
        };
        if n <= 0 {
            return; // stdin closed
        }
        if byte[0] != b' ' {
            continue;
        }
        paused = !paused;
        let sig = if paused { libc::SIGSTOP } else { libc::SIGCONT };
        for &pid in &initiator_pids {
            unsafe {
                libc::kill(pid as libc::pid_t, sig);
            }
        }
        eprintln!(
            "sca_sim: {} - press space to {}",
            if paused { "PAUSED" } else { "RESUMED" },
            if paused { "resume" } else { "pause" }
        );
    }
}

fn set_process_name(name: &str) {
    let cname = CString::new(name).expect("role name contains NUL");
    // PR_SET_NAME truncates to 15 chars; all our role names fit exactly.
    let ret = unsafe { libc::prctl(libc::PR_SET_NAME, cname.as_ptr(), 0, 0, 0) };
    if ret != 0 {
        fatal(&format!("prctl(PR_SET_NAME, {}) failed", name));
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("sca_sim: FATAL: {}", msg);
    std::process::exit(1);
}

fn log(role: &str, msg: &str) {
    eprintln!("sca_sim[{}]: {}", role, msg);
}

// ---------------------------------------------------------------------------
// Socket helpers (raw libc; sendmsg is used for all sends on purpose)
// ---------------------------------------------------------------------------

fn unix_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        fatal(&format!(
            "socket() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    fd
}

fn make_addr(path: &str) -> libc::sockaddr_un {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    assert!(bytes.len() < addr.sun_path.len(), "socket path too long");
    for (i, b) in bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }
    addr
}

fn listen_socket(path: &str) -> i32 {
    let _ = std::fs::remove_file(path); // drop stale socket file
    let fd = unix_socket();
    let addr = make_addr(path);
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        fatal(&format!(
            "bind({}) failed: {}",
            path,
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::listen(fd, 16) } < 0 {
        fatal(&format!(
            "listen({}) failed: {}",
            path,
            std::io::Error::last_os_error()
        ));
    }
    fd
}

fn accept_one(listen_fd: i32, path: &str) -> i32 {
    let fd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if fd < 0 {
        fatal(&format!(
            "accept({}) failed: {}",
            path,
            std::io::Error::last_os_error()
        ));
    }
    fd
}

fn connect_socket(path: &str) -> i32 {
    let fd = unix_socket();
    let addr = make_addr(path);
    for attempt in 0..CONNECT_RETRIES {
        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            return fd;
        }
        if attempt + 1 == CONNECT_RETRIES {
            fatal(&format!(
                "connect({}) failed after {} retries: {}",
                path,
                CONNECT_RETRIES,
                std::io::Error::last_os_error()
            ));
        }
        std::thread::sleep(CONNECT_RETRY_DELAY);
    }
    unreachable!()
}

/// Build one fixed-size wire message: 9B SPF | 4B protocol (BE) | 2B type (BE)
/// | 2B size (BE) | zero payload.
///
/// `protocol` is a per-message identifier, like in the real components; the
/// reply must echo the request's value so the agent can match the pair.
fn build_message(msg_type: u16, protocol: u32) -> [u8; MSG_SIZE] {
    let mut buf = [0u8; MSG_SIZE];
    buf[NNG_SPF_SIZE..NNG_SPF_SIZE + 4].copy_from_slice(&protocol.to_be_bytes());
    buf[NNG_SPF_SIZE + 4..NNG_SPF_SIZE + 6].copy_from_slice(&msg_type.to_be_bytes());
    buf[NNG_SPF_SIZE + 6..NNG_SPF_SIZE + 8].copy_from_slice(&(MSG_SIZE as u16).to_be_bytes());
    buf
}

/// Send one message with sendmsg(2) — the only syscall the SCA eBPF hooks.
fn send_message(fd: i32, msg_type: u16, protocol: u32) {
    let buf = build_message(msg_type, protocol);
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let hdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let sent = unsafe { libc::sendmsg(fd, &hdr, 0) };
    if sent < 0 {
        fatal(&format!(
            "sendmsg() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if sent as usize != buf.len() {
        fatal(&format!("sendmsg() short write: {}/{}", sent, buf.len()));
    }
}

/// Receive exactly one fixed-size message (stream sockets may split reads).
/// Returns (protocol, msg_type) so the reply can echo the protocol id and
/// answer with msg_type + 1, as the real NNG components do.
fn recv_message(fd: i32) -> (u32, u16) {
    let mut buf = [0u8; MSG_SIZE];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - got,
                0,
            )
        };
        if n == 0 {
            fatal("recv(): peer closed connection");
        }
        if n < 0 {
            fatal(&format!(
                "recv() failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        got += n as usize;
    }
    let protocol = u32::from_be_bytes([
        buf[NNG_SPF_SIZE],
        buf[NNG_SPF_SIZE + 1],
        buf[NNG_SPF_SIZE + 2],
        buf[NNG_SPF_SIZE + 3],
    ]);
    let msg_type = u16::from_be_bytes([buf[NNG_SPF_SIZE + 4], buf[NNG_SPF_SIZE + 5]]);
    (protocol, msg_type)
}

// ---------------------------------------------------------------------------
// Role implementations
// ---------------------------------------------------------------------------

fn run_initiator(role: &Role, out_path: &str) {
    let out_fd = connect_socket(out_path);
    log(
        role.name,
        &format!("connected to {}, starting cycle", out_path),
    );
    let mut cycle: u64 = 0;
    while !SHUTDOWN.load(Ordering::SeqCst) {
        // Both protocol (per-message id) and msg_type are randomly generated
        // for every request, like in the real components.
        let protocol = rand::random::<u32>();
        let msg_type = rand::random::<u16>();
        send_message(out_fd, msg_type, protocol);
        recv_message(out_fd); // wait for the REP to come all the way back
        cycle += 1;
        if cycle.is_multiple_of(10) {
            log(role.name, &format!("{} cycles completed", cycle));
        }
        std::thread::sleep(CYCLE_INTERVAL);
    }
}

fn run_worker(role: &Role) {
    // 1. Create all listener sockets first.
    let listeners: Vec<i32> = role
        .sessions
        .iter()
        .map(|s| listen_socket(s.listen_path))
        .collect();
    for s in role.sessions {
        log(role.name, &format!("listening on {}", s.listen_path));
    }

    // 2. Connect all outgoing sockets (retry until the peer is up).
    let outs: Vec<i32> = role
        .sessions
        .iter()
        .filter(|s| !s.out_path.is_empty())
        .map(|s| {
            let fd = connect_socket(s.out_path);
            log(role.name, &format!("connected to {}", s.out_path));
            fd
        })
        .collect();

    // 3. Accept the incoming connections (one per session).
    let ins: Vec<i32> = role
        .sessions
        .iter()
        .zip(listeners.iter())
        .map(|(s, lfd)| {
            let fd = accept_one(*lfd, s.listen_path);
            log(role.name, &format!("accepted peer on {}", s.listen_path));
            fd
        })
        .collect();

    // Map session index -> out fd (sessions without out_path have none).
    let mut out_per_session: Vec<Option<i32>> = Vec::with_capacity(role.sessions.len());
    let mut out_iter = outs.iter();
    for s in role.sessions {
        if s.out_path.is_empty() {
            out_per_session.push(None);
        } else {
            out_per_session.push(Some(*out_iter.next().expect("out fd missing")));
        }
    }

    // 4. One thread per session. A component can appear twice in the chain
    // (e.g. FRAGMENTER is on both the TX and RX paths), so a single-threaded
    // loop would deadlock waiting on a downstream reply that depends on this
    // same process servicing its other socket.
    log(role.name, "entering REQ/REP loop");
    for (idx, _s) in role.sessions.iter().enumerate() {
        let in_fd = ins[idx];
        let out_fd = out_per_session[idx];
        let delay = role.delay;
        std::thread::spawn(move || {
            loop {
                let (protocol, msg_type) = recv_message(in_fd); // REQ from upstream
                std::thread::sleep(delay); // simulated component processing time
                if let Some(out_fd) = out_fd {
                    send_message(out_fd, msg_type, protocol); // forward downstream unchanged
                    recv_message(out_fd); // REP from downstream
                }
                // Reply upstream: same protocol id, msg_type + 1 (NNG REQ/REP convention)
                send_message(in_fd, msg_type.wrapping_add(1), protocol);
            }
        });
    }

    // Park the main thread until a signal arrives; session threads are
    // blocked in recv() and die with the process.
    while !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
    std::process::exit(0);
}

fn run_role(role: &Role) {
    set_process_name(role.name);
    install_signal_handlers();
    log(role.name, &format!("started, pid {}", std::process::id()));
    match role.initiator_out {
        Some(out_path) => run_initiator(role, out_path),
        None => run_worker(role),
    }
}

// ---------------------------------------------------------------------------
// Launcher
// ---------------------------------------------------------------------------

fn cleanup_socket_files() {
    for path in ALL_PATHS {
        let _ = std::fs::remove_file(path);
    }
}

fn run_launcher() {
    install_signal_handlers();
    cleanup_socket_files(); // remove stale sockets from previous runs

    let exe = std::env::current_exe().expect("cannot resolve current exe");
    let mut children: Vec<Child> = Vec::new();
    for role in ROLES {
        // DATA_SOURCE is started last so no requests are sent before the
        // whole chain is wired.
        if role.initiator_out.is_some() {
            continue;
        }
        let child = Command::new(&exe)
            .arg(role.name)
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| fatal(&format!("failed to spawn {}: {}", role.name, e)));
        children.push(child);
    }

    // Wait until every socket file exists, i.e. all listeners are bound.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let all_up = ALL_PATHS.iter().all(|p| std::path::Path::new(p).exists());
        if all_up {
            break;
        }
        if std::time::Instant::now() > deadline {
            cleanup(children);
            fatal("timed out waiting for listener sockets");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Give connecters a moment to finish the connect/accept handshake.
    std::thread::sleep(Duration::from_millis(500));

    // Now start the initiator.
    let mut initiator_pids = Vec::new();
    for role in ROLES {
        if role.initiator_out.is_none() {
            continue;
        }
        let child = Command::new(&exe)
            .arg(role.name)
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| fatal(&format!("failed to spawn {}: {}", role.name, e)));
        initiator_pids.push(child.id());
        children.push(child);
    }

    eprintln!("sca_sim: all roles started ({} processes)", children.len());
    eprintln!(
        "sca_sim: data flowing every {:?} — start bpfagent now",
        CYCLE_INTERVAL
    );

    // Space bar pauses/resumes the initiator (SIGSTOP/SIGCONT) so stalled
    // traffic can be tested without tearing down the pipeline.
    enable_keypress_mode();
    std::thread::spawn(move || watch_pause_key(initiator_pids));
    eprintln!("sca_sim: press SPACE to pause/resume sending");

    // Wait until signaled or a child dies.
    while !SHUTDOWN.load(Ordering::SeqCst) {
        for child in children.iter_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!("sca_sim: child exited with {}", status);
                cleanup(children);
                std::process::exit(1);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    eprintln!("sca_sim: shutting down");
    cleanup(children);
}

fn cleanup(mut children: Vec<Child>) {
    for child in children.iter_mut() {
        unsafe {
            // SIGCONT first: a paused (SIGSTOP'd) child could not act on
            // SIGTERM and child.wait() below would hang.
            libc::kill(child.id() as libc::pid_t, libc::SIGCONT);
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }
    for child in children.iter_mut() {
        let _ = child.wait();
    }
    cleanup_socket_files();
}

fn main() {
    let arg = std::env::args().nth(1);
    match arg {
        None => run_launcher(),
        Some(name) => {
            // Accept the role name even if the OS mangled argv encoding.
            let name_lossy = String::from_utf8_lossy(name.as_bytes()).into_owned();
            match ROLES.iter().find(|r| r.name == name_lossy) {
                Some(role) => run_role(role),
                None => fatal(&format!("unknown role '{}'", name_lossy)),
            }
        }
    }
}
