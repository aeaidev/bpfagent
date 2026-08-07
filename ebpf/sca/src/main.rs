#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_ktime_get_ns, bpf_probe_read_user_buf},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, error};
use sca_common::SOCKET_FD_MAP_MAX_ENTRIES;

/// Socket file descriptors map
#[map]
pub static SOCKET_FD_MAP: HashMap<u32, u8> =
    HashMap::with_max_entries(SOCKET_FD_MAP_MAX_ENTRIES as u32, 0);

// Timestamp map: key = (protocol + msg_type), value = timestamp
#[map]
pub static TIMESTAMP_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Max latency per process name (process name -> max latency in ns)
#[map]
pub static LATENCY_PNAME_HASH: HashMap<[u8; 16], u64> = HashMap::with_max_entries(16, 0);

/// Timestamp of last reset for each process name (process name -> timestamp in ns)
#[map]
pub static LATENCY_RESET_TIME: HashMap<[u8; 16], u64> = HashMap::with_max_entries(16, 0);

/// 2 seconds in nanoseconds
const RESET_INTERVAL_NS: u64 = 20_000_000_000;

/// Process names map for filtering
#[map]
pub static PROCESS_NAMES_MAP: HashMap<[u8; 16], u8> = HashMap::with_max_entries(16, 0);

/// NNG header sizes
const NNG_SPF_SIZE: usize = 9; // NNG SPF (Socket Protocol Framework) header
const NNG_PROTOCOL_SIZE: usize = 4; // Protocol type (REQ/REP)
const NNG_MSG_TYPE_SIZE: usize = 2; // Message type

/// Tracepoint handler macro
macro_rules! tracepoint_handler {
    ($name:ident, $handler:path) => {
        #[tracepoint]
        pub fn $name(ctx: TracePointContext) -> u32 {
            match $handler(ctx) {
                Ok(ret) | Err(ret) => ret,
            }
        }
    };
}

// Send syscalls
tracepoint_handler!(sys_enter_sendmsg, generic_send);
tracepoint_handler!(sys_enter_sendto, generic_send);
tracepoint_handler!(sys_enter_write, generic_send);

// Receive syscalls
tracepoint_handler!(sys_enter_recvfrom, generic_receive);
tracepoint_handler!(sys_enter_read, generic_receive);
tracepoint_handler!(sys_enter_readv, generic_receive);

/// Generic tracepoint for send syscalls
fn generic_send(ctx: TracePointContext) -> Result<u32, u32> {
    // Check if this is an allowed process
    if !is_allowed_process(&ctx) {
        return Ok(0);
    }

    let fd = unsafe { ctx.read_at::<u64>(16).ok() };
    if let Some(fd) = fd {
        if is_valid_unix_socket(&ctx, fd as u32) {
            debug!(ctx, "sent: fd={}", fd);
            if let Some((buf_ptr, buf_size)) = read_buffer_info(&ctx) {
                debug!(ctx, "buf_ptr={}, buf_size={}", buf_ptr as u64, buf_size);
                read_buffer_data(&ctx, buf_ptr, buf_size, fd as u32, true);
            }
        }
    }
    Ok(0)
}

/// Generic tracepoint for receive syscalls
fn generic_receive(ctx: TracePointContext) -> Result<u32, u32> {
    // Check if this is an allowed process
    if !is_allowed_process(&ctx) {
        return Ok(0);
    }

    let fd = unsafe { ctx.read_at::<u64>(16).ok() };
    if let Some(fd) = fd {
        if is_valid_unix_socket(&ctx, fd as u32) {
            debug!(ctx, "received: fd={}", fd);
            if let Some((buf_ptr, buf_size)) = read_buffer_info(&ctx) {
                debug!(ctx, "buf_ptr={}, buf_size={}", buf_ptr as u64, buf_size);
                read_buffer_data(&ctx, buf_ptr, buf_size, fd as u32, false);
            }
        }
    }
    Ok(0)
}

fn is_valid_unix_socket(_ctx: &TracePointContext, fd: u32) -> bool {
    SOCKET_FD_MAP.get_ptr(&fd).is_some()
}

fn is_allowed_process(_ctx: &TracePointContext) -> bool {
    match bpf_get_current_comm() {
        Ok(comm) => (1..=comm.len()).any(|len| {
            let mut key: [u8; 16] = [0; 16];
            key[0..len].copy_from_slice(&comm[0..len]);
            PROCESS_NAMES_MAP.get_ptr(&key).is_some()
        }),
        Err(_) => false,
    }
}

/// Read buffer pointer and size from tracepoint context
fn read_buffer_info(ctx: &TracePointContext) -> Option<(*const u8, usize)> {
    unsafe {
        let buf_ptr: u64 = ctx.read_at(24).ok()?;
        let buf_size: u64 = ctx.read_at(32).ok()?;

        if buf_ptr == 0 {
            return None;
        }

        Some((buf_ptr as *const u8, buf_size as usize))
    }
}

/// Read and process NNG packet data
/// fd: socket file descriptor
/// is_send: true if send operation, false if receive
fn read_buffer_data(
    ctx: &TracePointContext,
    buf_ptr: *const u8,
    buf_size: usize,
    fd: u32,
    is_send: bool,
) {
    unsafe {
        // Read protocol and message type
        let protocol = match read_nng_protocol(ctx, buf_ptr, buf_size) {
            Some(p) => p,
            None => return,
        };
        debug!(ctx, "Protocol: {}", protocol);

        let msg_type = match read_nng_msg_type(ctx, buf_ptr, buf_size) {
            Some(t) => t,
            None => return,
        };
        debug!(ctx, "Message type: {}", msg_type);

        // Create combined key
        let key = create_nng_key(protocol, msg_type, is_send);
        debug!(ctx, "Combined key: {:x}", key);

        // Get current timestamp
        let timestamp = bpf_ktime_get_ns();

        if is_send {
            handle_send(ctx, key, timestamp, fd);
        } else {
            handle_receive(ctx, key, timestamp);
        }
    }
}

/// Read NNG protocol value from buffer
/// Returns None if buffer is too small or read fails
unsafe fn read_nng_protocol(
    ctx: &TracePointContext,
    buf_ptr: *const u8,
    buf_size: usize,
) -> Option<u32> {
    const MIN_PROTOCOL_OFFSET: usize = NNG_SPF_SIZE + NNG_PROTOCOL_SIZE;

    if buf_size < MIN_PROTOCOL_OFFSET {
        debug!(ctx, "Buffer too small for NNG protocol: size={}", buf_size);
        return None;
    }

    let mut protocol_buf: [u8; 4] = [0; 4];
    let protocol_ptr = buf_ptr.add(NNG_SPF_SIZE);
    match bpf_probe_read_user_buf(protocol_ptr, &mut protocol_buf) {
        Ok(()) => Some(u32::from_le_bytes(protocol_buf)),
        Err(e) => {
            error!(ctx, "Failed to read protocol: {}", e);
            None
        }
    }
}

/// Read NNG message type from buffer
/// Returns None if buffer is too small or read fails
unsafe fn read_nng_msg_type(
    ctx: &TracePointContext,
    buf_ptr: *const u8,
    buf_size: usize,
) -> Option<u16> {
    const MIN_MSG_TYPE_OFFSET: usize = NNG_SPF_SIZE + NNG_PROTOCOL_SIZE + NNG_MSG_TYPE_SIZE;

    if buf_size < MIN_MSG_TYPE_OFFSET {
        debug!(
            ctx,
            "Buffer too small for NNG message type: size={}", buf_size
        );
        return None;
    }

    let mut msg_type_buf: [u8; 2] = [0; 2];
    let msg_type_ptr = buf_ptr.add(NNG_SPF_SIZE + NNG_PROTOCOL_SIZE);
    match bpf_probe_read_user_buf(msg_type_ptr, &mut msg_type_buf) {
        Ok(()) => Some(u16::from_le_bytes(msg_type_buf)),
        Err(e) => {
            error!(ctx, "Failed to read message type: {}", e);
            None
        }
    }
}

/// Create combined key from protocol and message type
/// For send: key = (protocol << 16) | msg_type
/// For receive: key = (protocol << 16) | (msg_type + 1)
fn create_nng_key(protocol: u32, msg_type: u16, is_send: bool) -> u64 {
    if is_send {
        (protocol as u64) << 16 | (msg_type as u64)
    } else {
        (protocol as u64) << 16 | ((msg_type + 1) as u64)
    }
}

/// Get process name as key for latency tracking
fn get_process_name_key() -> [u8; 16] {
    let mut key: [u8; 16] = [0; 16];
    if let Ok(comm) = bpf_get_current_comm() {
        let len = comm.len().min(16);
        key[0..len].copy_from_slice(&comm[0..len]);
    }
    key
}

/// Check and reset latency if 2 seconds have elapsed
unsafe fn check_and_reset_latency_if_needed(
    ctx: &TracePointContext,
    pname_key: &[u8; 16],
    current_time: u64,
) {
    unsafe {
        match LATENCY_RESET_TIME.get(pname_key) {
            Some(last_reset_time) => {
                if current_time - *last_reset_time > RESET_INTERVAL_NS {
                    LATENCY_PNAME_HASH.insert(pname_key, &0, 0).ok();
                    LATENCY_RESET_TIME.insert(pname_key, &current_time, 0).ok();
                    debug!(ctx, "Reset latency for process at time {}", current_time);
                }
            }
            None => {
                LATENCY_RESET_TIME.insert(pname_key, &current_time, 0).ok();
            }
        }
    }
}

/// Update max latency for process
unsafe fn update_max_latency(ctx: &TracePointContext, pname_key: &[u8; 16], latency: u64) {
    unsafe {
        match LATENCY_PNAME_HASH.get(pname_key) {
            Some(max_latency) => {
                if latency > *max_latency {
                    LATENCY_PNAME_HASH.insert(pname_key, &latency, 0).ok();
                    debug!(ctx, "Updated max latency to {} ns", latency);
                }
            }
            None => {
                LATENCY_PNAME_HASH.insert(pname_key, &latency, 0).ok();
                debug!(ctx, "Inserted new entry with {} ns", latency);
            }
        }
    }
}

/// Handle send operation: calculate latency and update metrics
unsafe fn handle_send(ctx: &TracePointContext, key: u64, timestamp: u64, fd: u32) {
    match TIMESTAMP_MAP.get(&key) {
        Some(req_timestamp) => {
            let diff = timestamp - *req_timestamp;
            debug!(ctx, "Latency for fd={}: {} ns", fd, diff);

            let pname_key = get_process_name_key();
            check_and_reset_latency_if_needed(ctx, &pname_key, timestamp);
            update_max_latency(ctx, &pname_key, diff);
        }
        None => {
            debug!(
                ctx,
                "No timestamp found for key={:x}, cannot calculate latency", key
            );
        }
    }
    // Clean up the timestamp entry
    TIMESTAMP_MAP.remove(&key).ok();
}

/// Handle receive operation: store timestamp for later calculation
unsafe fn handle_receive(ctx: &TracePointContext, key: u64, timestamp: u64) {
    match TIMESTAMP_MAP.insert(&key, &timestamp, 0) {
        Ok(()) => debug!(
            ctx,
            "Stored timestamp for key={:x}, timestamp={}", key, timestamp
        ),
        Err(e) => error!(ctx, "Failed to store timestamp for key={:x}: {}", key, e),
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
