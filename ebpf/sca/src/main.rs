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

// Buffer hash for packet duration tracking
#[map]
pub static BUFFER_HASH: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

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
    // Check if current process is in allowed list
    if !is_allowed_process(&ctx) {
        return Ok(0);
    }

    // Get the socket file descriptor from args[0] (offset 16)
    let fd = unsafe { ctx.read_at::<u64>(16).ok() };
    if let Some(fd) = fd {
        if is_valid_unix_socket(&ctx, fd as u32) {
            debug!(ctx, "sent: fd={}", fd);
            if let Some((buf_ptr, buf_size)) = read_buffer_info(&ctx) {
                read_buffer_data(&ctx, buf_ptr, buf_size, fd as u32);
            }
        }
    }
    Ok(0)
}

/// Generic tracepoint for receive syscalls
fn generic_receive(ctx: TracePointContext) -> Result<u32, u32> {
    // Check if current process is in allowed list
    if !is_allowed_process(&ctx) {
        return Ok(0);
    }

    // Get the socket file descriptor from args[0] (offset 16)
    let fd = unsafe { ctx.read_at::<u64>(16).ok() };
    if let Some(fd) = fd {
        if is_valid_unix_socket(&ctx, fd as u32) {
            debug!(ctx, "received: fd={}", fd);
            if let Some((buf_ptr, buf_size)) = read_buffer_info(&ctx) {
                read_buffer_data(&ctx, buf_ptr, buf_size, fd as u32);
            }
        }
    }
    Ok(0)
}

fn is_valid_unix_socket(_ctx: &TracePointContext, fd: u32) -> bool {
    // Check if fd exists in SOCKET_FD_MAP
    match SOCKET_FD_MAP.get_ptr(&fd) {
        Some(_ptr) => true,
        None => false,
    }
}

fn is_allowed_process(_ctx: &TracePointContext) -> bool {
    match bpf_get_current_comm() {
        Ok(comm) => {
            // Build prefix keys and check against PROCESS_NAMES_MAP
            for len in 1..=comm.len() {
                let mut key: [u8; 16] = [0; 16];
                key[0..len].copy_from_slice(&comm[0..len]);

                if PROCESS_NAMES_MAP.get_ptr(&key).is_some() {
                    return true;
                }
            }
        }
        Err(_) => {}
    }
    false
}

/// Read buffer pointer and size from tracepoint context
fn read_buffer_info(ctx: &TracePointContext) -> Option<(*const u8, usize)> {
    unsafe {
        // Read buffer pointer from args[1] (offset 24)
        let buf_ptr: u64 = ctx.read_at(24).ok()?;

        // Read buffer size from args[2] (offset 32)
        let buf_size: u64 = ctx.read_at(32).ok()?;

        // Check if buffer pointer is valid (non-null)
        if buf_ptr == 0 {
            return None;
        }

        Some((buf_ptr as *const u8, buf_size as usize))
    }
}

/// Read and print buffer data
/// fd: socket file descriptor for logging
fn read_buffer_data(ctx: &TracePointContext, buf_ptr: *const u8, buf_size: usize, fd: u32) {
    debug!(ctx, "read_buffer_data: called");
    unsafe {
        // Limit to 4 bytes for simplicity to reduce stack usage
        let max_print = buf_size.min(4);

        if max_print == 0 {
            debug!(ctx, "max_print is 0, returning");
            return;
        }

        // Create a local buffer to read into
        let mut buf: [u8; 4] = [0; 4];

        debug!(
            ctx,
            "read_buffer_data: buf_ptr=0x{:x}, buf_size={}, max_print={}",
            buf_ptr as usize,
            buf_size,
            max_print
        );

        // Read the buffer using bpf_probe_read_user_buf
        debug!(ctx, "read_buffer_data: calling bpf_probe_read_user_buf");
        match bpf_probe_read_user_buf(buf_ptr, &mut buf[0..max_print]) {
            Ok(()) => {
                debug!(ctx, "read_buffer_data: read successful");
                for i in 0..max_print {
                    debug!(ctx, "byte[{}]: {}", i, buf[i]);
                }

                // Track packet duration with the buffer bytes
                // Note: fd needs to be passed from generic_send/generic_receive
                mesure_packet_duration(ctx, &buf, fd);
            }
            Err(e) => {
                error!(
                    ctx,
                    "read_buffer_data: bpf_probe_read_user_buf failed: {}", e
                );
            }
        }
    }
}

/// Track packet duration by measuring time between first and second occurrence
/// fd: socket file descriptor for logging purposes
fn mesure_packet_duration(ctx: &TracePointContext, buf: &[u8; 4], fd: u32) {
    debug!(ctx, "mesure_packet_duration: called, fd={}", fd);
    unsafe {
        // Read bytes in little-endian order to build the key
        let key = u32::from_le_bytes(*buf);

        // Get current timestamp in nanoseconds
        let timestamp = bpf_ktime_get_ns();
        debug!(
            ctx,
            "mesure_packet_duration: key={:x}, timestamp={}", key, timestamp
        );

        // Check if key already exists using get_ptr (returns Option<*const u64>)
        match BUFFER_HASH.get_ptr(&key) {
            Some(ptr) => {
                // Key exists, read the existing timestamp
                let existing_timestamp = *ptr;
                // Calculate time difference
                let diff = timestamp - existing_timestamp;
                debug!(ctx, "mesure_packet_duration: diff={}", diff);

                // Get process name for logging and latency tracking
                let comm = bpf_get_current_comm().unwrap_or_default();
                let mut pname_key: [u8; 16] = [0; 16];
                let len = comm.len().min(16);
                pname_key[0..len].copy_from_slice(&comm[0..len]);

                // Check if we need to reset latency for this process name (every 2 seconds)
                let current_time = bpf_ktime_get_ns();
                match LATENCY_RESET_TIME.get(&pname_key) {
                    Some(last_reset_time) => {
                        if current_time - *last_reset_time > RESET_INTERVAL_NS {
                            // Reset the latency hash entry and reset time
                            LATENCY_PNAME_HASH.insert(&pname_key, &0, 0).ok();
                            LATENCY_RESET_TIME.insert(&pname_key, &current_time, 0).ok();
                            debug!(ctx, "Reset latency for process at time {}", current_time);
                        }
                    }
                    None => {
                        // First time seeing this process, set reset time
                        LATENCY_RESET_TIME.insert(&pname_key, &current_time, 0).ok();
                    }
                }

                // Update max latency for this process
                debug!(ctx, "LATENCY_PNAME_HASH insert: diff={}", diff);
                match LATENCY_PNAME_HASH.get(&pname_key) {
                    Some(max_latency) => {
                        if diff > *max_latency {
                            LATENCY_PNAME_HASH.insert(&pname_key, &diff, 0).ok();
                            debug!(ctx, "Updated max latency to {} ns", diff);
                        } else {
                            debug!(
                                ctx,
                                "Process existing max {} ns > new diff {} ns", *max_latency, diff
                            );
                        }
                    }
                    None => {
                        LATENCY_PNAME_HASH.insert(&pname_key, &diff, 0).ok();
                        debug!(ctx, "Inserted new entry with {} ns", diff);
                    }
                }

                debug!(
                    ctx,
                    "packet [fd={}] [data={:x}...] duration: {} ns", fd, key, diff
                );
                // Remove the key from HashMap
                match BUFFER_HASH.remove(&key) {
                    Ok(()) => debug!(ctx, "removed key from HashMap"),
                    Err(e) => error!(ctx, "failed to remove key: {}", e),
                }
            }
            None => {
                // Key doesn't exist, insert it
                match BUFFER_HASH.insert(&key, &timestamp, 0) {
                    Ok(()) => debug!(ctx, "inserted key with timestamp"),
                    Err(e) => error!(ctx, "failed to insert: {}", e),
                }
            }
        }
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
