//! uprobe eBPF program: counts calls to a configured userspace function and
//! snapshots its arguments.
//!
//! The program is attached by userspace (symbol/offset/target/PID are
//! attach-time parameters, no config map needed). On every call it updates
//! the calling process's CallRecord in CALLS: cumulative count plus the six
//! x86_64 SysV argument registers of the most recent call. When userspace
//! configured a string argument in STRING_ARG_MAP (1..=MAX_ARGS), that
//! argument is additionally read as a NUL-terminated C string.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::trace;
use uprobe_common::{CallRecord, ARG_STR_SIZE, MAX_ARGS, STRING_ARG_KEY};

/// Per-process records of calls to the traced function.
/// Key: pid. Value: CallRecord (cumulative count + last call's arguments).
#[map]
pub static CALLS: HashMap<u32, CallRecord> = HashMap::with_max_entries(1024, 0);

/// Configured string argument index (0 = none, 1..=MAX_ARGS = read that
/// argument as a C string), written by userspace at load time; single entry
/// at STRING_ARG_KEY. Disabled when unset.
#[map]
pub static STRING_ARG_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[uprobe]
pub fn uprobe_trace_call(ctx: ProbeContext) -> u32 {
    match trace_call_handler(ctx) {
        Ok(ret) | Err(ret) => ret,
    }
}

/// Count the call for the calling process and snapshot its arguments (the
/// six integer/pointer argument registers of the x86_64 SysV ABI), reading
/// the configured string argument as a C string.
fn trace_call_handler(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Ensure a record exists, then update it in place through the map value
    // pointer.
    if unsafe { CALLS.get(&pid) }.is_none() {
        let zeroed: CallRecord = unsafe { core::mem::zeroed() };
        let _ = CALLS.insert(&pid, &zeroed, 0);
    }
    let Some(record_ptr) = CALLS.get_ptr_mut(&pid) else {
        return Ok(0); // Map full, skip
    };
    let record = unsafe { &mut *record_ptr };

    record.count += 1;
    record.last_ts = unsafe { bpf_ktime_get_ns() };
    record.comm = bpf_get_current_comm().unwrap_or([0; 16]);
    for i in 0..MAX_ARGS {
        record.args[i] = ctx.arg::<u64>(i).unwrap_or(0);
    }

    let string_arg = unsafe { STRING_ARG_MAP.get(&STRING_ARG_KEY).copied().unwrap_or(0) };
    if (1..=MAX_ARGS as u32).contains(&string_arg) {
        let src = record.args[(string_arg - 1) as usize];
        record.arg_str = [0; ARG_STR_SIZE];
        if src != 0 {
            if let Ok(bytes) =
                unsafe { bpf_probe_read_user_str_bytes(src as *const u8, &mut record.arg_str) }
            {
                trace!(
                    &ctx,
                    "uprobe: pid={} string_arg={} len={}",
                    pid,
                    string_arg,
                    bytes.len()
                );
            }
        }
    }
    Ok(0)
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
