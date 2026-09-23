// SPDX-License-Identifier: MIT OR Apache-2.0
//! Template: eBPF kernel program in Rust for bpfagent (see docs/PLUGINS.md)
//!
//! This is the kernel side of the plugin template; the matching userspace
//! handler is docs/templates/custom.rs. To use it:
//! 1. Copy this file to ebpf/my_program/src/main.rs with the Cargo.toml from
//!    docs/PLUGINS.md step 1 ([[bin]] name = "my_program" is the object name
//!    the userspace handler loads from OUT_DIR)
//! 2. Wire up the build as in docs/PLUGINS.md step 5 (workspace members,
//!    bpfagent/Cargo.toml dependency, bpfagent/build.rs match)
//!
//! The program attaches to the syscalls/sys_enter_openat tracepoint and
//! counts calls per PID in the COUNTERS map. The conventions that matter to
//! the agent:
//! - the function name (`my_handler`) becomes the aya program name:
//!   EbpfProgram::bpf_program_name() and ebpf.program_mut() must match it
//! - the static variable name (COUNTERS) becomes the map name:
//!   ebpf.map("COUNTERS") in the handler must match it
//! - the #[panic_handler] (gated on target_arch = "bpf" so host-side
//!   `cargo check` still works) and the license section are required
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use my_program_common::{EventCount, Pid};

// Counts sys_enter_openat calls per process ID. The userspace handler reads
// this map on every stats tick and exports the values as Prometheus gauges.
#[map]
pub static COUNTERS: HashMap<Pid, EventCount> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn my_handler(ctx: TracePointContext) -> u32 {
    match try_my_handler(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_my_handler(ctx: &TracePointContext) -> Result<u32, u32> {
    // Upper 32 bits of bpf_get_current_pid_tgid() are the thread-group ID,
    // i.e. the PID as userspace knows it. To read tracepoint fields instead,
    // read ctx.as_ptr() at the offsets from the event's
    // /sys/kernel/tracing/events/<category>/<event>/format file with
    // aya_ebpf::helpers::bpf_probe_read_kernel (see ebpf/kfree_skb).
    let pid = (bpf_get_current_pid_tgid() >> 32) as Pid;

    debug!(ctx, "my_handler: openat by pid {}", pid);

    // The HashMap uses interior mutability, so no mutable reference is needed.
    match unsafe { COUNTERS.get(&pid) } {
        Some(count) => {
            COUNTERS
                .insert(&pid, &count.wrapping_add(1), 0)
                .map_err(|e| e as u32)?;
        }
        None => {
            COUNTERS.insert(&pid, &1, 0).map_err(|e| e as u32)?;
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
