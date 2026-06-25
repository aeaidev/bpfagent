#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use kfree_skb_common::SkbDropReason;

// The kfree_skb tracepoint format (from /sys/kernel/tracing/events/skb/kfree_skb/format):
// field:unsigned short protocol;  offset:32; size:2; signed:0;
// field:enum skb_drop_reason reason; offset:36; size:4; signed:0;

// Map to count drops by reason - using interior mutability
#[map]
pub static DROP_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(131, 0);

#[tracepoint]
pub fn kfree_skb(ctx: TracePointContext) -> u32 {
    match unsafe { try_kfree_skb(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kfree_skb(ctx: TracePointContext) -> Result<u32, u32> {
    // Read the reason field at offset 36 using bpf_probe_read_kernel
    // The tracepoint format has reason at offset 36
    let reason_ptr = unsafe { ctx.as_ptr().add(36) } as *const u32;

    // Use bpf_probe_read_kernel to safely read the value
    let reason_raw: u32 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(reason_ptr).map_err(|e| e as u32)? };

    // Convert to our SkbDropReason enum
    let reason: SkbDropReason = reason_raw.into();

    debug!(
        &ctx,
        "kfree_skb called with reason: {} ({})",
        reason_raw,
        reason_name(reason)
    );

    // Increment the counter for this reason
    // The HashMap uses interior mutability, so we don't need mutable reference
    match unsafe { DROP_COUNTS.get(&reason_raw) } {
        Some(count) => {
            // Counter exists, increment it
            let new_count = count.wrapping_add(1);
            DROP_COUNTS
                .insert(&reason_raw, &new_count, 0)
                .map_err(|e| e as u32)?;
        }
        None => {
            // Counter doesn't exist, create it
            DROP_COUNTS
                .insert(&reason_raw, &1u64, 0)
                .map_err(|e| e as u32)?;
        }
    }

    Ok(0)
}

use kfree_skb_common::reason_name;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
