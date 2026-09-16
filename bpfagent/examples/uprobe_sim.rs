//! uprobe_sim - test target for the uprobe eBPF program.
//!
//! Calls the exported function `uprobe_sim_target` in a loop with varying
//! arguments so the agent's uprobe program has something to attach to and
//! observe, end to end and without root for the simulator itself:
//!
//! ```bash
//! cargo run -p bpfagent --example uprobe_sim    # note the printed PID/path
//! sudo ./target/debug/bpfagent                  # in another terminal, with a
//!                                               # [ebpf_programs.settings]
//!                                               # pointing at the sim binary
//! ```

use std::{ffi::CString, thread::sleep, time::Duration};

/// Function the uprobe program attaches to. Exported under its plain C name
/// so no demangling is needed; `inline(never)` guarantees a real call
/// instruction (the attach point) at every call site.
///
/// Reads the string argument so all three parameters are observably used:
/// arg 1 and 2 are integers, arg 3 is a C string pointer (trace it with
/// `string_arg = 3`).
#[no_mangle]
#[inline(never)]
pub extern "C" fn uprobe_sim_target(a: u64, b: u64, s: *const u8) -> u64 {
    let mut len = 0u64;
    if !s.is_null() {
        // SAFETY: callers pass a valid NUL-terminated string.
        unsafe {
            while *s.add(len as usize) != 0 {
                len += 1;
            }
        }
    }
    a ^ b ^ len
}

fn main() {
    println!("uprobe_sim: PID {}", std::process::id());
    println!(
        "uprobe_sim: attach with target = \"{}\", symbol = \"uprobe_sim_target\", string_arg = 3",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<this binary>".to_string())
    );

    let message = CString::new("hello from uprobe_sim").unwrap();
    let mut counter = 0u64;
    loop {
        let result = uprobe_sim_target(counter, 0xDEAD_BEEF, message.as_ptr().cast());
        counter = counter.wrapping_add(result & 0xFF).wrapping_add(1);
        sleep(Duration::from_millis(500));
    }
}
