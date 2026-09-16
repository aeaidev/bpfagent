#![no_std]

// Shared types between user and eBPF code

/// Maximum number of function arguments captured per call: the six
/// integer/pointer argument registers of the x86_64 SysV ABI
/// (rdi, rsi, rdx, rcx, r8, r9).
pub const MAX_ARGS: usize = 6;

/// Size of the arg_str buffer in CallRecord: the C string read from the
/// configured string argument (NUL-padded, truncated when longer).
pub const ARG_STR_SIZE: usize = 64;

/// Single key of the STRING_ARG_MAP entry holding the configured string
/// argument index (0 = none, 1..=MAX_ARGS = read that argument as a C
/// string).
pub const STRING_ARG_KEY: u32 = 0;

/// Per-process record of calls to the traced function, keyed by pid in the
/// CALLS map: the cumulative call count plus the arguments of the most
/// recent call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallRecord {
    /// Cumulative number of calls seen for this process since program load
    pub count: u64,
    /// Timestamp in ns (bpf_ktime_get_ns) of the most recent call
    pub last_ts: u64,
    /// Arguments of the most recent call (up to MAX_ARGS register values)
    pub args: [u64; MAX_ARGS],
    /// Command name of the calling thread (NUL-padded)
    pub comm: [u8; 16],
    /// C string read from the configured string argument (NUL-padded);
    /// empty when no string_arg is configured or the read failed
    pub arg_str: [u8; ARG_STR_SIZE],
}

// Implement Pod for CallRecord when compiled for userspace with aya.
// This is safe because CallRecord is a plain #[repr(C)] struct of
// integer fields and byte arrays.
#[cfg(feature = "user")]
pub use aya::Pod;

#[cfg(feature = "user")]
unsafe impl Pod for CallRecord {}
