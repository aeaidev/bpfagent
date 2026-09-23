#![no_std]

//! Shared types between the `my_program` eBPF program and its userspace
//! handler. Keep this crate `no_std`-compatible so both sides can use it.

/// Key of the `COUNTERS` map: the process ID (thread-group ID).
pub type Pid = u32;

/// Value of the `COUNTERS` map: number of `sys_enter_openat` events observed
/// for the process since program load.
pub type EventCount = u64;
