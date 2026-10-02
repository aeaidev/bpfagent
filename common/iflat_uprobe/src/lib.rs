#![no_std]

// Shared types between user and eBPF code

/// Size of the payload tag used as the TIMESTAMP1_MAP/TIMESTAMP2_MAP key:
/// the first 4 bytes of the UDP/TCP payload, read big-endian. The payload is
/// never rewritten while the kernel and the receiving application move a
/// datagram along, so the tag correlates the RX1 sighting, the RX2 sighting
/// and the function call of one datagram.
pub const KEY_SIZE: usize = 4;

/// Number of integer/pointer argument registers of the x86_64 SysV ABI
/// (rdi, rsi, rdx, rcx, r8, r9); UprobeConfig.arg_index selects one of them.
pub const MAX_ARGS: usize = 6;

/// Single key of the UPROBE_CONFIG_MAP entry holding the UprobeConfig.
pub const UPROBE_CONFIG_KEY: u32 = 0;

/// UprobeConfig.payload_ptr_offset value selecting the direct mode: the
/// argument register points straight at the payload, no pointer chase
/// through a containing struct.
pub const PAYLOAD_PTR_DIRECT: u32 = u32::MAX;

/// Runtime configuration for the uprobe side, written by userspace into
/// UPROBE_CONFIG_MAP at load time: which function argument leads to the
/// payload and where the tag starts relative to it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UprobeConfig {
    /// Argument register leading to the payload (1..=MAX_ARGS; for a C++
    /// method 1 is the hidden `this` pointer, so the first explicit
    /// argument is 2)
    pub arg_index: u32,
    /// Byte offset of the payload pointer within the struct the argument
    /// points to (e.g. offsetof(TxSlot, payload) when the function takes
    /// `TxSlot &slot` and the payload address is the `payload` member);
    /// PAYLOAD_PTR_DIRECT when the argument itself points at the payload
    pub payload_ptr_offset: u32,
    /// Byte offset from the resolved payload pointer to the first payload
    /// byte (the tag starts here)
    pub tag_offset: u32,
}

// Implement Pod for UprobeConfig when compiled for userspace with aya.
// This is safe because UprobeConfig is a plain #[repr(C)] struct of
// integer fields.
#[cfg(feature = "user")]
pub use aya::Pod;

#[cfg(feature = "user")]
unsafe impl Pod for UprobeConfig {}
