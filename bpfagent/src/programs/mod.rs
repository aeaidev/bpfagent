//! eBPF program management, registry, and traits

pub mod iflat;
pub mod irss;
pub mod kfree_skb;
pub mod my_program;
pub mod registry;
pub mod sca;
pub mod traits;
pub mod uprobe;

pub use registry::ProgramRegistry;
pub use traits::{EbpfAccess, EbpfProgram, MetricsDisplay};
