//! eBPF program management, registry, and traits

pub mod irss;
pub mod kfree_skb;
pub mod registry;
pub mod sca;
pub mod traits;

pub use registry::ProgramRegistry;
pub use traits::{EbpfAccess, EbpfProgram, MetricsDisplay};
