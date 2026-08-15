//! BPF Agent - Generic eBPF Program Manager with Prometheus Metrics Export
//!
//! This library contains the implementation of the bpfagent daemon:
//! - `cli`: command-line argument parsing
//! - `config`: TOML configuration loading
//! - `daemon`: daemonization (fork, stdio redirection, session detach)
//! - `app`: program wiring and the main event loop
//! - `metrics`: Prometheus HTTP metrics server
//! - `programs`: eBPF program traits, registry, and program modules
//!
//! The `bpfagent` binary is a thin entry point over these modules.
//!
//! # Programs
//!
//! - `kfree_skb`: Traces kernel packet drops by reason
//! - `sca`: Traces socket communication latency per process

pub mod app;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod metrics;
pub mod programs;
