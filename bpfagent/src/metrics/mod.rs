//! Prometheus metrics HTTP server and management

pub mod server;

pub use server::{handle_http_request, run_metrics_server};
