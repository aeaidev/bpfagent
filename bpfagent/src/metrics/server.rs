//! Prometheus Metrics HTTP Server
//!
//! This module provides a simple HTTP server that exposes eBPF program metrics
//! in Prometheus text format.
//!
//! # Endpoint
//!
//! - `GET /metrics` - Returns metrics in Prometheus text format
//!
//! # Example
//!
//! ```bash
//! curl http://localhost:9101/metrics
//! ```

use std::{io::Read, sync::Arc};

use log::debug;
use prometheus::{Encoder, Registry, TextEncoder};

pub async fn run_metrics_server(
    registry: Arc<Registry>,
    cancel_token: tokio_util::sync::CancellationToken,
    addr: String,
) -> anyhow::Result<()> {
    debug!("Starting metrics server on {}", addr);
    // Use the provided registry for gathering metrics
    std::thread::spawn(move || {
        let server = match std::net::TcpListener::bind(&addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to bind metrics server on {}: {}", addr, e);
                return;
            }
        };

        for stream in server.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Handle each request synchronously using the provided registry
                    if let Err(e) = handle_http_request(&mut stream, &registry) {
                        debug!("metrics request failed: {}", e);
                    }
                }
                Err(e) => {
                    debug!("metrics listener accept failed: {}", e);
                }
            }
        }
    });

    // Wait for cancellation
    cancel_token.cancelled().await;
    Ok(())
}

pub fn handle_http_request(
    stream: &mut std::net::TcpStream,
    registry: &Registry,
) -> anyhow::Result<()> {
    // Read the HTTP request
    let mut buffer = [0u8; 4096];
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);

    // Simple HTTP request parsing
    let method_line = request.lines().next().unwrap_or("");
    let path = method_line.split_whitespace().nth(1).unwrap_or("/");

    // Respond with metrics for /metrics path
    if path == "/metrics" {
        handle_metrics_response(stream, registry)?;
    } else {
        handle_not_found_response(stream)?;
    }

    Ok(())
}

fn handle_metrics_response(
    stream: &mut std::net::TcpStream,
    registry: &Registry,
) -> anyhow::Result<()> {
    let metric_families = registry.gather();
    debug!(
        "registry.gather() returned {} metric families",
        metric_families.len()
    );

    use std::io::Write;

    let mut response_buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut response_buffer)?;
    debug!("response_buffer length: {}", response_buffer.len());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
        response_buffer.len(),
        String::from_utf8_lossy(&response_buffer)
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn handle_not_found_response(stream: &mut std::net::TcpStream) -> anyhow::Result<()> {
    use std::io::Write;

    let response =
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found";
    stream.write_all(response.as_bytes())?;
    Ok(())
}
