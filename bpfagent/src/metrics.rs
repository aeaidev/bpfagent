use std::io::Read;

use log::{debug, info, warn};
use prometheus::{Encoder, Registry, TextEncoder};

pub async fn run_metrics_server(
    registry: Registry,
    cancel_token: tokio_util::sync::CancellationToken,
    addr: String,
) -> anyhow::Result<()> {
    // Create a simple HTTP server using a blocking approach
    // This is simpler and works with the current tokio version
    std::thread::spawn(move || {
        let server = std::net::TcpListener::bind(&addr).expect("failed to bind metrics server");

        info!("Prometheus metrics server listening on http://{}", addr);

        for stream in server.incoming() {
            match stream {
                Ok(mut stream) => {
                    let registry = registry.clone();
                    // Handle each request synchronously
                    if let Err(e) = handle_http_request(&mut stream, &registry) {
                        debug!("metrics request failed: {e}");
                    }
                }
                Err(e) => {
                    warn!("metrics listener accept failed: {e}");
                }
            }
        }
    });

    // Wait for cancellation
    cancel_token.cancelled().await;
    Ok(())
}

fn handle_http_request(
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
    use std::io::Write;

    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut response_buffer = Vec::new();
    encoder.encode(&metric_families, &mut response_buffer)?;
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
