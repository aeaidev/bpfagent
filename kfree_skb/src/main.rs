use std::{sync::Arc, time::Duration};

use aya::{
    maps::{HashMap, MapData},
    programs::TracePoint,
};
use aya_log::EbpfLogger;
/**
 * Copyright (c) 2026 Katim LLC
 * All rights reserved.
 */
use clap::Parser;
use kfree_skb_common::{SkbDropReason, reason_name};
use log::{debug, info, trace, warn};
use prometheus::{Encoder, IntCounterVec, Registry, TextEncoder};
use tokio::signal;
use tokio_util::sync::CancellationToken;

/// Command-line arguments for kfree_skb
#[derive(Parser, Debug)]
#[command(
    name = "kfree_skb",
    author = "Katim LLC",
    version,
    about = "eBPF application that traces kernel packet drops via kfree_skb",
    long_about = None
)]
struct Args {
    /// Metrics server IP address
    #[arg(short = 'i', long, default_value = "127.0.0.1")]
    metrics_ip: String,

    /// Metrics server port
    #[arg(short = 'p', long, default_value = "9090")]
    metrics_port: u16,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::init();

    tokio::runtime::Runtime::new()?.block_on(async move {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // Initialize Prometheus registry
        let registry = Registry::new();
        let metrics = Metrics::new(&registry);

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/kfree_skb"
        )))?;
        match EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }
        let program: &mut TracePoint = ebpf.program_mut("kfree_skb").unwrap().try_into()?;
        program.load()?;
        program.attach("skb", "kfree_skb")?;

        // Get the DROP_COUNTS map
        let drop_counts =
            HashMap::<&mut MapData, u32, u64>::try_from(ebpf.map_mut("DROP_COUNTS").unwrap())?;
        let drop_counts = Arc::new(std::sync::Mutex::new(drop_counts));

        // Initialize cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();
        let cancel_token_metrics = cancel_token.clone();

        // Start metrics server
        tokio::task::spawn(async move {
            let metrics_addr = format!("{}:{}", args.metrics_ip, args.metrics_port);
            if let Err(e) = run_metrics_server(registry, cancel_token_metrics, metrics_addr).await {
                warn!("metrics server error: {e}");
            }
        });

        // Display drops and update metrics every 3 second until Ctrl-C
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    cancel_token.cancel();
                    println!("\nExiting...");
                    break;
                }
                _ = interval.tick() => {
                    // Fetch and display current counts, update Prometheus metrics
                    display_drop_counts(&mut drop_counts.lock().unwrap(), &metrics)?;
                }
            }
        }

        Ok(())
    })
}

/// Prometheus metrics for kfree_skb
struct Metrics {
    total_drops: IntCounterVec,
    drops_by_reason: IntCounterVec,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        let total_drops = IntCounterVec::new(
            prometheus::opts!["kfree_skb_total_drops", "Total number of SKB drops"],
            &["reason"],
        )
        .expect("failed to create total_drops counter");
        registry
            .register(Box::new(total_drops.clone()))
            .expect("failed to register total_drops counter");

        let drops_by_reason = IntCounterVec::new(
            prometheus::opts!["kfree_skb_drops_by_reason", "Number of drops by reason"],
            &["reason_code", "reason_name"],
        )
        .expect("failed to create drops_by_reason counter");
        registry
            .register(Box::new(drops_by_reason.clone()))
            .expect("failed to register drops_by_reason counter");

        Self {
            total_drops,
            drops_by_reason,
        }
    }
}

fn display_drop_counts(
    drop_counts: &mut HashMap<&mut MapData, u32, u64>,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    // Collect all entries from the map
    let mut all_counts = Vec::new();
    for entry in drop_counts.iter() {
        let (reason, count) = entry?;
        let reason_name = reason_name(SkbDropReason::from(reason));
        all_counts.push((reason, reason_name, count));
    }

    // Sort by count (descending)
    all_counts.sort_by(|a, b| b.2.cmp(&a.2));

    if all_counts.is_empty() {
        trace!("No drops recorded yet");
    } else {
        let total: u64 = all_counts.iter().map(|(_, _, c)| *c).sum();
        metrics
            .total_drops
            .with_label_values(&["all"])
            .inc_by(total);

        info!("Drop counts (total: {}):", total);
        for (reason, name, count) in &all_counts {
            info!("  {:3} ({:30}): {}", reason, name, count);
            // Update Prometheus metrics
            metrics
                .drops_by_reason
                .with_label_values(&[&reason.to_string(), name])
                .inc_by(*count);
        }
    }

    Ok(())
}

async fn run_metrics_server(
    registry: Registry,
    cancel_token: CancellationToken,
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
    use std::io::Read;

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
