/**
 * Copyright (c) 2026 Katim LLC
 * All rights reserved.
 */
use std::sync::{Arc, Mutex};

use axum::{Router, routing::get};
use aya::{
    maps::{HashMap, MapData},
    programs::TracePoint,
};
use aya_log::EbpfLogger;
use kfree_skb_common::{SkbDropReason, reason_name};
use log::{debug, info};
use serde::Serialize;

#[derive(Serialize)]
struct DropCount {
    reason: u32,
    name: String,
    count: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kfree_skb_net"
    )))?;
    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            log::warn!("failed to initialize eBPF logger: {e}");
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

    // Store both in Arc<Mutex> - this ensures both are kept alive
    let state = Arc::new(Mutex::new((drop_counts, ebpf)));

    // Spawn the HTTP server
    let state_http = Arc::clone(&state);
    let app = Router::new()
        .route("/metrics", get(move || metrics_handler(state_http)))
        .route("/", get(|| async { "kfree_skb-net Prometheus Exporter" }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9102").await?;
    info!("Prometheus exporter listening on port 9102");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn metrics_handler(
    state: Arc<Mutex<(HashMap<&mut MapData, u32, u64>, aya::Ebpf)>>,
) -> String {
    let mut all_counts = Vec::new();

    {
        let counts = state.lock().unwrap();
        for entry in counts.0.iter() {
            if let Ok((reason, count)) = entry {
                let reason_name = reason_name(SkbDropReason::from(reason));
                all_counts.push(DropCount {
                    reason,
                    name: reason_name.to_string(),
                    count,
                });
            }
        }
    }

    // Sort by count (descending)
    all_counts.sort_by(|a, b| b.count.cmp(&a.count));

    // Generate Prometheus metrics format
    let mut metrics = String::new();
    metrics.push_str("# HELP kfree_skb_drops_total Number of packet drops by reason\n");
    metrics.push_str("# TYPE kfree_skb_drops_total counter\n");

    for dc in &all_counts {
        metrics.push_str(&format!(
            "kfree_skb_drops_total{{reason=\"{}\",reason_id=\"{}\"}} {}\n",
            dc.name, dc.reason, dc.count
        ));
    }

    // Add a summary metric
    let total: u64 = all_counts.iter().map(|dc| dc.count).sum();
    metrics.push_str(&format!(
        "\n# HELP kfree_skb_drops_total_summary Total packet drops\n"
    ));
    metrics.push_str("# TYPE kfree_skb_drops_total_summary counter\n");
    metrics.push_str(&format!("kfree_skb_drops_total_summary {}\n", total));

    metrics
}
