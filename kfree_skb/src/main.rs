use std::time::Duration;

use aya::{
    maps::{HashMap, MapData},
    programs::TracePoint,
};
use aya_log::EbpfLogger;
use kfree_skb_common::{SkbDropReason, reason_name};
use log::{debug, info, warn};
use tokio::signal;

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
    let mut drop_counts =
        HashMap::<&mut MapData, u32, u64>::try_from(ebpf.map_mut("DROP_COUNTS").unwrap())?;

    println!("Waiting for Ctrl-C... (drops will be displayed periodically)");

    // Display drops every second until Ctrl-C
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\nExiting...");
                break;
            }
            _ = interval.tick() => {
                // Fetch and display current counts
                display_drop_counts(&mut drop_counts)?;
            }
        }
    }

    Ok(())
}

fn display_drop_counts(drop_counts: &mut HashMap<&mut MapData, u32, u64>) -> anyhow::Result<()> {
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
        info!("No drops recorded yet");
    } else {
        info!(
            "Drop counts (total: {}):",
            all_counts.iter().map(|(_, _, c)| *c).sum::<u64>()
        );
        for (reason, name, count) in &all_counts {
            info!("  {:3} ({:30}): {}", reason, name, count);
        }
    }

    Ok(())
}
