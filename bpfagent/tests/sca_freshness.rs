//! Tests for SCA latency freshness tracking: a PID whose samples stop
//! changing (traffic paused or processes gone) must be dropped from the
//! display instead of being reported forever with its last average.

use std::collections::HashMap;

use bpfagent::programs::sca::partition_fresh;

/// Build a samples map from (pid, sum, count) triples.
fn samples(entries: &[(u32, u64, u64)]) -> HashMap<u32, (u64, u64)> {
    entries
        .iter()
        .map(|&(pid, sum, count)| (pid, (sum, count)))
        .collect()
}

#[test]
fn first_tick_reports_everything_as_fresh() {
    let mut ledger = HashMap::new();
    let (fresh, stale) = partition_fresh(&mut ledger, &samples(&[(100, 5000, 5), (200, 9000, 3)]));
    assert!(stale.is_empty());
    assert_eq!(fresh.len(), 2);
    assert!(fresh.contains(&100) && fresh.contains(&200));
}

#[test]
fn unchanged_counters_are_stale() {
    let mut ledger = HashMap::new();
    partition_fresh(&mut ledger, &samples(&[(100, 5000, 5)]));
    let (fresh, stale) = partition_fresh(&mut ledger, &samples(&[(100, 5000, 5)]));
    assert!(fresh.is_empty());
    assert_eq!(stale, vec![100]);
}

#[test]
fn new_samples_make_pid_fresh_again() {
    // Pause/resume cycle: fresh -> stale (paused) -> fresh (resumed).
    let mut ledger = HashMap::new();
    partition_fresh(&mut ledger, &samples(&[(100, 5000, 5)]));
    partition_fresh(&mut ledger, &samples(&[(100, 5000, 5)]));
    let (fresh, stale) = partition_fresh(&mut ledger, &samples(&[(100, 8000, 7)]));
    assert_eq!(fresh, vec![100]);
    assert!(stale.is_empty());
}

#[test]
fn window_slide_reset_counts_as_fresh() {
    // The eBPF window slide resets sum/count to small values; a count
    // decrease must not be mistaken for staleness.
    let mut ledger = HashMap::new();
    partition_fresh(&mut ledger, &samples(&[(100, 50000, 40)]));
    let (fresh, stale) = partition_fresh(&mut ledger, &samples(&[(100, 1200, 1)]));
    assert_eq!(fresh, vec![100]);
    assert!(stale.is_empty());
}

#[test]
fn vanished_pids_are_dropped_from_ledger() {
    let mut ledger = HashMap::new();
    partition_fresh(&mut ledger, &samples(&[(100, 5000, 5), (200, 9000, 3)]));
    let (fresh, stale) = partition_fresh(&mut ledger, &samples(&[(100, 5000, 5)]));
    assert!(fresh.is_empty());
    assert_eq!(stale, vec![100]);
    assert!(!ledger.contains_key(&200));
}
