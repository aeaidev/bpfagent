//! Tests for the kfree_skb moving-average window over per-tick drop deltas.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bpfagent::programs::kfree_skb::update_window;

#[test]
fn deltas_accumulate_within_window() {
    let mut w = VecDeque::new();
    let t0 = Instant::now();
    assert_eq!(update_window(&mut w, t0, 3), 3);
    assert_eq!(update_window(&mut w, t0 + Duration::from_secs(3), 4), 7);
    assert_eq!(update_window(&mut w, t0 + Duration::from_secs(6), 0), 7);
}

#[test]
fn entries_older_than_the_window_are_evicted() {
    let mut w = VecDeque::new();
    let t0 = Instant::now();
    update_window(&mut w, t0, 10);
    // 11s later, beyond the 10s window: the old entry is gone even with no
    // new drops
    assert_eq!(update_window(&mut w, t0 + Duration::from_secs(11), 0), 0);
}

#[test]
fn rate_decays_as_entries_age_out() {
    let mut w = VecDeque::new();
    let t0 = Instant::now();
    update_window(&mut w, t0, 6);
    update_window(&mut w, t0 + Duration::from_secs(9), 6);
    // At t0+12 the first delta (t0) has aged out, the second (t0+9) remains
    assert_eq!(update_window(&mut w, t0 + Duration::from_secs(12), 0), 6);
}
