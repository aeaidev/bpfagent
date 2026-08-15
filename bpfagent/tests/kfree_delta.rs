//! Tests for the kfree_skb cumulative-counter delta computation.

use std::collections::HashMap;

use bpfagent::programs::kfree_skb::counter_delta;

#[test]
fn first_read_reports_full_value() {
    let mut last = HashMap::new();
    assert_eq!(counter_delta(&mut last, 10, 456), 456);
}

#[test]
fn subsequent_reads_report_only_deltas() {
    let mut last = HashMap::new();
    counter_delta(&mut last, 10, 456);
    assert_eq!(counter_delta(&mut last, 10, 460), 4);
    assert_eq!(counter_delta(&mut last, 10, 460), 0);
    assert_eq!(counter_delta(&mut last, 10, 500), 40);
}

#[test]
fn reasons_are_tracked_independently() {
    let mut last = HashMap::new();
    counter_delta(&mut last, 10, 100);
    counter_delta(&mut last, 64, 50);
    assert_eq!(counter_delta(&mut last, 10, 110), 10);
    assert_eq!(counter_delta(&mut last, 64, 75), 25);
}

#[test]
fn backwards_value_saturates_to_zero() {
    let mut last = HashMap::new();
    counter_delta(&mut last, 10, 100);
    // Map was reset (program reload): counter went backwards
    assert_eq!(counter_delta(&mut last, 10, 5), 0);
    // And the new baseline is used from then on
    assert_eq!(counter_delta(&mut last, 10, 8), 3);
}
