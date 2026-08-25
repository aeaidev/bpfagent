//! Tests for the IRSS cumulative-accumulator delta and per-tick average
//! latency computation.

use bpfagent::programs::irss::{avg_latency_us, latency_deltas};

#[test]
fn first_read_reports_full_values() {
    let (mut last_sum, mut last_count) = (0, 0);
    assert_eq!(
        latency_deltas(&mut last_sum, &mut last_count, 456, 3),
        (456, 3)
    );
}

#[test]
fn subsequent_reads_report_only_deltas() {
    let (mut last_sum, mut last_count) = (0, 0);
    latency_deltas(&mut last_sum, &mut last_count, 1000, 2);
    assert_eq!(
        latency_deltas(&mut last_sum, &mut last_count, 1500, 3),
        (500, 1)
    );
    assert_eq!(
        latency_deltas(&mut last_sum, &mut last_count, 1500, 3),
        (0, 0)
    );
}

#[test]
fn backwards_values_saturate_to_zero() {
    let (mut last_sum, mut last_count) = (0, 0);
    latency_deltas(&mut last_sum, &mut last_count, 1000, 2);
    // Maps were reset (program reload): accumulators went backwards
    assert_eq!(
        latency_deltas(&mut last_sum, &mut last_count, 50, 1),
        (0, 0)
    );
    // And the new baseline is used from then on
    assert_eq!(
        latency_deltas(&mut last_sum, &mut last_count, 150, 2),
        (100, 1)
    );
}

#[test]
fn average_is_none_without_samples() {
    assert_eq!(avg_latency_us(0, 0), None);
    // Leftover sum with no new samples still means no average
    assert_eq!(avg_latency_us(123, 0), None);
}

#[test]
fn average_converts_ns_to_us() {
    // 2 samples totaling 2_500_000 ns -> 1250 us average
    assert_eq!(avg_latency_us(2_500_000, 2), Some(1250));
    // Sub-microsecond averages truncate to 0
    assert_eq!(avg_latency_us(999, 1), Some(0));
}
