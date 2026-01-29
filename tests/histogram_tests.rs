//! Integration tests for latency histogram.
//!
//! Tests histogram bucket distribution and percentile calculation.

#![cfg(feature = "tracepoint-support")]

use axebpf::tracepoints::histogram::{BUCKET_BOUNDS_NS, BUCKET_LABELS, LatencyHistogram};

// =============================================================================
// Histogram Creation Tests
// =============================================================================

#[test]
fn test_histogram_new() {
    let hist = LatencyHistogram::new();
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.total, 0);
    assert_eq!(snapshot.buckets, [0u64; 8]);
}

#[test]
fn test_histogram_default() {
    let hist = LatencyHistogram::default();
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.total, 0);
}

// =============================================================================
// Bucket Distribution Tests
// =============================================================================

#[test]
fn test_bucket_bounds_count() {
    assert_eq!(BUCKET_BOUNDS_NS.len(), 8);
    assert_eq!(BUCKET_LABELS.len(), 8);
}

#[test]
fn test_bucket_bounds_order() {
    // Bucket bounds should be monotonically increasing
    for i in 0..BUCKET_BOUNDS_NS.len() - 1 {
        assert!(
            BUCKET_BOUNDS_NS[i] < BUCKET_BOUNDS_NS[i + 1],
            "Bucket bounds should be increasing"
        );
    }
}

#[test]
fn test_record_sub_microsecond() {
    let hist = LatencyHistogram::new();
    // 500ns should go to bucket 0 (0-1us)
    hist.record(500);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[0], 1);
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_microsecond_range() {
    let hist = LatencyHistogram::new();
    // 5us (5000ns) should go to bucket 1 (1-10us)
    hist.record(5_000);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[1], 1);
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_millisecond_range() {
    let hist = LatencyHistogram::new();
    // 5ms (5_000_000ns) should go to bucket 4 (1-10ms)
    hist.record(5_000_000);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[4], 1);
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_over_second() {
    let hist = LatencyHistogram::new();
    // 2 seconds should go to bucket 7 (>1s)
    hist.record(2_000_000_000);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[7], 1);
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_multiple_samples() {
    let hist = LatencyHistogram::new();

    // Record samples in different buckets
    hist.record(500); // bucket 0
    hist.record(5_000); // bucket 1
    hist.record(50_000); // bucket 2
    hist.record(500_000); // bucket 3

    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[0], 1);
    assert_eq!(snapshot.buckets[1], 1);
    assert_eq!(snapshot.buckets[2], 1);
    assert_eq!(snapshot.buckets[3], 1);
    assert_eq!(snapshot.total, 4);
}

#[test]
fn test_record_same_bucket_multiple() {
    let hist = LatencyHistogram::new();

    // Record multiple samples in the same bucket
    for _ in 0..10 {
        hist.record(500); // bucket 0
    }

    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[0], 10);
    assert_eq!(snapshot.total, 10);
}

// =============================================================================
// Percentile Calculation Tests
// =============================================================================

#[test]
fn test_percentile_empty_histogram() {
    let hist = LatencyHistogram::new();
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.p50_ns, 0);
    assert_eq!(snapshot.p90_ns, 0);
    assert_eq!(snapshot.p99_ns, 0);
}

#[test]
fn test_percentile_single_bucket() {
    let hist = LatencyHistogram::new();

    // All samples in bucket 0
    for _ in 0..100 {
        hist.record(500);
    }

    let snapshot = hist.snapshot();
    // All percentiles should be at bucket 0 boundary
    assert_eq!(snapshot.p50_ns, BUCKET_BOUNDS_NS[0]);
    assert_eq!(snapshot.p90_ns, BUCKET_BOUNDS_NS[0]);
    assert_eq!(snapshot.p99_ns, BUCKET_BOUNDS_NS[0]);
}

#[test]
fn test_percentile_distributed() {
    let hist = LatencyHistogram::new();

    // 50 samples in bucket 0, 50 in bucket 1
    for _ in 0..50 {
        hist.record(500); // bucket 0
    }
    for _ in 0..50 {
        hist.record(5_000); // bucket 1
    }

    let snapshot = hist.snapshot();
    assert_eq!(snapshot.total, 100);
    // p50 should be at bucket 0 (50% at index 0)
    assert_eq!(snapshot.p50_ns, BUCKET_BOUNDS_NS[0]);
    // p90 should be at bucket 1 (90% requires going past bucket 0)
    assert_eq!(snapshot.p90_ns, BUCKET_BOUNDS_NS[1]);
}

// =============================================================================
// Reset Tests
// =============================================================================

#[test]
fn test_histogram_reset() {
    let hist = LatencyHistogram::new();

    // Record some samples
    hist.record(500);
    hist.record(5_000);
    hist.record(50_000);

    let snapshot_before = hist.snapshot();
    assert_eq!(snapshot_before.total, 3);

    // Reset
    hist.reset();

    let snapshot_after = hist.snapshot();
    assert_eq!(snapshot_after.total, 0);
    assert_eq!(snapshot_after.buckets, [0u64; 8]);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_record_zero_duration() {
    let hist = LatencyHistogram::new();
    hist.record(0);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[0], 1); // Should go to first bucket
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_max_u64() {
    let hist = LatencyHistogram::new();
    hist.record(u64::MAX);
    let snapshot = hist.snapshot();
    assert_eq!(snapshot.buckets[7], 1); // Should go to last bucket
    assert_eq!(snapshot.total, 1);
}

#[test]
fn test_record_bucket_boundary() {
    let hist = LatencyHistogram::new();

    // Record exactly at bucket boundary (1000ns = 1us)
    hist.record(1_000);

    let snapshot = hist.snapshot();
    // 1000ns is NOT less than 1000ns, so it goes to bucket 1
    assert_eq!(snapshot.buckets[1], 1);
}

#[test]
fn test_record_just_below_boundary() {
    let hist = LatencyHistogram::new();

    // Record just below bucket boundary (999ns)
    hist.record(999);

    let snapshot = hist.snapshot();
    // 999ns < 1000ns, so it goes to bucket 0
    assert_eq!(snapshot.buckets[0], 1);
}
