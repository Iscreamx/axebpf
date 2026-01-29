//! Integration tests for tracepoint statistics.
//!
//! Tests TracepointStats and StatsManager functionality.

#![cfg(feature = "tracepoint-support")]

use axebpf::tracepoints::stats::{StatsManager, TracepointStats};

// =============================================================================
// TracepointStats Creation Tests
// =============================================================================

#[test]
fn test_stats_new() {
    let stats = TracepointStats::new();
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 0);
    assert_eq!(snapshot.total_ns, 0);
    assert_eq!(snapshot.min_ns, 0);
    assert_eq!(snapshot.max_ns, 0);
    assert_eq!(snapshot.avg_ns, 0);
}

// =============================================================================
// Record Hit Tests
// =============================================================================

#[test]
fn test_record_hit() {
    let stats = TracepointStats::new();
    stats.record_hit(1000);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 1);
    // record_hit doesn't update duration stats
    assert_eq!(snapshot.total_ns, 0);
}

#[test]
fn test_record_hit_multiple() {
    let stats = TracepointStats::new();

    for i in 0..10 {
        stats.record_hit(i * 1000);
    }

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 10);
}

// =============================================================================
// Record Duration Tests
// =============================================================================

#[test]
fn test_record_duration() {
    let stats = TracepointStats::new();
    stats.record_duration(1000, 500);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 1);
    assert_eq!(snapshot.total_ns, 500);
    assert_eq!(snapshot.min_ns, 500);
    assert_eq!(snapshot.max_ns, 500);
    assert_eq!(snapshot.avg_ns, 500);
}

#[test]
fn test_record_duration_multiple() {
    let stats = TracepointStats::new();

    stats.record_duration(1000, 100);
    stats.record_duration(2000, 200);
    stats.record_duration(3000, 300);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 3);
    assert_eq!(snapshot.total_ns, 600);
    assert_eq!(snapshot.min_ns, 100);
    assert_eq!(snapshot.max_ns, 300);
    assert_eq!(snapshot.avg_ns, 200);
}

#[test]
fn test_record_duration_min_max_update() {
    let stats = TracepointStats::new();

    // Start with medium value
    stats.record_duration(1000, 500);

    // Record smaller value - min should update
    stats.record_duration(2000, 100);

    // Record larger value - max should update
    stats.record_duration(3000, 900);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.min_ns, 100);
    assert_eq!(snapshot.max_ns, 900);
}

// =============================================================================
// Histogram Integration Tests
// =============================================================================

#[test]
fn test_histogram_snapshot() {
    let stats = TracepointStats::new();

    // Record some durations
    stats.record_duration(1000, 500); // bucket 0
    stats.record_duration(2000, 5_000); // bucket 1

    let hist_snapshot = stats.histogram_snapshot();
    assert_eq!(hist_snapshot.total, 2);
}

// =============================================================================
// Reset Tests
// =============================================================================

#[test]
fn test_stats_reset() {
    let stats = TracepointStats::new();

    stats.record_duration(1000, 500);
    stats.record_duration(2000, 1000);

    let before = stats.snapshot();
    assert_eq!(before.count, 2);

    stats.reset();

    let after = stats.snapshot();
    assert_eq!(after.count, 0);
    assert_eq!(after.total_ns, 0);
    assert_eq!(after.min_ns, 0);
    assert_eq!(after.max_ns, 0);
}

// =============================================================================
// StatsManager Tests
// =============================================================================

#[test]
fn test_stats_manager_new() {
    let manager = StatsManager::new();
    // Should have pre-registered tracepoints
    let snapshots = manager.all_snapshots();
    assert!(!snapshots.is_empty());
}

#[test]
fn test_stats_manager_get_known_tracepoint() {
    let manager = StatsManager::new();

    // Should be able to get pre-registered tracepoints
    let vm_create = manager.get("vmm:vm_create");
    assert!(vm_create.is_some());

    let vcpu_run = manager.get("vmm:vcpu_run_enter");
    assert!(vcpu_run.is_some());
}

#[test]
fn test_stats_manager_get_unknown_tracepoint() {
    let manager = StatsManager::new();

    let unknown = manager.get("unknown:tracepoint");
    assert!(unknown.is_none());
}

#[test]
fn test_stats_manager_all_snapshots() {
    let manager = StatsManager::new();
    let snapshots = manager.all_snapshots();

    // Should include known tracepoints
    let has_vm_create = snapshots.iter().any(|(name, _)| name == "vmm:vm_create");
    let has_vcpu_run = snapshots
        .iter()
        .any(|(name, _)| name == "vmm:vcpu_run_enter");

    assert!(has_vm_create);
    assert!(has_vcpu_run);
}

#[test]
fn test_stats_manager_reset_all() {
    let manager = StatsManager::new();

    // Record some data
    if let Some(stats) = manager.get("vmm:vm_create") {
        stats.record_hit(1000);
        stats.record_hit(2000);
    }

    // Reset all
    manager.reset_all();

    // Verify reset
    if let Some(stats) = manager.get("vmm:vm_create") {
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.count, 0);
    }
}

#[test]
fn test_stats_manager_default() {
    let manager = StatsManager::default();
    let snapshots = manager.all_snapshots();
    assert!(!snapshots.is_empty());
}

// =============================================================================
// StatsSnapshot Tests
// =============================================================================

#[test]
fn test_stats_snapshot_clone() {
    let stats = TracepointStats::new();
    stats.record_duration(1000, 500);

    let snapshot1 = stats.snapshot();
    let snapshot2 = snapshot1.clone();

    assert_eq!(snapshot1.count, snapshot2.count);
    assert_eq!(snapshot1.total_ns, snapshot2.total_ns);
}

#[test]
fn test_stats_snapshot_debug() {
    let stats = TracepointStats::new();
    stats.record_duration(1000, 500);

    let snapshot = stats.snapshot();
    let debug_str = format!("{:?}", snapshot);

    assert!(debug_str.contains("count"));
    assert!(debug_str.contains("500"));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_avg_with_zero_count() {
    let stats = TracepointStats::new();
    let snapshot = stats.snapshot();
    // Should not panic on division by zero
    assert_eq!(snapshot.avg_ns, 0);
}

#[test]
fn test_record_zero_duration() {
    let stats = TracepointStats::new();
    stats.record_duration(1000, 0);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.count, 1);
    assert_eq!(snapshot.min_ns, 0);
    assert_eq!(snapshot.max_ns, 0);
}

#[test]
fn test_record_large_duration() {
    let stats = TracepointStats::new();
    let large_duration = 10_000_000_000u64; // 10 seconds
    stats.record_duration(1000, large_duration);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.max_ns, large_duration);
}
