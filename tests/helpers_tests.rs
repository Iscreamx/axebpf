//! Integration tests for eBPF helper functions.
//!
//! Tests helper registration and basic functionality.

use axebpf::helpers::{self, HelperFn, SUPPORTED_HELPERS, id};
use axebpf::maps::{self, MapDef, MapType};

// =============================================================================
// Helper Registration Tests
// =============================================================================

#[test]
fn test_supported_helpers_count() {
    // Phase 2 requires 6 standard helpers
    assert_eq!(SUPPORTED_HELPERS.len(), 6);
}

#[test]
fn test_get_helper_map_lookup() {
    let helper = helpers::get_helper(id::MAP_LOOKUP_ELEM);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_map_update() {
    let helper = helpers::get_helper(id::MAP_UPDATE_ELEM);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_map_delete() {
    let helper = helpers::get_helper(id::MAP_DELETE_ELEM);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_ktime() {
    let helper = helpers::get_helper(id::KTIME_GET_NS);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_trace_printk() {
    let helper = helpers::get_helper(id::TRACE_PRINTK);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_cpu_id() {
    let helper = helpers::get_helper(id::GET_SMP_PROCESSOR_ID);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_unsupported() {
    // Helper ID 999 should not exist
    let helper = helpers::get_helper(999);
    assert!(helper.is_none());
}

// =============================================================================
// Helper ID Constants Tests
// =============================================================================

#[test]
fn test_helper_ids_match_linux() {
    // Verify our helper IDs match Linux BPF helper IDs
    assert_eq!(id::MAP_LOOKUP_ELEM, 1);
    assert_eq!(id::MAP_UPDATE_ELEM, 2);
    assert_eq!(id::MAP_DELETE_ELEM, 3);
    assert_eq!(id::KTIME_GET_NS, 5);
    assert_eq!(id::TRACE_PRINTK, 6);
    assert_eq!(id::GET_SMP_PROCESSOR_ID, 8);
}

// =============================================================================
// Helper Function Execution Tests (via map operations)
// =============================================================================

#[test]
fn test_map_helpers_integration() {
    // Create a map
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    // Get the helper functions
    let lookup_fn = helpers::get_helper(id::MAP_LOOKUP_ELEM).unwrap();
    let update_fn = helpers::get_helper(id::MAP_UPDATE_ELEM).unwrap();
    let delete_fn = helpers::get_helper(id::MAP_DELETE_ELEM).unwrap();

    let key: u64 = 42;
    let value: u64 = 12345;

    // Test update helper
    let result = update_fn(map_id as u64, key, value, 0, 0);
    assert_eq!(result, 0); // Success

    // Test lookup helper
    let result = lookup_fn(map_id as u64, key, 0, 0, 0);
    assert_eq!(result, 12345);

    // Test delete helper
    let result = delete_fn(map_id as u64, key, 0, 0, 0);
    assert_eq!(result, 0); // Success

    // Verify deleted
    let result = lookup_fn(map_id as u64, key, 0, 0, 0);
    assert_eq!(result, 0); // Not found
}

#[test]
fn test_trace_printk_helper() {
    let printk_fn = helpers::get_helper(id::TRACE_PRINTK).unwrap();
    // Should return 0 and not crash
    let result = printk_fn(12345, 0, 0, 0, 0);
    assert_eq!(result, 0);
}
