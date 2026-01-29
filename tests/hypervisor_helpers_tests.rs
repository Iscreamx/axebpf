//! Integration tests for hypervisor-specific eBPF helpers.
//!
//! Tests helper registration, context management, and helper execution.

#![cfg(all(feature = "runtime", feature = "tracepoint-support"))]

use axebpf::tracepoints::hypervisor_helpers::{
    HYPERVISOR_HELPERS, clear_current_context, get_hypervisor_helper, hypervisor_helper_ids,
    set_current_context,
};

// =============================================================================
// Helper ID Constants Tests
// =============================================================================

#[test]
fn test_hypervisor_helper_ids() {
    assert_eq!(hypervisor_helper_ids::GET_CURRENT_VM_ID, 100);
    assert_eq!(hypervisor_helper_ids::GET_CURRENT_VCPU_ID, 101);
    assert_eq!(hypervisor_helper_ids::GET_EXIT_REASON, 102);
}

#[test]
fn test_hypervisor_helpers_list() {
    assert_eq!(HYPERVISOR_HELPERS.len(), 3);
    assert!(HYPERVISOR_HELPERS.contains(&100));
    assert!(HYPERVISOR_HELPERS.contains(&101));
    assert!(HYPERVISOR_HELPERS.contains(&102));
}

// =============================================================================
// Get Helper Tests
// =============================================================================

#[test]
fn test_get_helper_vm_id() {
    let helper = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_vcpu_id() {
    let helper = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VCPU_ID);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_exit_reason() {
    let helper = get_hypervisor_helper(hypervisor_helper_ids::GET_EXIT_REASON);
    assert!(helper.is_some());
}

#[test]
fn test_get_helper_unsupported() {
    let helper = get_hypervisor_helper(999);
    assert!(helper.is_none());
}

#[test]
fn test_get_helper_standard_id() {
    // Standard helper IDs (1-99) should not be handled by hypervisor helpers
    let helper = get_hypervisor_helper(1);
    assert!(helper.is_none());
}

// =============================================================================
// Context Management Tests
// =============================================================================

#[test]
fn test_set_and_get_context() {
    // Set context
    set_current_context(42, 7, 0x1234);

    // Get helpers
    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();
    let vcpu_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VCPU_ID).unwrap();
    let exit_reason_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_EXIT_REASON).unwrap();

    // Verify context values
    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 42);
    assert_eq!(vcpu_id_fn(0, 0, 0, 0, 0), 7);
    assert_eq!(exit_reason_fn(0, 0, 0, 0, 0), 0x1234);

    // Cleanup
    clear_current_context();
}

#[test]
fn test_clear_context() {
    // Set context first
    set_current_context(1, 2, 3);

    // Clear it
    clear_current_context();

    // Get helpers
    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();
    let vcpu_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VCPU_ID).unwrap();
    let exit_reason_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_EXIT_REASON).unwrap();

    // Should all be zero after clear
    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 0);
    assert_eq!(vcpu_id_fn(0, 0, 0, 0, 0), 0);
    assert_eq!(exit_reason_fn(0, 0, 0, 0, 0), 0);
}

#[test]
fn test_context_update() {
    // Set initial context
    set_current_context(1, 1, 1);

    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();
    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 1);

    // Update context
    set_current_context(99, 88, 77);

    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 99);

    // Cleanup
    clear_current_context();
}

// =============================================================================
// Helper Function Signature Tests
// =============================================================================

#[test]
fn test_helper_ignores_arguments() {
    set_current_context(42, 0, 0);

    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();

    // Should return same value regardless of arguments
    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 42);
    assert_eq!(vm_id_fn(1, 2, 3, 4, 5), 42);
    assert_eq!(
        vm_id_fn(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        42
    );

    clear_current_context();
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_context_max_values() {
    set_current_context(u32::MAX, u32::MAX, u64::MAX);

    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();
    let vcpu_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VCPU_ID).unwrap();
    let exit_reason_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_EXIT_REASON).unwrap();

    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), u32::MAX as u64);
    assert_eq!(vcpu_id_fn(0, 0, 0, 0, 0), u32::MAX as u64);
    assert_eq!(exit_reason_fn(0, 0, 0, 0, 0), u64::MAX);

    clear_current_context();
}

#[test]
fn test_context_zero_values() {
    set_current_context(0, 0, 0);

    let vm_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VM_ID).unwrap();
    let vcpu_id_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_CURRENT_VCPU_ID).unwrap();
    let exit_reason_fn = get_hypervisor_helper(hypervisor_helper_ids::GET_EXIT_REASON).unwrap();

    assert_eq!(vm_id_fn(0, 0, 0, 0, 0), 0);
    assert_eq!(vcpu_id_fn(0, 0, 0, 0, 0), 0);
    assert_eq!(exit_reason_fn(0, 0, 0, 0, 0), 0);
}
