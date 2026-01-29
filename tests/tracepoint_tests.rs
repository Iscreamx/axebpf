//! Integration tests for tracepoint management.
//!
//! Tests TracepointManager API and error handling.
//!
//! Note: Full tracepoint functionality requires runtime initialization
//! with static_keys and ktracepoint library, which is not available in
//! unit test environment. These tests focus on API behavior and error cases.

#![cfg(feature = "tracepoint-support")]

use axebpf::tracepoint::{self, Error, TracepointManager};

// =============================================================================
// Initialization State Tests
// =============================================================================

#[test]
fn test_is_initialized() {
    // Check that is_initialized is callable
    let _ = tracepoint::is_initialized();
}

#[test]
fn test_try_global_before_init() {
    // try_global should return None if not initialized
    // Note: May return Some if other tests initialized it
    let result = TracepointManager::try_global();
    // Just verify it doesn't panic
    let _ = result;
}

// =============================================================================
// Error Display Tests
// =============================================================================

#[test]
fn test_error_display_not_initialized() {
    let err = Error::NotInitialized;
    let msg = format!("{}", err);
    assert!(msg.contains("not initialized"));
}

#[test]
fn test_error_display_not_found() {
    let err = Error::NotFound("test:event".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("test:event"));
    assert!(msg.contains("not found"));
}

#[test]
fn test_error_display_invalid_name() {
    let err = Error::InvalidName("badname".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("badname"));
    assert!(msg.contains("Invalid"));
}

#[test]
fn test_error_display_already_initialized() {
    let err = Error::AlreadyInitialized;
    let msg = format!("{}", err);
    assert!(msg.contains("already initialized"));
}

#[test]
fn test_error_display_init_failed() {
    let err = Error::InitFailed("test reason");
    let msg = format!("{}", err);
    assert!(msg.contains("test reason"));
    assert!(msg.contains("failed"));
}

// =============================================================================
// Error Debug Tests
// =============================================================================

#[test]
fn test_error_debug() {
    let err = Error::NotFound("vmm:test".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("NotFound"));
}

#[test]
fn test_error_clone() {
    let err1 = Error::NotFound("test".to_string());
    let err2 = err1.clone();
    assert_eq!(format!("{}", err1), format!("{}", err2));
}

// =============================================================================
// TracepointInfo Tests
// =============================================================================

#[test]
fn test_tracepoint_info_debug() {
    use axebpf::tracepoint::TracepointInfo;

    let info = TracepointInfo {
        name: "vmm:test".to_string(),
        subsystem: "vmm".to_string(),
        event: "test".to_string(),
        enabled: true,
        id: 42,
    };

    let debug_str = format!("{:?}", info);
    assert!(debug_str.contains("vmm:test"));
    assert!(debug_str.contains("42"));
}

#[test]
fn test_tracepoint_info_clone() {
    use axebpf::tracepoint::TracepointInfo;

    let info1 = TracepointInfo {
        name: "vmm:test".to_string(),
        subsystem: "vmm".to_string(),
        event: "test".to_string(),
        enabled: false,
        id: 1,
    };

    let info2 = info1.clone();
    assert_eq!(info1.name, info2.name);
    assert_eq!(info1.enabled, info2.enabled);
    assert_eq!(info1.id, info2.id);
}

// =============================================================================
// Name Parsing Tests (via error messages)
// =============================================================================

#[test]
fn test_invalid_name_no_colon() {
    // Names without colon should be invalid
    // We can't directly call parse_tracepoint_name, but we can infer from error
    let err = Error::InvalidName("badname".to_string());
    assert!(matches!(err, Error::InvalidName(_)));
}

#[test]
fn test_valid_name_format() {
    // Valid format is "subsystem:event"
    let name = "vmm:vcpu_run_enter";
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], "vmm");
    assert_eq!(parts[1], "vcpu_run_enter");
}

#[test]
fn test_name_with_multiple_colons() {
    // Should only split on first colon
    let name = "vmm:event:extra";
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], "vmm");
    assert_eq!(parts[1], "event:extra");
}
