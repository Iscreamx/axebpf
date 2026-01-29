//! Integration tests for kernel symbol table management.
//!
//! Tests symbol initialization and lookup operations.
//!
//! Note: Full symbol lookup tests require a valid kallsyms binary blob,
//! which is not available in the unit test environment. These tests focus
//! on the API behavior and error handling.

#![cfg(feature = "symbols")]

use axebpf::symbols::{self, Error};

// =============================================================================
// Initialization State Tests
// =============================================================================

#[test]
fn test_is_initialized_check() {
    // This test checks the is_initialized function works
    // Note: In multi-test environments, the state may already be initialized
    // from other tests, so we just verify the function is callable
    let _ = symbols::is_initialized();
}

// =============================================================================
// Lookup Without Init Tests
// =============================================================================

#[test]
fn test_lookup_symbol_without_init() {
    // When symbol table is not initialized, lookup should return None
    // Note: If init was called in another test, this may behave differently
    // but it should never panic
    let result = symbols::lookup_symbol(0x1000);
    // Result is either None (not initialized) or Some (if initialized elsewhere)
    let _ = result;
}

#[test]
fn test_lookup_addr_without_init() {
    // When symbol table is not initialized, lookup should return None
    let result = symbols::lookup_addr("nonexistent_symbol");
    // Result is either None (not initialized) or Some (if initialized elsewhere)
    let _ = result;
}

// =============================================================================
// Error Display Tests
// =============================================================================

#[test]
fn test_error_display_already_initialized() {
    let err = Error::AlreadyInitialized;
    let msg = format!("{}", err);
    assert!(msg.contains("already initialized"));
}

#[test]
fn test_error_display_parse_error() {
    let err = Error::ParseError("invalid format");
    let msg = format!("{}", err);
    assert!(msg.contains("invalid format"));
}

#[test]
fn test_error_display_not_initialized() {
    let err = Error::NotInitialized;
    let msg = format!("{}", err);
    assert!(msg.contains("not initialized"));
}

// =============================================================================
// Init Edge Cases
// =============================================================================

#[test]
fn test_init_empty_blob() {
    // Empty blob should fail to parse
    // Note: This test may fail if init was already called successfully
    // in another test (AlreadyInitialized error)
    let result = symbols::init(&[], 0x0, 0x0);
    // Either ParseError (empty/invalid) or AlreadyInitialized
    assert!(result.is_err());
}

#[test]
fn test_init_invalid_blob() {
    // Invalid blob data should fail to parse
    let invalid_data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
    let result = symbols::init(
        // Need to leak to get 'static lifetime for test
        Box::leak(invalid_data.to_vec().into_boxed_slice()),
        0x1000,
        0x2000,
    );
    // Either ParseError or AlreadyInitialized (if another test ran first)
    assert!(result.is_err());
}

// =============================================================================
// Symbol Lookup Edge Cases
// =============================================================================

#[test]
fn test_lookup_symbol_zero_address() {
    let result = symbols::lookup_symbol(0);
    // Should return None for address 0 (or valid result if initialized with data)
    let _ = result;
}

#[test]
fn test_lookup_symbol_max_address() {
    let result = symbols::lookup_symbol(u64::MAX);
    // Should return None for invalid address
    let _ = result;
}

#[test]
fn test_lookup_addr_empty_name() {
    let result = symbols::lookup_addr("");
    // Should return None for empty name
    let _ = result;
}

#[test]
fn test_lookup_addr_long_name() {
    // Test with a very long symbol name (should not crash)
    let long_name = "a".repeat(2048);
    let result = symbols::lookup_addr(&long_name);
    // Should return None (not found)
    let _ = result;
}
