//! Integration tests for eBPF program attachment.
//!
//! Tests attach, detach, and attachment registry operations.

use axebpf::attach::{self, Error};
use axebpf::runtime;

/// Simple program: mov r0, 42; exit
const PROG_RETURN_42: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r0, 42
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

/// Simple program: mov r0, 0; exit
const PROG_RETURN_ZERO: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

// =============================================================================
// Attach Tests
// =============================================================================

#[test]
fn test_attach_success() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:attach_success";

    let result = attach::attach(tracepoint, prog_id);
    assert!(result.is_ok());

    // Cleanup
    let _ = attach::detach(tracepoint);
    let _ = runtime::unload_program(prog_id);
}

#[test]
fn test_attach_program_not_found() {
    let result = attach::attach("test:nonexistent_prog", 99999);
    assert!(matches!(result, Err(Error::ProgramNotFound(99999))));
}

#[test]
fn test_attach_already_attached() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:already_attached";

    // First attach should succeed
    attach::attach(tracepoint, prog_id).unwrap();

    // Second attach to same tracepoint should fail
    let prog_id2 = runtime::load_program(PROG_RETURN_ZERO).unwrap();
    let result = attach::attach(tracepoint, prog_id2);
    assert!(matches!(result, Err(Error::AlreadyAttached(_))));

    // Cleanup
    let _ = attach::detach(tracepoint);
    let _ = runtime::unload_program(prog_id);
    let _ = runtime::unload_program(prog_id2);
}

// =============================================================================
// Detach Tests
// =============================================================================

#[test]
fn test_detach_success() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:detach_success";

    attach::attach(tracepoint, prog_id).unwrap();
    let result = attach::detach(tracepoint);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), prog_id);

    // Cleanup
    let _ = runtime::unload_program(prog_id);
}

#[test]
fn test_detach_not_attached() {
    let result = attach::detach("test:not_attached");
    assert!(matches!(result, Err(Error::NotAttached(_))));
}

// =============================================================================
// Get Attached Tests
// =============================================================================

#[test]
fn test_get_attached_exists() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:get_attached_exists";

    attach::attach(tracepoint, prog_id).unwrap();
    let result = attach::get_attached(tracepoint);

    assert_eq!(result, Some(prog_id));

    // Cleanup
    let _ = attach::detach(tracepoint);
    let _ = runtime::unload_program(prog_id);
}

#[test]
fn test_get_attached_not_exists() {
    let result = attach::get_attached("test:nonexistent");
    assert_eq!(result, None);
}

#[test]
fn test_get_attached_after_detach() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:get_after_detach";

    attach::attach(tracepoint, prog_id).unwrap();
    attach::detach(tracepoint).unwrap();

    let result = attach::get_attached(tracepoint);
    assert_eq!(result, None);

    // Cleanup
    let _ = runtime::unload_program(prog_id);
}

// =============================================================================
// List Attachments Tests
// =============================================================================

#[test]
fn test_list_attachments() {
    let prog_id1 = runtime::load_program(PROG_RETURN_42).unwrap();
    let prog_id2 = runtime::load_program(PROG_RETURN_ZERO).unwrap();
    let tp1 = "test:list_attach_1";
    let tp2 = "test:list_attach_2";

    attach::attach(tp1, prog_id1).unwrap();
    attach::attach(tp2, prog_id2).unwrap();

    let attachments = attach::list_attachments();

    // Check that our attachments are in the list
    let has_tp1 = attachments
        .iter()
        .any(|(name, id)| name == tp1 && *id == prog_id1);
    let has_tp2 = attachments
        .iter()
        .any(|(name, id)| name == tp2 && *id == prog_id2);

    assert!(has_tp1, "tp1 should be in attachments");
    assert!(has_tp2, "tp2 should be in attachments");

    // Cleanup
    let _ = attach::detach(tp1);
    let _ = attach::detach(tp2);
    let _ = runtime::unload_program(prog_id1);
    let _ = runtime::unload_program(prog_id2);
}

// =============================================================================
// Attachment Count Tests
// =============================================================================

#[test]
fn test_attachment_count() {
    let initial_count = attach::attachment_count();

    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:count_test";

    attach::attach(tracepoint, prog_id).unwrap();
    assert_eq!(attach::attachment_count(), initial_count + 1);

    attach::detach(tracepoint).unwrap();
    assert_eq!(attach::attachment_count(), initial_count);

    // Cleanup
    let _ = runtime::unload_program(prog_id);
}

// =============================================================================
// Error Display Tests
// =============================================================================

#[test]
fn test_error_display() {
    let err = Error::TracepointNotFound("test:tp".to_string());
    assert!(format!("{}", err).contains("test:tp"));

    let err = Error::ProgramNotFound(123);
    assert!(format!("{}", err).contains("123"));

    let err = Error::AlreadyAttached("test:attached".to_string());
    assert!(format!("{}", err).contains("test:attached"));

    let err = Error::NotAttached("test:notattached".to_string());
    assert!(format!("{}", err).contains("test:notattached"));
}

// =============================================================================
// Reattach Tests
// =============================================================================

#[test]
fn test_reattach_after_detach() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let tracepoint = "test:reattach";

    // Attach
    attach::attach(tracepoint, prog_id).unwrap();
    assert_eq!(attach::get_attached(tracepoint), Some(prog_id));

    // Detach
    attach::detach(tracepoint).unwrap();
    assert_eq!(attach::get_attached(tracepoint), None);

    // Reattach same program
    attach::attach(tracepoint, prog_id).unwrap();
    assert_eq!(attach::get_attached(tracepoint), Some(prog_id));

    // Cleanup
    let _ = attach::detach(tracepoint);
    let _ = runtime::unload_program(prog_id);
}

#[test]
fn test_attach_different_program_after_detach() {
    let prog_id1 = runtime::load_program(PROG_RETURN_42).unwrap();
    let prog_id2 = runtime::load_program(PROG_RETURN_ZERO).unwrap();
    let tracepoint = "test:different_prog";

    // Attach first program
    attach::attach(tracepoint, prog_id1).unwrap();
    assert_eq!(attach::get_attached(tracepoint), Some(prog_id1));

    // Detach
    attach::detach(tracepoint).unwrap();

    // Attach different program
    attach::attach(tracepoint, prog_id2).unwrap();
    assert_eq!(attach::get_attached(tracepoint), Some(prog_id2));

    // Cleanup
    let _ = attach::detach(tracepoint);
    let _ = runtime::unload_program(prog_id1);
    let _ = runtime::unload_program(prog_id2);
}
