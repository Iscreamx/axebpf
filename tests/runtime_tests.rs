//! Integration tests for eBPF runtime.
//!
//! Tests program loading, execution, and helper integration.

use axebpf::maps::{self, MapDef, MapType};
use axebpf::runtime::{self, EbpfProgram};

/// Simple program: mov r0, 42; exit
/// Returns constant 42.
const PROG_RETURN_42: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r0, 42
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

/// Program: mov r0, 0; exit
/// Returns zero.
const PROG_RETURN_ZERO: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

/// Program: mov r0, r1; exit
/// Returns first argument (context pointer as u64).
const PROG_RETURN_R1: &[u8] = &[
    0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r1
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

// =============================================================================
// EbpfProgram Tests
// =============================================================================

#[test]
fn test_program_new_valid() {
    let program = EbpfProgram::new(PROG_RETURN_42);
    assert!(program.is_ok());
}

#[test]
fn test_program_new_empty() {
    let program = EbpfProgram::new(&[]);
    assert!(program.is_err());
}

#[test]
fn test_program_new_invalid_size() {
    // eBPF instructions are 8 bytes, so 7 bytes is invalid
    let program = EbpfProgram::new(&[0x00; 7]);
    assert!(program.is_err());
}

#[test]
fn test_program_bytecode() {
    let program = EbpfProgram::new(PROG_RETURN_42).unwrap();
    assert_eq!(program.bytecode(), PROG_RETURN_42);
}

#[test]
fn test_execute_return_42() {
    let program = EbpfProgram::new(PROG_RETURN_42).unwrap();
    let result = program.execute().unwrap();
    assert_eq!(result, 42);
}

#[test]
fn test_execute_return_zero() {
    let program = EbpfProgram::new(PROG_RETURN_ZERO).unwrap();
    let result = program.execute().unwrap();
    assert_eq!(result, 0);
}

#[test]
fn test_execute_with_context() {
    let program = EbpfProgram::new(PROG_RETURN_R1).unwrap();
    let mut ctx = [0u8; 16];
    let result = program.execute_with_context(&mut ctx);
    // Program returns r1 which is pointer to ctx
    assert!(result.is_ok());
}

// =============================================================================
// Program Registry Tests
// =============================================================================

#[test]
fn test_load_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42);
    assert!(prog_id.is_ok());
}

#[test]
fn test_get_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let program = runtime::get_program(prog_id);
    assert!(program.is_some());
}

#[test]
fn test_run_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    let result = runtime::run_program(prog_id, None).unwrap();
    assert_eq!(result, 42);
}

#[test]
fn test_unload_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    assert!(runtime::unload_program(prog_id).is_ok());
    assert!(runtime::get_program(prog_id).is_none());
}

#[test]
fn test_run_unloaded_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42).unwrap();
    runtime::unload_program(prog_id).unwrap();
    let result = runtime::run_program(prog_id, None);
    assert!(result.is_err());
}

// =============================================================================
// Legacy API Tests
// =============================================================================

#[test]
fn test_legacy_execute() {
    let result = runtime::execute(PROG_RETURN_42).unwrap();
    assert_eq!(result, 42);
}

#[test]
fn test_legacy_execute_with_mem() {
    let mut mem = [0u8; 32];
    let result = runtime::execute_with_mem(PROG_RETURN_R1, &mut mem);
    assert!(result.is_ok());
}
