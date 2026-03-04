//! Integration tests for eBPF runtime.
//!
//! Tests program loading, execution, and helper integration.

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
    let program = EbpfProgram::new(PROG_RETURN_42, None);
    assert!(program.is_ok());
}

#[test]
fn test_program_new_empty() {
    let program = EbpfProgram::new(&[], None);
    assert!(program.is_err());
}

#[test]
fn test_program_new_invalid_size() {
    // eBPF instructions are 8 bytes, so 7 bytes is invalid
    let program = EbpfProgram::new(&[0x00; 7], None);
    assert!(program.is_err());
}

#[test]
fn test_program_bytecode() {
    let program = EbpfProgram::new(PROG_RETURN_42, None).unwrap();
    assert_eq!(program.bytecode(), PROG_RETURN_42);
}

#[test]
fn test_execute_return_42() {
    let program = EbpfProgram::new(PROG_RETURN_42, None).unwrap();
    let result = program.execute().unwrap();
    assert_eq!(result, 42);
}

#[test]
fn test_execute_return_zero() {
    let program = EbpfProgram::new(PROG_RETURN_ZERO, None).unwrap();
    let result = program.execute().unwrap();
    assert_eq!(result, 0);
}

#[test]
fn test_execute_with_context() {
    let program = EbpfProgram::new(PROG_RETURN_R1, None).unwrap();
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
    let prog_id = runtime::load_program(PROG_RETURN_42, None);
    assert!(prog_id.is_ok());
}

#[test]
fn test_get_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42, None).unwrap();
    let program = runtime::get_program(prog_id);
    assert!(program.is_some());
}

#[test]
fn test_run_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42, None).unwrap();
    let result = runtime::run_program(prog_id, None).unwrap();
    assert_eq!(result, 42);
}

#[test]
fn test_unload_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42, None).unwrap();
    assert!(runtime::unload_program(prog_id).is_ok());
    assert!(runtime::get_program(prog_id).is_none());
}

#[test]
fn test_run_unloaded_program() {
    let prog_id = runtime::load_program(PROG_RETURN_42, None).unwrap();
    runtime::unload_program(prog_id).unwrap();
    let result = runtime::run_program(prog_id, None);
    assert!(result.is_err());
}

// =============================================================================
// ELF Loading Tests (precompiled programs verification)
// =============================================================================

/// Load printk.o — tracepoint program with a counter map.
#[test]
fn test_load_elf_printk() {
    let elf_bytes = include_bytes!("../../../target/bpf/printk.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(program.is_ok(), "printk.o should load: {:?}", program.err());
    let prog = program.unwrap();
    assert!(!prog.map_fds().is_empty(), "printk should have maps");
    assert!(prog.bytecode().len() >= 16, "bytecode too short: {}", prog.bytecode().len());
}

/// Load hprobe_entry.o — kprobe program capturing PC and args.
#[test]
fn test_load_elf_hprobe_entry() {
    let elf_bytes = include_bytes!("../../../target/bpf/hprobe_entry.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(
        program.is_ok(),
        "hprobe_entry.o should load: {:?}",
        program.err()
    );
    let prog = program.unwrap();
    assert!(!prog.map_fds().is_empty(), "hprobe_entry should have maps");
}

/// Load hprobe_exit.o — kprobe-style return program with a map.
#[test]
fn test_load_elf_hprobe_exit() {
    let elf_bytes = include_bytes!("../../../target/bpf/hprobe_exit.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(program.is_ok(), "hprobe_exit.o should load: {:?}", program.err());
    let prog = program.unwrap();
    assert!(!prog.map_fds().is_empty(), "hprobe_exit should have maps");
}

/// Load printk.o via registry API.
#[test]
fn test_load_program_elf() {
    let elf_bytes = include_bytes!("../../../target/bpf/printk.o");
    let prog_id = runtime::load_program(elf_bytes, None);
    assert!(prog_id.is_ok(), "load_program with ELF should work: {:?}", prog_id.err());
}
