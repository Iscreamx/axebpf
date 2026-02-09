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
// ELF Loading Tests (Issue #4 verification)
// =============================================================================

/// Load kprobe_noop.o — simplest possible ELF, no maps, no .text calls.
/// This is the baseline: if this fails, basic ELF loading is broken.
#[test]
fn test_load_elf_kprobe_noop() {
    let elf_bytes = include_bytes!("../../../target/bpf/kprobe_noop.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(program.is_ok(), "kprobe_noop.o should load: {:?}", program.err());
    let prog = program.unwrap();
    // kprobe_noop is just "r0 = 0; exit" so bytecode should be 16 bytes (2 instructions)
    assert!(prog.bytecode().len() >= 16, "bytecode too short: {}", prog.bytecode().len());
}

/// Load kprobe_simple.o — has maps, .text section (memset), R_BPF_64_32 relocs.
/// This was the Issue #4 failing case. Must parse and relocate without error.
#[test]
fn test_load_elf_kprobe_simple() {
    let elf_bytes = include_bytes!("../../../target/bpf/kprobe_simple.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(program.is_ok(), "kprobe_simple.o should load: {:?}", program.err());
    let prog = program.unwrap();
    // Must have maps (SIMPLE_MAP)
    assert!(!prog.map_fds().is_empty(), "kprobe_simple should have maps");
    // Bytecode should include .text section (memset) merged in,
    // so it should be larger than just the kprobe section (45 instructions = 360 bytes)
    assert!(prog.bytecode().len() > 360, "bytecode should include .text: {}", prog.bytecode().len());
}

/// Load kprobe_args.o — has maps, .text section, multiple R_BPF_64_32 relocs.
#[test]
fn test_load_elf_kprobe_args() {
    let elf_bytes = include_bytes!("../../../target/bpf/kprobe_args.o");
    let program = EbpfProgram::new(elf_bytes, None);
    assert!(program.is_ok(), "kprobe_args.o should load: {:?}", program.err());
    let prog = program.unwrap();
    assert!(!prog.map_fds().is_empty(), "kprobe_args should have maps");
}

/// Load kprobe_noop.o via registry API.
#[test]
fn test_load_program_elf() {
    let elf_bytes = include_bytes!("../../../target/bpf/kprobe_noop.o");
    let prog_id = runtime::load_program(elf_bytes, None);
    assert!(prog_id.is_ok(), "load_program with ELF should work: {:?}", prog_id.err());
}
