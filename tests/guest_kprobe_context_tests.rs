#![cfg(all(feature = "runtime", feature = "guest-kprobe"))]

use axebpf::probe::kprobe::handler::build_guest_ctx_for_test;

#[test]
fn guest_ctx_sets_probe_type_and_vm_id() {
    let ctx = build_guest_ctx_for_test(3, false, 0x100, 0x200, &[0u64; 31]);
    assert_eq!(ctx.vm_id, 3);
    assert_eq!(ctx.probe_type, 2);
    assert_eq!(ctx.arg0, 0x100);
    assert_eq!(ctx.arg1, 0x200);
}

#[test]
fn guest_ctx_regs_default_to_zero() {
    let ctx = build_guest_ctx_for_test(1, false, 0x100, 0x200, &[0u64; 31]);
    assert_eq!(ctx.regs, [0u64; 8]);
}

#[test]
fn guest_ctx_regs_are_passed_through() {
    let regs: [u64; 31] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let ctx = build_guest_ctx_for_test(1, false, 0x100, 0x200, &regs);
    assert_eq!(ctx.regs, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    assert_eq!(ctx.arg0, 0x100);
    assert_eq!(ctx.arg1, 0x200);
}
