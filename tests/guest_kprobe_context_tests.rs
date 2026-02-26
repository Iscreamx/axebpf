#![cfg(all(feature = "runtime", feature = "guest-kprobe"))]

use axebpf::probe::kprobe::handler::build_guest_ctx_for_test;

#[test]
fn guest_ctx_sets_probe_type_and_vm_id() {
    let ctx = build_guest_ctx_for_test(3, false, 0x100, 0x200);
    assert_eq!(ctx.vm_id, 3);
    assert_eq!(ctx.probe_type, 2);
    assert_eq!(ctx.arg0, 0x100);
    assert_eq!(ctx.arg1, 0x200);
}
