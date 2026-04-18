#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::return_stack::{self, ReturnEntry};
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn return_stack_isolated_by_vm_vcpu_and_mm() {
    let _guard = TEST_LOCK.lock().unwrap();
    return_stack::clear_all_for_test();

    return_stack::push(ReturnEntry {
        vm_id: 1,
        vcpu_id: 0,
        mm: 0x1000,
        instance_id: 1,
        entry_pc: 0x400010,
        return_gva: 0x5000,
        return_hva: 0x9000,
        saved_insn: 0xd65f03c0,
        prog_id: 7,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 11,
        tgid: 11,
        comm: "demo".into(),
    })
    .unwrap();
    return_stack::push(ReturnEntry {
        vm_id: 1,
        vcpu_id: 1,
        mm: 0x1000,
        instance_id: 2,
        entry_pc: 0x400010,
        return_gva: 0x5000,
        return_hva: 0x9004,
        saved_insn: 0xd65f03c0,
        prog_id: 8,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 12,
        tgid: 12,
        comm: "demo".into(),
    })
    .unwrap();
    return_stack::push(ReturnEntry {
        vm_id: 1,
        vcpu_id: 0,
        mm: 0x2000,
        instance_id: 3,
        entry_pc: 0x400010,
        return_gva: 0x5000,
        return_hva: 0x9008,
        saved_insn: 0xd65f03c0,
        prog_id: 9,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 13,
        tgid: 13,
        comm: "demo".into(),
    })
    .unwrap();

    let popped = return_stack::pop(1, 0, 0x1000, 0x5000).unwrap();
    assert_eq!(popped.prog_id, 7);
    assert!(return_stack::list_for_test(1, 0, 0x1000).is_empty());
    assert_eq!(return_stack::list_for_test(1, 1, 0x1000).len(), 1);
    assert_eq!(return_stack::list_for_test(1, 0, 0x2000).len(), 1);
}

#[test]
fn return_stack_preserves_retprobe_metadata() {
    let _guard = TEST_LOCK.lock().unwrap();
    return_stack::clear_all_for_test();

    return_stack::push(ReturnEntry {
        vm_id: 2,
        vcpu_id: 0,
        mm: 0x3000,
        instance_id: 7,
        entry_pc: 0x400020,
        return_gva: 0x6000,
        return_hva: 0xa000,
        saved_insn: 0xd65f03c0,
        prog_id: 15,
        guest_path: "/usr/bin/ax_uprobe_demo".into(),
        symbol: "target_fn".into(),
        pid: 21,
        tgid: 21,
        comm: "ax_uprobe_demo".into(),
    })
    .unwrap();

    let entry = return_stack::pop(2, 0, 0x3000, 0x6000).unwrap();
    assert_eq!(entry.entry_pc, 0x400020);
    assert_eq!(entry.instance_id, 7);
    assert_eq!(entry.guest_path, "/usr/bin/ax_uprobe_demo");
    assert_eq!(entry.symbol, "target_fn");
    assert_eq!(entry.pid, 21);
    assert_eq!(entry.tgid, 21);
    assert_eq!(entry.comm, "ax_uprobe_demo");
}

#[test]
fn clear_for_instance_removes_only_matching_return_entries() {
    let _guard = TEST_LOCK.lock().unwrap();
    return_stack::clear_all_for_test();

    return_stack::push(ReturnEntry {
        vm_id: 3,
        vcpu_id: 0,
        mm: 0x4000,
        instance_id: 11,
        entry_pc: 0x500010,
        return_gva: 0x7000,
        return_hva: 0xb000,
        saved_insn: 0xd65f03c0,
        prog_id: 20,
        guest_path: "/usr/lib/libdemo.so".into(),
        symbol: "target_fn".into(),
        pid: 31,
        tgid: 31,
        comm: "demo".into(),
    })
    .unwrap();
    return_stack::push(ReturnEntry {
        vm_id: 3,
        vcpu_id: 0,
        mm: 0x4000,
        instance_id: 12,
        entry_pc: 0x600010,
        return_gva: 0x8000,
        return_hva: 0xb004,
        saved_insn: 0xd65f03c0,
        prog_id: 21,
        guest_path: "/usr/lib/libdemo.so".into(),
        symbol: "target_fn".into(),
        pid: 31,
        tgid: 31,
        comm: "demo".into(),
    })
    .unwrap();

    let removed = return_stack::clear_for_instance(3, 12);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].instance_id, 12);

    let remaining = return_stack::list_for_test(3, 0, 0x4000);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].instance_id, 11);
}
