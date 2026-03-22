#![cfg(all(feature = "runtime", feature = "guest-uprobe"))]

use std::sync::{Mutex, MutexGuard};

use axebpf::probe::uprobe::handler::{
    build_uprobe_ctx_for_test, is_guest_user_mode, should_emit_for_filter,
};
use axebpf::probe::uprobe::linux_observer;
use axebpf::probe::uprobe::{handler, manager};
use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axebpf::probe::uprobe::return_stack::{self, ReturnEntry};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn lock_test_state() -> MutexGuard<'static, ()> {
    TEST_GUARD.lock().expect("test state poisoned")
}

#[test]
fn build_uprobe_ctx_sets_user_process_fields() {
    let _guard = lock_test_state();
    let ctx = build_uprobe_ctx_for_test(1, 2, 10, 10, 0x1000, false);
    assert_eq!(ctx.vm_id, 1);
    assert_eq!(ctx.vcpu_id, 2);
    assert_eq!(ctx.probe_type, 5);
    assert_eq!(ctx.arg0, 10);
    assert_eq!(ctx.arg1, 10);
    assert_eq!(ctx.arg2, 0x1000);
}

#[test]
fn filter_rejects_non_target_pid() {
    let _guard = lock_test_state();
    assert!(!should_emit_for_filter(Some(11), None, None, 10, 10, "demo"));
}

#[test]
fn guest_user_mode_accepts_el0t_and_rejects_el1h() {
    let _guard = lock_test_state();
    assert!(is_guest_user_mode(0b0000));
    assert!(!is_guest_user_mode(0b0101));
}

#[test]
fn uretprobe_entry_pushes_return_instance_and_return_hit_pops_it() {
    let _guard = lock_test_state();
    return_stack::clear_all_for_test();
    let entry = ReturnEntry {
        vm_id: 1,
        vcpu_id: 2,
        mm: 0x1000,
        return_gva: 0x4000,
        return_hva: 0x8000,
        saved_insn: 0xd65f03c0,
        prog_id: 7,
    };

    return_stack::push(entry.clone()).unwrap();
    assert_eq!(return_stack::list_for_test(1, 2, 0x1000).len(), 1);

    let popped = return_stack::pop(1, 2, 0x1000, 0x4000).unwrap();
    assert_eq!(popped.return_gva, 0x4000);
    assert!(return_stack::list_for_test(1, 2, 0x1000).is_empty());
}

#[test]
fn linux_observer_updates_process_maps() {
    let _guard = lock_test_state();
    let maps = ProcessMaps::new();

    linux_observer::on_exec(&maps, 1, 10, 10, 0x1000, "demo");
    linux_observer::on_mmap(&maps, 1, 0x1000, 0x400000, 0x401000, 0, "/usr/bin/demo");

    assert!(maps.lookup_pc(1, 0x1000, 0x400010).is_some());

    linux_observer::on_exit_mm(&maps, 1, 0x1000);
    assert!(maps.lookup_pc(1, 0x1000, 0x400010).is_none());
}

#[test]
fn el0_brk_hit_restores_insn_and_requests_single_step() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    manager::install_mock_active_probe_for_test(3, 0x400010, 0x8000, 0x12345678, 7);

    let regs = [0u64; 31];
    let result = handler::handle_guest_brk_for_test(3, 0x400010, 0, &regs, 0b0000);

    assert!(matches!(result, handler::UprobeBrkHandleResult::ProbeHitSingleStep));
}

#[test]
fn non_el0_brk_is_left_unhandled() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    manager::install_mock_active_probe_for_test(4, 0x400010, 0x8000, 0x12345678, 7);

    let regs = [0u64; 31];
    let result = handler::handle_guest_brk_for_test(4, 0x400010, 0, &regs, 0b0101);

    assert!(matches!(result, handler::UprobeBrkHandleResult::Unhandled));
}
