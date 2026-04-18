#![cfg(all(feature = "runtime", feature = "guest-uprobe"))]

use std::sync::{Mutex, MutexGuard};

use axebpf::probe::guest_runtime_state::{
    LiveGuestRuntimeState, LiveGuestRuntimeStateGuard, clear_live_guest_runtime_state_for_test,
    install_live_guest_runtime_state,
};
use axebpf::probe::uprobe::handler::{
    build_uprobe_ctx_for_test, is_guest_user_mode, should_emit_for_filter,
};
use axebpf::probe::uprobe::linux_observer;
use axebpf::probe::uprobe::object;
use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axebpf::probe::uprobe::return_stack::{self, ReturnEntry};
use axebpf::probe::uprobe::{handler, manager};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn lock_test_state() -> MutexGuard<'static, ()> {
    match TEST_GUARD.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn install_current_mm(vm_id: u32, mm: u64) -> LiveGuestRuntimeStateGuard {
    install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id,
        ttbr0_el1: mm,
        ttbr1_el1: 0,
        contextidr_el1: 0,
        sp_el0: 0,
        tpidr_el0: 0,
        guest_spsr: 0,
    })
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
    assert!(!should_emit_for_filter(
        Some(11),
        None,
        None,
        10,
        10,
        "demo"
    ));
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
        instance_id: 1,
        entry_pc: 0x2000,
        return_gva: 0x4000,
        return_hva: 0x8000,
        saved_insn: 0xd65f03c0,
        prog_id: 7,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 10,
        tgid: 10,
        comm: "demo".into(),
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
    clear_live_guest_runtime_state_for_test();
    manager::install_mock_active_probe_for_test(3, 0x400010, 0x8000, 0x12345678, 7, false);
    let _live_state = install_current_mm(3, 0x1000);

    let regs = [0u64; 31];
    let result = handler::handle_guest_brk_for_test(3, 0x400010, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
}

#[test]
fn ret_entry_hit_only_arms_return_site() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(5, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(5, "/usr/bin/demo", "target_fn", 9, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        5,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8000,
        0x12345678,
    )
    .unwrap();
    manager::set_mock_patch_result_for_test(0x9000, 0xd65f03c0, 0);
    let _live_state = install_current_mm(5, 0x1000);

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;
    let result = handler::handle_guest_brk_for_test(5, 0x400010, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_test(5, 0x400010).unwrap().hits,
        0
    );
    let pending = return_stack::list_for_test(5, 0, 0x1000);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].return_gva, 0x5000);
}

#[test]
fn ret_probe_hit_increments_hits_only_on_return() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(6, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(6, "/usr/bin/demo", "target_fn", 10, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        6,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8000,
        0x12345678,
    )
    .unwrap();
    manager::set_mock_patch_result_for_test(0x9000, 0xd65f03c0, 0);
    let _live_state = install_current_mm(6, 0x2000);

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;
    assert!(matches!(
        handler::handle_guest_brk_for_test(6, 0x400010, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert!(handler::handle_software_step());

    let result = handler::handle_guest_brk_for_test(6, 0x5000, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_test(6, 0x400010).unwrap().hits,
        1
    );
    assert!(return_stack::list_for_test(6, 0, 0x2000).is_empty());
}

#[test]
fn ret_probe_overlapping_calls_share_return_brk_refcount() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(7, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(7, "/usr/bin/demo", "target_fn", 11, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        7,
        "/usr/bin/demo",
        0x3000,
        0x400000,
        0,
        0x8000,
        0x12345678,
    )
    .unwrap();
    manager::set_mock_patch_result_for_test(0x9000, 0xd65f03c0, 0);
    let _live_state = install_current_mm(7, 0x3000);

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;

    assert!(matches!(
        handler::handle_guest_brk_for_test(7, 0x400010, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_return_brk_for_test(7, 0x3000, 0x5000)
            .unwrap()
            .refcount,
        1
    );
    assert!(handler::handle_software_step());

    assert!(matches!(
        handler::handle_guest_brk_for_test(7, 0x400010, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_return_brk_for_test(7, 0x3000, 0x5000)
            .unwrap()
            .refcount,
        2
    );
    assert!(handler::handle_software_step());

    assert!(matches!(
        handler::handle_guest_brk_for_test(7, 0x5000, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_test(7, 0x400010).unwrap().hits,
        1
    );
    assert_eq!(
        manager::lookup_return_brk_for_test(7, 0x3000, 0x5000)
            .unwrap()
            .refcount,
        1
    );
    assert!(handler::handle_software_step());

    assert!(matches!(
        handler::handle_guest_brk_for_test(7, 0x5000, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_test(7, 0x400010).unwrap().hits,
        2
    );
    assert!(manager::lookup_return_brk_for_test(7, 0x3000, 0x5000).is_none());
}

#[test]
fn ret_probe_second_mm_reuses_shared_return_brk_patch_state() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(70, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(70, "/usr/bin/demo", "target_fn", 21, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        70,
        "/usr/bin/demo",
        0x3000,
        0x400000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        70,
        "/usr/bin/demo",
        0x4000,
        0x400000,
        0,
        0x8200,
        0x2222_2222,
    )
    .unwrap();

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;

    manager::set_mock_patch_result_for_test(0x9000, 0xd65f_03c0, 0);
    {
        let _live_state = install_current_mm(70, 0x3000);
        assert!(matches!(
            handler::handle_guest_brk_for_test(70, 0x400010, 0, &regs, 0b0000),
            handler::UprobeBrkHandleResult::ProbeHitSingleStep
        ));
        assert!(handler::handle_software_step());
    }
    let first = manager::lookup_return_brk_for_test(70, 0x3000, 0x5000).unwrap();
    assert_eq!(first.return_hva, 0x9000);
    assert_eq!(first.saved_insn, 0xd65f_03c0);
    assert_eq!(first.refcount, 1);

    manager::set_mock_patch_result_for_test(0x9000, 0xd420_0000, 0);
    {
        let _live_state = install_current_mm(70, 0x4000);
        assert!(matches!(
            handler::handle_guest_brk_for_test(70, 0x400010, 0, &regs, 0b0000),
            handler::UprobeBrkHandleResult::ProbeHitSingleStep
        ));
        assert!(handler::handle_software_step());
    }
    let second = manager::lookup_return_brk_for_test(70, 0x4000, 0x5000).unwrap();
    assert_eq!(second.return_hva, first.return_hva);
    assert_eq!(second.saved_insn, first.saved_insn);
    assert_eq!(second.refcount, 2);
}

#[test]
fn non_el0_brk_is_left_unhandled() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    manager::install_mock_active_probe_for_test(4, 0x400010, 0x8000, 0x12345678, 7, false);

    let regs = [0u64; 31];
    let result = handler::handle_guest_brk_for_test(4, 0x400010, 0, &regs, 0b0101);

    assert!(matches!(result, handler::UprobeBrkHandleResult::Unhandled));
}

#[test]
fn non_ret_uprobe_hit_uses_current_mm_instance() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    clear_live_guest_runtime_state_for_test();
    object::load_text_symbols(8, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(8, "/usr/bin/demo", "target_fn", 16, false).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        8,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        8,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8200,
        0x2222_2222,
    )
    .unwrap();
    let _live_state = install_current_mm(8, 0x2000);

    let regs = [0u64; 31];
    let result = handler::handle_guest_brk_for_test(8, 0x400010, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_mm_for_test(8, 0x1000, 0x400010)
            .unwrap()
            .hits,
        0
    );
    assert_eq!(
        manager::lookup_active_for_mm_for_test(8, 0x2000, 0x400010)
            .unwrap()
            .hits,
        1
    );
}

#[test]
fn ret_entry_hit_uses_current_mm_instance_metadata() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    return_stack::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();
    object::load_text_symbols(9, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(9, "/usr/bin/demo", "target_fn", 17, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        9,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8300,
        0x3333_3333,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        9,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8400,
        0x4444_4444,
    )
    .unwrap();
    manager::set_mock_patch_result_for_test(0x9000, 0xd65f03c0, 0);
    let _live_state = install_current_mm(9, 0x2000);

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;
    let result = handler::handle_guest_brk_for_test(9, 0x400010, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert!(return_stack::list_for_test(9, 0, 0x1000).is_empty());
    let pending = return_stack::list_for_test(9, 0, 0x2000);
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].instance_id,
        manager::lookup_active_for_mm_for_test(9, 0x2000, 0x400010)
            .unwrap()
            .instance_id
    );
}

#[test]
fn ret_return_hit_updates_hits_for_matching_mm_instance_only() {
    let _guard = lock_test_state();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    return_stack::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();
    object::load_text_symbols(10, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(10, "/usr/bin/demo", "target_fn", 18, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        10,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8500,
        0x5555_5555,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        10,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8600,
        0x6666_6666,
    )
    .unwrap();
    manager::set_mock_patch_result_for_test(0x9000, 0xd65f03c0, 0);
    let _live_state = install_current_mm(10, 0x2000);

    let mut regs = [0u64; 31];
    regs[30] = 0x5000;
    assert!(matches!(
        handler::handle_guest_brk_for_test(10, 0x400010, 0, &regs, 0b0000),
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert!(handler::handle_software_step());

    let result = handler::handle_guest_brk_for_test(10, 0x5000, 0, &regs, 0b0000);

    assert!(matches!(
        result,
        handler::UprobeBrkHandleResult::ProbeHitSingleStep
    ));
    assert_eq!(
        manager::lookup_active_for_mm_for_test(10, 0x1000, 0x400010)
            .unwrap()
            .hits,
        0
    );
    assert_eq!(
        manager::lookup_active_for_mm_for_test(10, 0x2000, 0x400010)
            .unwrap()
            .hits,
        1
    );
}
