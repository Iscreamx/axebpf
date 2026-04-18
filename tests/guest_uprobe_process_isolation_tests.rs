#![cfg(feature = "guest-uprobe")]

use std::sync::{Mutex, MutexGuard, OnceLock};

use axebpf::probe::guest_runtime_state::{
    LiveGuestRuntimeState, LiveGuestRuntimeStateGuard, clear_live_guest_runtime_state_for_test,
    install_live_guest_runtime_state,
};
use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axebpf::probe::uprobe::return_stack;
use axebpf::probe::uprobe::{handler, linux_observer, manager, object};

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn active_count() -> usize {
    manager::list_all()
        .into_iter()
        .filter(|entry| entry.state == manager::UprobeState::Active)
        .count()
}

fn pending_count() -> usize {
    manager::list_all()
        .into_iter()
        .filter(|entry| entry.state == manager::UprobeState::Pending)
        .count()
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
fn same_template_can_activate_for_two_mms() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(31, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(31, "/usr/bin/demo", "target_fn", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        31,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        31,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8200,
        0x2222_2222,
    )
    .unwrap();

    assert_eq!(active_count(), 2);
}

#[test]
fn second_mm_activation_reuses_existing_patch_state() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(37, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(37, "/usr/bin/demo", "target_fn", 13, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        37,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        37,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8200,
        0x2222_2222,
    )
    .unwrap();

    let first = manager::lookup_active_for_mm_for_test(37, 0x1000, 0x400010).unwrap();
    let second = manager::lookup_active_for_mm_for_test(37, 0x2000, 0x400010).unwrap();
    assert_eq!(first.hva, 0x8100);
    assert_eq!(first.saved_insn, 0x1111_1111);
    assert_eq!(second.hva, first.hva);
    assert_eq!(second.saved_insn, first.saved_insn);
    assert_ne!(first.instance_id, second.instance_id);
    assert_eq!(manager::instance_count_for_test(37), 2);
}

#[test]
fn try_activate_for_mm_keeps_template_after_first_activation() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(32, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(32, "/usr/bin/demo", "target_fn", 8, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        32,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8300,
        0x3333_3333,
    )
    .unwrap();

    assert_eq!(pending_count(), 1);
}

#[test]
fn exit_mm_removes_only_instances_for_that_mm() {
    let _guard = test_guard();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(33, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(33, "/usr/bin/demo", "target_fn", 9, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 33, 11, 11, 0x1000, "demo");
    linux_observer::on_mmap(&maps, 33, 0x1000, 0x400000, 0x401000, 0, "/usr/bin/demo");
    linux_observer::on_exec(&maps, 33, 22, 22, 0x2000, "demo");
    linux_observer::on_mmap(&maps, 33, 0x2000, 0x400000, 0x401000, 0, "/usr/bin/demo");

    assert!(manager::lookup_active_for_mm_for_test(33, 0x1000, 0x400010).is_some());
    assert!(manager::lookup_active_for_mm_for_test(33, 0x2000, 0x400010).is_some());

    linux_observer::on_exit_mm(&maps, 33, 0x1000);

    assert!(manager::lookup_active_for_mm_for_test(33, 0x1000, 0x400010).is_none());
    assert!(manager::lookup_active_for_mm_for_test(33, 0x2000, 0x400010).is_some());
}

#[test]
fn exit_removes_only_instances_for_that_pid() {
    let _guard = test_guard();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(34, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(34, "/usr/bin/demo", "target_fn", 10, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 34, 31, 31, 0x3000, "demo");
    linux_observer::on_mmap(&maps, 34, 0x3000, 0x400000, 0x401000, 0, "/usr/bin/demo");
    linux_observer::on_exec(&maps, 34, 42, 42, 0x4000, "demo");
    linux_observer::on_mmap(&maps, 34, 0x4000, 0x400000, 0x401000, 0, "/usr/bin/demo");

    assert_eq!(
        manager::lookup_active_for_mm_for_test(34, 0x3000, 0x400010)
            .unwrap()
            .pid,
        31
    );
    assert_eq!(
        manager::lookup_active_for_mm_for_test(34, 0x4000, 0x400010)
            .unwrap()
            .pid,
        42
    );

    linux_observer::on_exit(&maps, 34, 31);

    assert!(manager::lookup_active_for_mm_for_test(34, 0x3000, 0x400010).is_none());
    assert!(manager::lookup_active_for_mm_for_test(34, 0x4000, 0x400010).is_some());
}

#[test]
fn detach_removes_template_and_all_derived_instances() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(35, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(35, "/usr/bin/demo", "target_fn", 11, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        35,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8500,
        0x5555_5555,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        35,
        "/usr/bin/demo",
        0x2000,
        0x400000,
        0,
        0x8600,
        0x6666_6666,
    )
    .unwrap();

    manager::detach(35, "/usr/bin/demo", "target_fn").unwrap();

    assert_eq!(pending_count(), 0);
    assert_eq!(active_count(), 0);
    assert_eq!(manager::binding_count_for_test(35), 0);
}

#[test]
fn remap_reload_creates_new_instance_id() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(38, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(38, "/usr/bin/demo", "target_fn", 13, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        38,
        "/usr/bin/demo",
        0x7000,
        0x400000,
        0,
        0x8300,
        0x3333_3333,
    )
    .unwrap();
    let first = manager::lookup_active_for_mm_for_test(38, 0x7000, 0x400010).unwrap();

    manager::activate_for_mapping_for_test(
        38,
        "/usr/bin/demo",
        0x7000,
        0x420000,
        0,
        0x8400,
        0x4444_4444,
    )
    .unwrap();
    let second = manager::lookup_active_for_mm_for_test(38, 0x7000, 0x420010).unwrap();

    assert_ne!(first.instance_id, second.instance_id);
}

#[test]
fn exit_mm_cleans_only_target_mm_uretprobe_return_state() {
    let _guard = test_guard();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    return_stack::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();
    object::load_text_symbols(36, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(36, "/usr/bin/demo", "target_fn", 12, true).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 36, 51, 51, 0x5000, "demo");
    linux_observer::on_mmap(&maps, 36, 0x5000, 0x400000, 0x401000, 0, "/usr/bin/demo");
    linux_observer::on_exec(&maps, 36, 62, 62, 0x6000, "demo");
    linux_observer::on_mmap(&maps, 36, 0x6000, 0x400000, 0x401000, 0, "/usr/bin/demo");

    manager::set_mock_patch_result_for_test(0x9100, 0xd65f03c0, 0);
    {
        let _live_state = install_current_mm(36, 0x5000);
        let mut regs = [0u64; 31];
        regs[30] = 0x7000;
        assert!(matches!(
            handler::handle_guest_brk_for_test(36, 0x400010, 0, &regs, 0b0000),
            handler::UprobeBrkHandleResult::ProbeHitSingleStep
        ));
        assert!(handler::handle_software_step());
    }

    manager::set_mock_patch_result_for_test(0x9200, 0xd65f03c0, 0);
    {
        let _live_state = install_current_mm(36, 0x6000);
        let mut regs = [0u64; 31];
        regs[30] = 0x8000;
        assert!(matches!(
            handler::handle_guest_brk_for_test(36, 0x400010, 0, &regs, 0b0000),
            handler::UprobeBrkHandleResult::ProbeHitSingleStep
        ));
        assert!(handler::handle_software_step());
    }

    assert_eq!(return_stack::list_for_test(36, 0, 0x5000).len(), 1);
    assert_eq!(return_stack::list_for_test(36, 0, 0x6000).len(), 1);
    assert!(manager::lookup_return_brk_for_test(36, 0x5000, 0x7000).is_some());
    assert!(manager::lookup_return_brk_for_test(36, 0x6000, 0x8000).is_some());

    linux_observer::on_exit_mm(&maps, 36, 0x5000);

    assert!(return_stack::list_for_test(36, 0, 0x5000).is_empty());
    assert!(manager::lookup_return_brk_for_test(36, 0x5000, 0x7000).is_none());
    assert_eq!(return_stack::list_for_test(36, 0, 0x6000).len(), 1);
    assert!(manager::lookup_return_brk_for_test(36, 0x6000, 0x8000).is_some());
}

#[test]
fn munmap_cleans_only_return_state_owned_by_unloaded_shared_object_instance() {
    let _guard = test_guard();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    handler::clear_state_for_test();
    return_stack::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();
    object::load_text_symbols(
        39,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x2234 0x900 0x1234 0x5
0000000000002256 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(39, "/usr/lib/libdemo.so", "target_fn", 14, true).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 39, 71, 71, 0x7000, "demo");
    linux_observer::on_mmap(
        &maps,
        39,
        0x7000,
        0x500000,
        0x501000,
        0x1000,
        "/usr/lib/libdemo.so",
    );

    manager::set_mock_patch_result_for_test(0x9300, 0xd65f03c0, 0);
    {
        let _live_state = install_current_mm(39, 0x7000);
        let mut regs = [0u64; 31];
        regs[30] = 0x8000;
        assert!(matches!(
            handler::handle_guest_brk_for_test(39, 0x500256, 0, &regs, 0b0000),
            handler::UprobeBrkHandleResult::ProbeHitSingleStep
        ));
        assert!(handler::handle_software_step());
    }

    assert_eq!(return_stack::list_for_test(39, 0, 0x7000).len(), 1);
    assert!(manager::lookup_return_brk_for_test(39, 0x7000, 0x8000).is_some());

    linux_observer::on_munmap(&maps, 39, 0x7000, 0x500000, 0x501000);

    assert!(return_stack::list_for_test(39, 0, 0x7000).is_empty());
    assert!(manager::lookup_return_brk_for_test(39, 0x7000, 0x8000).is_none());
}
