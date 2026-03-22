#![cfg(feature = "guest-uprobe")]

use std::sync::Mutex;

use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axebpf::probe::uprobe::{linux_runtime_observer, manager, object};

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn executable_file_backed_mmap_return_activates_matching_pending_probe() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/ax_uprobe_demo", "0000000000000040 T target_fn\n")
        .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x55,
        0x1000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();
    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x55, 0x1000, true, 0x2000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x55, 0x1000, 0x400000)
        .unwrap();

    assert!(manager::lookup_active_for_test(1, 0x400040).is_some());
}

#[test]
fn executable_mmap_return_activates_pending_probe_after_exec_switches_mm() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/ax_uprobe_demo", "0000000000000040 T target_fn\n")
        .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 9, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x77,
        0x1000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();
    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x77, 0x2000, true, 0x2000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x77, 0x2000, 0x400000)
        .unwrap();

    assert!(maps.lookup_main_text(1, 0x2000).is_some());
    assert!(manager::lookup_active_for_test(1, 0x400040).is_some());
}

#[test]
fn executable_mmap_return_uses_latest_pending_exec_intent_when_proc_token_changes() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/ax_uprobe_demo", "0000000000000040 T target_fn\n")
        .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 11, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x77,
        0x1000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();
    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x88, 0x2000, true, 0x1000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x88, 0x2000, 0x400000)
        .unwrap();

    assert!(maps.lookup_main_text(1, 0x2000).is_some());
    assert!(manager::lookup_active_for_test(1, 0x400040).is_some());
}

#[test]
fn executable_mmap_return_ignores_newer_exec_intent_without_pending_probe() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/ax_uprobe_demo", "0000000000000040 T target_fn\n")
        .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 13, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x77,
        0x1000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();
    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x99,
        0x3000,
        "/bin/busybox",
    )
    .unwrap();
    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x88, 0x2000, true, 0x1000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x88, 0x2000, 0x400000)
        .unwrap();

    assert!(maps.lookup_main_text(1, 0x2000).is_some());
    assert!(manager::lookup_active_for_test(1, 0x400040).is_some());
}

#[test]
fn raw_vma_exec_intent_waits_for_matching_main_mapping_start() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(
        1,
        "/usr/bin/ax_uprobe_demo",
        "# axvisor-main-text-start 0x210000\n00000000002101c0 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 15, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x77,
        0x1000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();
    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x99,
        0x3000,
        "/bin/busybox",
    )
    .unwrap();
    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x88, 0x2000, true, 0x200000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x88, 0x2000, 0x400000)
        .unwrap();
    assert!(manager::lookup_active_for_test(1, 0x2101c0).is_none());

    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0xaa, 0x4000, true, 0x1000, 0x5, 0)
        .unwrap();
    linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0xaa, 0x4000, 0x210000)
        .unwrap();

    assert!(maps.lookup_main_text(1, 0x4000).is_some());
    assert!(manager::lookup_active_for_test(1, 0x2101c0).is_some());
}

#[test]
fn anonymous_or_non_exec_mmap_is_ignored() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    linux_runtime_observer::clear_all_for_test();

    linux_runtime_observer::record_vm_mmap_entry_for_test(1, 0x66, 0x2000, false, 0x1000, 0x1, 0)
        .unwrap();

    assert!(
        linux_runtime_observer::record_vm_mmap_return_for_test(&maps, 1, 0x66, 0x2000, 0x500000)
            .is_ok()
    );
    assert!(maps.lookup_main_text(1, 0x2000).is_none());
}
