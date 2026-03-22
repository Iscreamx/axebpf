#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::{manager, object};
use axebpf::probe::uprobe::{linux_observer, process_maps::ProcessMaps};

#[test]
fn activate_pending_probe_for_runtime_mapping() {
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/demo", "0000000000000010 T main\n").unwrap();
    manager::attach_symbol(1, "/usr/bin/demo", "main", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(1, "/usr/bin/demo", 0x1000, 0x400000, 0, 0x8000, 0x12345678)
        .unwrap();

    let hit = manager::lookup_active_for_test(1, 0x400010).unwrap();
    assert_eq!(hit.mm, 0x1000);
    assert_eq!(hit.prog_id, 7);
    assert_eq!(hit.saved_insn, 0x12345678);
}

#[test]
fn observer_exec_and_mmap_activate_pending_probe() {
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(2, "/usr/bin/demo", "0000000000000010 T main\n").unwrap();
    manager::attach_symbol(2, "/usr/bin/demo", "main", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 2, 10, 10, 0x1000, "demo");
    linux_observer::on_mmap(&maps, 2, 0x1000, 0x400000, 0x401000, 0, "/usr/bin/demo");

    assert!(manager::lookup_active_for_test(2, 0x400010).is_some());
}

#[test]
fn activate_pending_probe_accepts_absolute_exec_symbol_value() {
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(3, "/usr/bin/demo", "00000000002101c0 T target_fn\n").unwrap();
    manager::attach_symbol(3, "/usr/bin/demo", "target_fn", 9, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(3, "/usr/bin/demo", 0x3000, 0x210000, 0, 0x9000, 0x12345678)
        .unwrap();

    assert!(manager::lookup_active_for_test(3, 0x2101c0).is_some());
}
