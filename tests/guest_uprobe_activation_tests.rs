#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::{linux_observer, process_maps::ProcessMaps};
use axebpf::probe::uprobe::{manager, object};
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn activate_pending_probe_for_runtime_mapping() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/demo", "0000000000000010 T main\n").unwrap();
    manager::attach_symbol(1, "/usr/bin/demo", "main", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        1,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8000,
        0x12345678,
    )
    .unwrap();

    let hit = manager::lookup_active_for_test(1, 0x400010).unwrap();
    assert_eq!(hit.mm, 0x1000);
    assert_eq!(hit.prog_id, 7);
    assert_eq!(hit.saved_insn, 0x12345678);
}

#[test]
fn observer_exec_and_mmap_activate_pending_probe() {
    let _guard = TEST_LOCK.lock().unwrap();
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
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(3, "/usr/bin/demo", "00000000002101c0 T target_fn\n").unwrap();
    manager::attach_symbol(3, "/usr/bin/demo", "target_fn", 9, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        3,
        "/usr/bin/demo",
        0x3000,
        0x210000,
        0,
        0x9000,
        0x12345678,
    )
    .unwrap();

    assert!(manager::lookup_active_for_test(3, 0x2101c0).is_some());
}

#[test]
fn resolve_executable_target_uses_load_segment_metadata() {
    let _guard = TEST_LOCK.lock().unwrap();
    let text = "\
# axvisor-load-segment 0x1000 0x400 0x0 0x5
# axvisor-load-segment 0x3000 0x200 0x400 0x4
0000000000001010 T target_fn\n";
    object::load_text_symbols(4, "/usr/lib/libdemo.so", text).unwrap();

    let addr =
        object::resolve_executable_object_addr(4, "/usr/lib/libdemo.so", "target_fn").unwrap();
    assert_eq!(addr, 0x1010);
    assert!(object::resolve_executable_object_addr(4, "/usr/lib/libdemo.so", "0x3008").is_err());
}

#[test]
fn activate_pending_probe_uses_segment_load_bias_runtime_pc() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(
        5,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x2234 0x900 0x1234 0x5
0000000000002256 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(5, "/usr/lib/libdemo.so", "target_fn", 10, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        5,
        "/usr/lib/libdemo.so",
        0x5000,
        0x500000,
        0x1000,
        0x9100,
        0xface_cafe,
    )
    .unwrap();

    assert!(manager::lookup_active_for_mm_for_test(5, 0x5000, 0x500256).is_some());
}

#[test]
fn same_shared_object_path_in_two_mms_gets_two_runtime_pcs() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(
        6,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x2234 0x900 0x1234 0x5
0000000000002256 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(6, "/usr/lib/libdemo.so", "target_fn", 11, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::activate_for_mapping_for_test(
        6,
        "/usr/lib/libdemo.so",
        0x6000,
        0x500000,
        0x1000,
        0x9200,
        0x1111_0001,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        6,
        "/usr/lib/libdemo.so",
        0x7000,
        0x700000,
        0x1000,
        0x9300,
        0x2222_0002,
    )
    .unwrap();

    assert!(manager::lookup_active_for_mm_for_test(6, 0x6000, 0x500256).is_some());
    assert!(manager::lookup_active_for_mm_for_test(6, 0x7000, 0x700256).is_some());
}

#[test]
fn incompatible_mapping_is_rejected_before_patching() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(
        7,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x3000 0x1000 0x3000 0x5
0000000000003010 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(7, "/usr/lib/libdemo.so", "target_fn", 12, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    // Mapping starts after the target's backing file offset, so this mapping
    // cannot cover object address 0x3010.
    manager::activate_for_mapping_for_test(
        7,
        "/usr/lib/libdemo.so",
        0x8000,
        0x500000,
        0x4000,
        0x9400,
        0x3333_0003,
    )
    .unwrap();

    assert_eq!(manager::instance_count_for_test(7), 0);
}

#[test]
fn try_activate_for_mm_rejects_runtime_pc_outside_mapping_end() {
    let _guard = TEST_LOCK.lock().unwrap();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(
        8,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x1000 0x1000 0x2000 0x5
0000000000001010 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(8, "/usr/lib/libdemo.so", "target_fn", 13, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 8, 80, 80, 0x8800, "libdemo.so");
    maps.apply(axebpf::probe::uprobe::process_maps::ObserverEvent::Mmap {
        vm_id: 8,
        mm: 0x8800,
        start: 0x500000,
        end: 0x500010,
        file_offset: 0x2000,
        guest_path: "/usr/lib/libdemo.so".into(),
    });

    assert_eq!(manager::try_activate_for_mm(&maps, 8, 0x8800).unwrap(), 0);
    assert!(manager::lookup_active_for_mm_for_test(8, 0x8800, 0x500010).is_none());
}
