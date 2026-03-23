#![cfg(feature = "guest-uprobe")]

use std::string::String;
use std::sync::{Mutex, MutexGuard, OnceLock};

use axebpf::probe::uprobe::return_stack::{self, ReturnEntry};
use axebpf::probe::uprobe::{manager, object};

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[test]
fn attach_by_guest_path_and_symbol_registers_pending_probe() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/demo", "0000000000000010 T main\n").unwrap();
    manager::attach_symbol(1, "/usr/bin/demo", "main", 7, false).unwrap();
    let entries = manager::list_all();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].guest_path, "/usr/bin/demo");
    assert_eq!(entries[0].symbol, "main");
    assert!(!entries[0].is_ret);
    assert_eq!(entries[0].offset, 0x10);
    assert_eq!(entries[0].state, manager::UprobeState::Pending);
}

#[test]
fn detach_ret_probe_cleans_pending_return_instances() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(2, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(2, "/usr/bin/demo", "target_fn", 8, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(2, "/usr/bin/demo", 0x1000, 0x400000, 0, 0x8000, 0x12345678)
        .unwrap();
    return_stack::push(ReturnEntry {
        vm_id: 2,
        vcpu_id: 0,
        mm: 0x1000,
        entry_pc: 0x400010,
        return_gva: 0x5000,
        return_hva: 0x9000,
        saved_insn: 0xd65f03c0,
        prog_id: 8,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 0,
        tgid: 0,
        comm: String::new(),
    })
    .unwrap();

    manager::detach(2, "/usr/bin/demo", "target_fn").unwrap();

    assert!(return_stack::list_for_test(2, 0, 0x1000).is_empty());
}

#[test]
fn return_brk_acquire_and_release_track_refcount() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    manager::install_mock_patch_backend_for_test();

    let (return_hva, saved_insn, refcount) = manager::acquire_return_brk(3, 0x1000, 0x5000).unwrap();
    assert_eq!(return_hva, 0x8000);
    assert_eq!(saved_insn, 0x1234_5678);
    assert_eq!(refcount, 1);

    let (_, _, refcount) = manager::acquire_return_brk(3, 0x1000, 0x5000).unwrap();
    assert_eq!(refcount, 2);
    assert_eq!(
        manager::lookup_return_brk_for_test(3, 0x1000, 0x5000).unwrap().refcount,
        2
    );

    assert!(manager::release_return_brk(3, 0x1000, 0x5000).unwrap());
    assert_eq!(
        manager::lookup_return_brk_for_test(3, 0x1000, 0x5000).unwrap().refcount,
        1
    );

    assert!(!manager::release_return_brk(3, 0x1000, 0x5000).unwrap());
    assert!(manager::lookup_return_brk_for_test(3, 0x1000, 0x5000).is_none());
}

#[test]
fn disable_active_ret_probe_cleans_return_state() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    return_stack::clear_all_for_test();
    object::load_text_symbols(4, "/usr/bin/demo", "0000000000000010 T target_fn\n").unwrap();
    manager::attach_symbol(4, "/usr/bin/demo", "target_fn", 12, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(4, "/usr/bin/demo", 0x1000, 0x400000, 0, 0x8000, 0x12345678)
        .unwrap();
    let (return_hva, saved_insn, _refcount) = manager::acquire_return_brk(4, 0x1000, 0x5000).unwrap();
    return_stack::push(ReturnEntry {
        vm_id: 4,
        vcpu_id: 0,
        mm: 0x1000,
        entry_pc: 0x400010,
        return_gva: 0x5000,
        return_hva,
        saved_insn,
        prog_id: 12,
        guest_path: "/usr/bin/demo".into(),
        symbol: "target_fn".into(),
        pid: 0,
        tgid: 0,
        comm: String::new(),
    })
    .unwrap();

    manager::disable_active(4, 0x400010).unwrap();

    assert!(return_stack::list_for_test(4, 0, 0x1000).is_empty());
    assert!(manager::lookup_return_brk_for_test(4, 0x1000, 0x5000).is_none());
}
