#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::{manager, object};

#[test]
fn attach_by_guest_path_and_symbol_registers_pending_probe() {
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
