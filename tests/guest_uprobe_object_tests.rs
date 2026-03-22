#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::object;

#[test]
fn load_text_symbols_for_guest_path() {
    let text = "0000000000000010 T main\n0000000000000040 T helper\n";
    let count = object::load_text_symbols(1, "/usr/bin/demo", text).unwrap();
    assert_eq!(count, 2);
    assert_eq!(object::lookup_offset(1, "/usr/bin/demo", "main"), Some(0x10));
}
