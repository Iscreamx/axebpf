#![cfg(feature = "guest-kprobe")]

use axebpf::guest_symbols;

const SAMPLE_SYMS: &str = "\
ffff800080001000 T _start
ffff800080001040 t early_init
ffff800080002000 T main
ffff800080003000 D __bss_start
ffff800080004000 B __bss_end
";

#[test]
fn load_and_lookup_by_name() {
    let vm_id = 100;
    guest_symbols::unload(vm_id);

    let count = guest_symbols::load_from_text(vm_id, SAMPLE_SYMS).unwrap();
    assert_eq!(count, 5);
    assert!(guest_symbols::is_loaded(vm_id));
    assert_eq!(guest_symbols::symbol_count(vm_id), 5);

    assert_eq!(
        guest_symbols::lookup_addr(vm_id, "_start"),
        Some(0xffff800080001000)
    );
    assert_eq!(
        guest_symbols::lookup_addr(vm_id, "main"),
        Some(0xffff800080002000)
    );
    assert_eq!(guest_symbols::lookup_addr(vm_id, "nonexistent"), None);

    guest_symbols::unload(vm_id);
    assert!(!guest_symbols::is_loaded(vm_id));
}

#[test]
fn lookup_by_addr_nearest() {
    let vm_id = 101;
    guest_symbols::unload(vm_id);
    guest_symbols::load_from_text(vm_id, SAMPLE_SYMS).unwrap();

    let (name, ty, offset) = guest_symbols::lookup_name(vm_id, 0xffff800080001000).unwrap();
    assert_eq!(name, "_start");
    assert_eq!(ty, 'T');
    assert_eq!(offset, 0);

    let (name, _, offset) = guest_symbols::lookup_name(vm_id, 0xffff800080001010).unwrap();
    assert_eq!(name, "_start");
    assert_eq!(offset, 0x10);

    assert!(guest_symbols::lookup_name(vm_id, 0x1000).is_none());

    guest_symbols::unload(vm_id);
}

#[test]
fn search_pattern_and_limit() {
    let vm_id = 102;
    guest_symbols::unload(vm_id);
    guest_symbols::load_from_text(vm_id, SAMPLE_SYMS).unwrap();

    let results = guest_symbols::search(vm_id, "__bss", 10);
    assert_eq!(results.len(), 2);

    let limited = guest_symbols::search(vm_id, "_", 1);
    assert_eq!(limited.len(), 1);

    guest_symbols::unload(vm_id);
}

#[test]
fn malformed_lines_skipped_and_reload_replaces_table() {
    let vm_id = 103;
    guest_symbols::unload(vm_id);

    let content = "\
ffff800080001000 T good_symbol
this is garbage
ffff800080002000 T another_good

# comment line
incomplete
";
    let count = guest_symbols::load_from_text(vm_id, content).unwrap();
    assert_eq!(count, 2);
    assert_eq!(guest_symbols::symbol_count(vm_id), 2);

    guest_symbols::load_from_text(vm_id, "ffff800080003000 T newer").unwrap();
    assert_eq!(guest_symbols::symbol_count(vm_id), 1);
    assert_eq!(guest_symbols::lookup_addr(vm_id, "good_symbol"), None);
    assert_eq!(
        guest_symbols::lookup_addr(vm_id, "newer"),
        Some(0xffff800080003000)
    );

    guest_symbols::unload(vm_id);
}

#[test]
fn empty_or_comment_only_input_returns_error() {
    let vm_id = 104;
    guest_symbols::unload(vm_id);

    let result = guest_symbols::load_from_text(vm_id, "");
    assert!(result.is_err());

    let result = guest_symbols::load_from_text(vm_id, "# only comments\n\n");
    assert!(result.is_err());
}

#[test]
fn duplicate_symbol_name_uses_last_address() {
    let vm_id = 105;
    guest_symbols::unload(vm_id);

    let content = "\
ffff800080001000 T foo
ffff800080002000 T foo
";

    let count = guest_symbols::load_from_text(vm_id, content).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        guest_symbols::lookup_addr(vm_id, "foo"),
        Some(0xffff800080002000)
    );

    let nearest_old = guest_symbols::lookup_name(vm_id, 0xffff800080001000);
    assert!(nearest_old.is_none());

    guest_symbols::unload(vm_id);
}
