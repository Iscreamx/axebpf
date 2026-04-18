#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::object;

#[test]
fn load_text_symbols_for_guest_path() {
    let text = "0000000000000010 T main\n0000000000000040 T helper\n";
    let count = object::load_text_symbols(1, "/usr/bin/demo", text).unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        object::lookup_offset(1, "/usr/bin/demo", "main"),
        Some(0x10)
    );
}

#[test]
fn metadata_stores_executable_load_segments() {
    let text = "\
# axvisor-load-segment 0x1000 0x200 0x0 0x5
# axvisor-load-segment 0x3000 0x100 0x200 0x4
0000000000001080 T target_fn\n";
    object::load_text_symbols(2, "/usr/lib/libdemo.so", text).unwrap();

    let segments = object::list_load_segments(2, "/usr/lib/libdemo.so").unwrap();
    assert_eq!(segments.len(), 2);
    let exec_segments = object::list_executable_load_segments(2, "/usr/lib/libdemo.so").unwrap();
    assert_eq!(exec_segments.len(), 1);
    assert_eq!(exec_segments[0].vaddr, 0x1000);
    assert_eq!(exec_segments[0].memsz, 0x200);
}

#[test]
fn symbol_or_offset_resolves_to_load_segment() {
    let text = "\
# axvisor-load-segment 0x1000 0x200 0x0 0x5
# axvisor-load-segment 0x3000 0x100 0x200 0x4
0000000000001080 T target_fn
0000000000003008 R ro_data\n";
    object::load_text_symbols(3, "/usr/lib/libdemo.so", text).unwrap();

    let sym_addr = object::resolve_object_addr(3, "/usr/lib/libdemo.so", "target_fn").unwrap();
    assert_eq!(sym_addr, 0x1080);
    let sym_seg = object::lookup_load_segment(3, "/usr/lib/libdemo.so", sym_addr).unwrap();
    assert_eq!(sym_seg.vaddr, 0x1000);

    let off_addr = object::resolve_object_addr(3, "/usr/lib/libdemo.so", "0x3008").unwrap();
    assert_eq!(off_addr, 0x3008);
    let off_seg = object::lookup_load_segment(3, "/usr/lib/libdemo.so", off_addr).unwrap();
    assert_eq!(off_seg.vaddr, 0x3000);
}

#[test]
fn reject_offset_outside_executable_segment() {
    let text = "\
# axvisor-load-segment 0x1000 0x200 0x0 0x5
# axvisor-load-segment 0x3000 0x100 0x200 0x4
0000000000001080 T target_fn\n";
    object::load_text_symbols(4, "/usr/lib/libdemo.so", text).unwrap();

    let ok_addr =
        object::resolve_executable_object_addr(4, "/usr/lib/libdemo.so", "target_fn").unwrap();
    assert_eq!(ok_addr, 0x1080);
    assert!(object::resolve_executable_object_addr(4, "/usr/lib/libdemo.so", "0x3008").is_err());
}
