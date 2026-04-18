#![cfg(feature = "guest-uprobe")]

use axebpf::probe::uprobe::linux_observer;
use axebpf::probe::uprobe::process_maps::ProcessMaps;

#[test]
fn only_main_elf_text_mapping_is_kept_for_one_mm() {
    let maps = ProcessMaps::new();

    linux_observer::on_exec(&maps, 1, 10, 10, 0x1000, "demo");
    linux_observer::on_mmap(&maps, 1, 0x1000, 0x400000, 0x401000, 0, "/usr/bin/demo");
    assert!(maps.lookup_pc(1, 0x1000, 0x400010).is_some());

    linux_observer::on_mmap(&maps, 1, 0x1000, 0x500000, 0x501000, 0, "/usr/lib/libc.so");
    assert!(maps.lookup_pc(1, 0x1000, 0x500010).is_none());

    linux_observer::on_exit_mm(&maps, 1, 0x1000);
    assert!(maps.lookup_pc(1, 0x1000, 0x400010).is_none());
}

#[test]
fn path_query_returns_shared_object_mappings_per_mm() {
    let maps = ProcessMaps::new();

    linux_observer::on_exec(&maps, 2, 20, 20, 0x2000, "demo");
    linux_observer::on_mmap(&maps, 2, 0x2000, 0x400000, 0x401000, 0, "/usr/bin/demo");
    linux_observer::on_mmap(&maps, 2, 0x2000, 0x500000, 0x502000, 0, "/usr/lib/libc.so");
    linux_observer::on_mmap(&maps, 2, 0x2000, 0x600000, 0x601000, 0, "/usr/lib/libm.so");

    let libc = maps.lookup_mappings_for_path(2, 0x2000, "/usr/lib/libc.so");
    assert_eq!(libc.len(), 1);
    assert_eq!(libc[0].start, 0x500000);
    assert_eq!(libc[0].end, 0x502000);

    let main = maps.lookup_mappings_for_path(2, 0x2000, "/usr/bin/demo");
    assert_eq!(main.len(), 1);
    assert_eq!(main[0].start, 0x400000);
}
