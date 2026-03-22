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
