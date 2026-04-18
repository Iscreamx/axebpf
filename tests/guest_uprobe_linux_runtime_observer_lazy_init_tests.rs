#![cfg(all(feature = "guest-kprobe", feature = "guest-uprobe"))]

use axebpf::guest_symbols;
use axebpf::probe::uprobe::linux_runtime_observer;

#[test]
fn ensure_registered_for_vm_lazily_initializes_guest_kprobe_dependency() {
    guest_symbols::load_from_text(
        9,
        "\
ffff800080001000 T __arm64_sys_execve\n\
ffff800080001100 T __arm64_sys_execveat\n\
ffff800080002000 T vm_mmap_pgoff\n",
    )
    .unwrap();

    linux_runtime_observer::clear_all_for_test();

    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(9).unwrap(),
        3
    );
}
