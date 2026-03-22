#![cfg(feature = "guest-kprobe")]

use axebpf::probe::kprobe::manager::{self, KprobeMode};

#[test]
fn register_lazily_initializes_guest_kprobe_registry() {
    let vm_id = 17;
    let gva = 0x1000_u64;

    manager::register(vm_id, gva, 1, false, KprobeMode::Stage2Fault).unwrap();
    manager::unregister(vm_id, gva).unwrap();
}
