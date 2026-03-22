#![cfg(all(feature = "guest-kprobe", feature = "guest-uprobe"))]

use std::sync::Mutex;

use axebpf::guest_symbols;
use axebpf::probe::guest_runtime_state::{
    LiveGuestRuntimeState, clear_live_guest_runtime_state_for_test,
    install_live_guest_runtime_state,
};
use axebpf::probe::kprobe::manager as guest_kprobe;
use axebpf::probe::uprobe::addr_translate::{
    clear_vm_ttbr0_hook_for_test, register_vm_ttbr0_hook,
};
use axebpf::probe::uprobe::linux_observer;
use axebpf::probe::uprobe::linux_runtime_observer;
use axebpf::probe::uprobe::linux_runtime_observer::clear_vm_contextidr_hook_for_test;
use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axebpf::probe::uprobe::{manager, object};

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn ensure_registered_for_vm_is_idempotent() {
    let _guard = TEST_LOCK.lock().unwrap();
    guest_kprobe::init();
    guest_symbols::load_from_text(
        1,
        "\
ffff800080001000 T __arm64_sys_execve\n\
ffff800080001100 T __arm64_sys_execveat\n\
ffff800080002000 T vm_mmap_pgoff\n",
    )
    .unwrap();

    linux_runtime_observer::clear_all_for_test();
    assert_eq!(linux_runtime_observer::ensure_registered_for_vm(1).unwrap(), 3);
    assert_eq!(linux_runtime_observer::ensure_registered_for_vm(1).unwrap(), 0);
    assert!(guest_kprobe::list_all().is_empty());
}

#[test]
fn ensure_registered_for_vm_waits_for_guest_kernel_symbols() {
    let _guard = TEST_LOCK.lock().unwrap();
    guest_kprobe::init();
    linux_runtime_observer::clear_all_for_test();

    assert_eq!(linux_runtime_observer::ensure_registered_for_vm(2).unwrap(), 0);
}

#[test]
fn current_tokens_prefers_live_guest_state_over_cached_hooks() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();

    register_vm_ttbr0_hook(|_| Ok(0x1111));
    linux_runtime_observer::register_vm_contextidr_hook(|_| Ok(0x22));
    let _live_state = install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id: 7,
        ttbr0_el1: 0x3333,
        ttbr1_el1: 0,
        contextidr_el1: 0x44,
        sp_el0: 0,
        tpidr_el0: 0,
        guest_spsr: 0,
    });

    let tokens = linux_runtime_observer::current_tokens_for_test(7).unwrap();
    assert_eq!(tokens, (0x44, 0x3333));

    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();
}

#[test]
fn current_tokens_falls_back_to_synthetic_proc_token_when_live_contextidr_is_zero() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();

    let _live_state = install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id: 9,
        ttbr0_el1: 0x5555_0000,
        ttbr1_el1: 0,
        contextidr_el1: 0,
        sp_el0: 0xffff_8000_0000_0042,
        tpidr_el0: 0x1234_5678_0000_0042,
        guest_spsr: 0,
    });

    let tokens = linux_runtime_observer::current_tokens_for_test(9).unwrap();
    assert_eq!(
        tokens,
        (
            linux_runtime_observer::fallback_proc_token_for_test(0xffff_8000_0000_0042),
            0x5555_0000,
        )
    );

    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();
}

#[test]
fn current_tokens_falls_back_to_synthetic_proc_token_when_contextidr_hook_errors() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();

    register_vm_ttbr0_hook(|_| Ok(0x6666_0000));
    linux_runtime_observer::register_vm_contextidr_hook(|_| Err(axerrno::AxError::BadState));

    let tokens = linux_runtime_observer::current_tokens_for_test(10).unwrap();
    assert_eq!(
        tokens,
        (
            linux_runtime_observer::fallback_proc_token_for_test(0x6666_0000),
            0x6666_0000,
        )
    );

    clear_live_guest_runtime_state_for_test();
    clear_vm_ttbr0_hook_for_test();
    clear_vm_contextidr_hook_for_test();
}

#[test]
fn runtime_retry_activates_pending_probe_for_existing_main_text_mapping() {
    let _guard = TEST_LOCK.lock().unwrap();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(1, "/usr/bin/ax_uprobe_demo", "0000000000000040 T target_fn\n")
        .unwrap();
    manager::attach_symbol(1, "/usr/bin/ax_uprobe_demo", "target_fn", 17, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 1, 11, 11, 0x4000, "ax_uprobe_demo");
    maps.apply(axebpf::probe::uprobe::process_maps::ObserverEvent::Mmap {
        vm_id: 1,
        mm: 0x4000,
        start: 0x210000,
        end: 0x211000,
        file_offset: 0,
        guest_path: "/usr/bin/ax_uprobe_demo".into(),
    });

    linux_runtime_observer::retry_pending_activation_for_test(&maps, 1, 0x4000).unwrap();

    assert!(manager::lookup_active_for_test(1, 0x210040).is_some());
}
