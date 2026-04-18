#![cfg(all(feature = "guest-kprobe", feature = "guest-uprobe"))]

use std::sync::Mutex;

use axebpf::guest_symbols;
use axebpf::probe::guest_runtime_state::{
    LiveGuestRuntimeState, clear_live_guest_runtime_state_for_test,
    install_live_guest_runtime_state,
};
use axebpf::probe::kprobe::manager as guest_kprobe;
use axebpf::probe::uprobe::addr_translate::{clear_vm_ttbr0_hook_for_test, register_vm_ttbr0_hook};
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
    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(1).unwrap(),
        3
    );
    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(1).unwrap(),
        0
    );
    assert!(guest_kprobe::list_all().is_empty());
}

#[test]
fn ensure_registered_for_vm_waits_for_guest_kernel_symbols() {
    let _guard = TEST_LOCK.lock().unwrap();
    guest_kprobe::init();
    linux_runtime_observer::clear_all_for_test();

    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(2).unwrap(),
        0
    );
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
    object::load_text_symbols(
        1,
        "/usr/bin/ax_uprobe_demo",
        "0000000000000040 T target_fn\n",
    )
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

#[test]
fn runtime_retry_reuses_existing_patch_for_second_mm() {
    let _guard = TEST_LOCK.lock().unwrap();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(
        11,
        "/usr/bin/ax_uprobe_demo",
        "0000000000000040 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(11, "/usr/bin/ax_uprobe_demo", "target_fn", 19, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    manager::set_mock_patch_result_for_test(0x8100, 0x1111_1111, 0);
    linux_observer::on_exec(&maps, 11, 11, 11, 0x4000, "ax_uprobe_demo");
    linux_observer::on_mmap(
        &maps,
        11,
        0x4000,
        0x210000,
        0x211000,
        0,
        "/usr/bin/ax_uprobe_demo",
    );

    linux_observer::on_exec(&maps, 11, 22, 22, 0x5000, "ax_uprobe_demo");
    maps.apply(axebpf::probe::uprobe::process_maps::ObserverEvent::Mmap {
        vm_id: 11,
        mm: 0x5000,
        start: 0x210000,
        end: 0x211000,
        file_offset: 0,
        guest_path: "/usr/bin/ax_uprobe_demo".into(),
    });
    manager::set_mock_patch_result_for_test(0x8200, 0x2222_2222, 0);

    assert_eq!(
        linux_runtime_observer::retry_pending_activation_for_test(&maps, 11, 0x5000).unwrap(),
        1
    );

    let first = manager::lookup_active_for_mm_for_test(11, 0x4000, 0x210040).unwrap();
    let second = manager::lookup_active_for_mm_for_test(11, 0x5000, 0x210040).unwrap();
    assert_eq!(second.hva, first.hva);
    assert_eq!(second.saved_insn, first.saved_insn);
}

#[test]
fn runtime_retry_activates_pending_probe_for_existing_shared_object_mapping() {
    let _guard = TEST_LOCK.lock().unwrap();
    let maps = ProcessMaps::new();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    object::load_text_symbols(
        12,
        "/usr/lib/libdemo.so",
        "\
# axvisor-load-segment 0x2234 0x900 0x1234 0x5
0000000000002256 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(12, "/usr/lib/libdemo.so", "target_fn", 20, false).unwrap();
    manager::install_mock_patch_backend_for_test();

    linux_observer::on_exec(&maps, 12, 33, 33, 0x6000, "ax_uprobe_demo");
    maps.apply(axebpf::probe::uprobe::process_maps::ObserverEvent::Mmap {
        vm_id: 12,
        mm: 0x6000,
        start: 0x500000,
        end: 0x501000,
        file_offset: 0x1000,
        guest_path: "/usr/lib/libdemo.so".into(),
    });

    assert_eq!(
        linux_runtime_observer::retry_pending_activation_for_test(&maps, 12, 0x6000).unwrap(),
        1
    );
    assert!(manager::lookup_active_for_mm_for_test(12, 0x6000, 0x500256).is_some());
}

#[test]
fn do_exit_hidden_probe_does_not_cleanup_active_mm_instances() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();

    guest_symbols::load_from_text(
        21,
        "\
ffff800080001000 T __arm64_sys_execve\n\
ffff800080001100 T __arm64_sys_execveat\n\
ffff800080002000 T vm_mmap_pgoff\n\
ffff800080003000 T do_exit\n\
ffff800080004000 T exit_mmap\n",
    )
    .unwrap();
    object::load_text_symbols(
        21,
        "/usr/bin/ax_uprobe_demo",
        "0000000000000040 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(21, "/usr/bin/ax_uprobe_demo", "target_fn", 23, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        21,
        "/usr/bin/ax_uprobe_demo",
        0x4000,
        0x210000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();

    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(21).unwrap(),
        4
    );
    assert!(manager::lookup_active_for_mm_for_test(21, 0x4000, 0x210040).is_some());

    let _live_state = install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id: 21,
        ttbr0_el1: 0x4000,
        ttbr1_el1: 0,
        contextidr_el1: 0x55,
        sp_el0: 0,
        tpidr_el0: 0,
        guest_spsr: 0,
    });
    linux_runtime_observer::handle_exit_entry_for_test(21);

    assert!(manager::lookup_active_for_mm_for_test(21, 0x4000, 0x210040).is_some());
}

#[test]
fn exit_mmap_hidden_probe_cleans_only_current_mm_instances() {
    let _guard = TEST_LOCK.lock().unwrap();
    manager::init();
    manager::clear_all_for_test();
    linux_runtime_observer::clear_all_for_test();
    clear_live_guest_runtime_state_for_test();

    guest_symbols::load_from_text(
        22,
        "\
ffff800080001000 T __arm64_sys_execve\n\
ffff800080001100 T __arm64_sys_execveat\n\
ffff800080002000 T vm_mmap_pgoff\n\
ffff800080004000 T exit_mmap\n",
    )
    .unwrap();
    object::load_text_symbols(
        22,
        "/usr/bin/ax_uprobe_demo",
        "0000000000000040 T target_fn\n",
    )
    .unwrap();
    manager::attach_symbol(22, "/usr/bin/ax_uprobe_demo", "target_fn", 24, true).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::activate_for_mapping_for_test(
        22,
        "/usr/bin/ax_uprobe_demo",
        0x4000,
        0x210000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();
    manager::activate_for_mapping_for_test(
        22,
        "/usr/bin/ax_uprobe_demo",
        0x5000,
        0x210000,
        0,
        0x8100,
        0x1111_1111,
    )
    .unwrap();

    assert_eq!(
        linux_runtime_observer::ensure_registered_for_vm(22).unwrap(),
        4
    );
    assert!(manager::lookup_active_for_mm_for_test(22, 0x4000, 0x210040).is_some());
    assert!(manager::lookup_active_for_mm_for_test(22, 0x5000, 0x210040).is_some());

    let _live_state = install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id: 22,
        ttbr0_el1: 0x4000,
        ttbr1_el1: 0,
        contextidr_el1: 0x55,
        sp_el0: 0,
        tpidr_el0: 0,
        guest_spsr: 0,
    });
    linux_runtime_observer::handle_exit_mmap_entry_for_test(22);

    assert!(manager::lookup_active_for_mm_for_test(22, 0x4000, 0x210040).is_none());
    assert!(manager::lookup_active_for_mm_for_test(22, 0x5000, 0x210040).is_some());
}
