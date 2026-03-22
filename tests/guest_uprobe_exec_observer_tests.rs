#![cfg(feature = "guest-uprobe")]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axebpf::probe::kprobe::addr_translate::{
    clear_gva_to_hva_hook_for_test as clear_kernel_gva_to_hva_hook_for_test,
    register_gva_to_hva_hook as register_kernel_gva_to_hva_hook,
};
use axebpf::probe::uprobe::linux_runtime_observer;
use axebpf::probe::uprobe::addr_translate::{
    clear_gva_to_hva_hook_for_test as clear_user_gva_to_hva_hook_for_test,
    register_gva_to_hva_hook as register_user_gva_to_hva_hook,
};
use axebpf::probe::uprobe::process_maps::ProcessMaps;
use axerrno::AxResult;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static KERNEL_BASE_GVA: AtomicUsize = AtomicUsize::new(0);
static KERNEL_PTR: AtomicUsize = AtomicUsize::new(0);
static USER_BASE_GVA: AtomicUsize = AtomicUsize::new(0);
static USER_PTR: AtomicUsize = AtomicUsize::new(0);

fn kernel_gva_to_hva(gva: u64, _vm_id: u32) -> AxResult<usize> {
    let base = KERNEL_BASE_GVA.load(Ordering::Relaxed);
    Ok(KERNEL_PTR.load(Ordering::Relaxed) + (gva as usize).saturating_sub(base))
}

fn user_gva_to_hva(gva: u64, _vm_id: u32) -> AxResult<usize> {
    let base = USER_BASE_GVA.load(Ordering::Relaxed);
    Ok(USER_PTR.load(Ordering::Relaxed) + (gva as usize).saturating_sub(base))
}

#[test]
fn execve_entry_records_exec_intent_with_proc_and_mm_tokens() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    linux_runtime_observer::clear_all_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execve",
        0x1234,
        0x4000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();

    let exec = linux_runtime_observer::lookup_exec_intent_for_test(1, 0x1234, 0x4000).unwrap();
    assert_eq!(exec.exec_path, "/usr/bin/ax_uprobe_demo");
    assert_eq!(exec.proc_token, 0x1234);
    assert_eq!(exec.mm_token, 0x4000);
}

#[test]
fn execveat_uses_second_syscall_argument_as_path() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let maps = ProcessMaps::new();
    linux_runtime_observer::clear_all_for_test();

    linux_runtime_observer::record_execve_for_test(
        &maps,
        1,
        "__arm64_sys_execveat",
        0x55,
        0x9000,
        "/usr/bin/ax_uprobe_demo",
    )
    .unwrap();

    assert!(linux_runtime_observer::lookup_exec_intent_for_test(1, 0x55, 0x9000).is_some());
}

#[test]
fn execve_wrapper_reads_path_from_guest_pt_regs_x0() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    const PT_REGS_GVA: u64 = 0xffff_8000_0010_0000;
    const USER_PATH_GVA: u64 = 0x7000_0020;
    let mut pt_regs = [0_u64; 31];
    pt_regs[0] = USER_PATH_GVA;
    let user_bytes = Box::leak(Box::new(*b"/usr/bin/ax_uprobe_demo\0"));

    clear_kernel_gva_to_hva_hook_for_test();
    clear_user_gva_to_hva_hook_for_test();
    KERNEL_BASE_GVA.store(PT_REGS_GVA as usize, Ordering::Relaxed);
    KERNEL_PTR.store(pt_regs.as_ptr() as usize, Ordering::Relaxed);
    USER_BASE_GVA.store(USER_PATH_GVA as usize, Ordering::Relaxed);
    USER_PTR.store(user_bytes.as_ptr() as usize, Ordering::Relaxed);
    register_kernel_gva_to_hva_hook(kernel_gva_to_hva);
    register_user_gva_to_hva_hook(user_gva_to_hva);

    let path = linux_runtime_observer::read_exec_path_from_regs_for_test(
        1,
        "__arm64_sys_execve",
        &[PT_REGS_GVA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(path, "/usr/bin/ax_uprobe_demo");

    clear_kernel_gva_to_hva_hook_for_test();
    clear_user_gva_to_hva_hook_for_test();
}

#[test]
fn execveat_wrapper_reads_path_from_guest_pt_regs_x1() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    const PT_REGS_GVA: u64 = 0xffff_8000_0020_0000;
    const USER_PATH_GVA: u64 = 0x7000_0040;
    let mut pt_regs = [0_u64; 31];
    pt_regs[1] = USER_PATH_GVA;
    let user_bytes = Box::leak(Box::new(*b"/usr/bin/ax_uprobe_demo\0"));

    clear_kernel_gva_to_hva_hook_for_test();
    clear_user_gva_to_hva_hook_for_test();
    KERNEL_BASE_GVA.store(PT_REGS_GVA as usize, Ordering::Relaxed);
    KERNEL_PTR.store(pt_regs.as_ptr() as usize, Ordering::Relaxed);
    USER_BASE_GVA.store(USER_PATH_GVA as usize, Ordering::Relaxed);
    USER_PTR.store(user_bytes.as_ptr() as usize, Ordering::Relaxed);
    register_kernel_gva_to_hva_hook(kernel_gva_to_hva);
    register_user_gva_to_hva_hook(user_gva_to_hva);

    let path = linux_runtime_observer::read_exec_path_from_regs_for_test(
        1,
        "__arm64_sys_execveat",
        &[PT_REGS_GVA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(path, "/usr/bin/ax_uprobe_demo");

    clear_kernel_gva_to_hva_hook_for_test();
    clear_user_gva_to_hva_hook_for_test();
}
