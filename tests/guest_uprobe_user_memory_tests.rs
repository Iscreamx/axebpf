#![cfg(feature = "guest-uprobe")]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axebpf::probe::uprobe::addr_translate::{
    read_user_cstring_with_vm, register_gva_to_hva_hook, register_vm_ttbr0_hook,
};

static OFFSET_BYTES_PTR: AtomicUsize = AtomicUsize::new(0);
static OFFSET_GVA_BASE: AtomicUsize = AtomicUsize::new(0);
static BASE_BYTES_PTR: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn mock_gva_to_hva_with_offset(gva: u64, _vm_id: u32) -> axerrno::AxResult<usize> {
    let base = OFFSET_GVA_BASE.load(Ordering::Relaxed);
    Ok(OFFSET_BYTES_PTR.load(Ordering::Relaxed) + ((gva as usize).saturating_sub(base)))
}

fn mock_gva_to_hva_base(_gva: u64, _vm_id: u32) -> axerrno::AxResult<usize> {
    Ok(BASE_BYTES_PTR.load(Ordering::Relaxed))
}

#[test]
fn user_string_reader_returns_absolute_exec_path() {
    let _guard = TEST_LOCK.lock().unwrap();
    let user_gva = 0x7000_0020;
    let bytes = Box::leak(Box::new(*b"/usr/bin/ax_uprobe_demo\0"));
    register_vm_ttbr0_hook(|_| Ok(0x2000_0000));
    OFFSET_BYTES_PTR.store(bytes.as_ptr() as usize, Ordering::Relaxed);
    OFFSET_GVA_BASE.store(user_gva as usize, Ordering::Relaxed);
    register_gva_to_hva_hook(mock_gva_to_hva_with_offset);

    let path = read_user_cstring_with_vm(1, user_gva, 128).unwrap();
    assert_eq!(path, "/usr/bin/ax_uprobe_demo");
}

#[test]
fn user_string_reader_rejects_missing_nul() {
    let _guard = TEST_LOCK.lock().unwrap();
    let bytes = Box::leak(Box::new(
        *b"/usr/bin/no-nul................................",
    ));
    BASE_BYTES_PTR.store(bytes.as_ptr() as usize, Ordering::Relaxed);
    register_gva_to_hva_hook(mock_gva_to_hva_base);

    assert!(read_user_cstring_with_vm(1, 0x7000_0000, 8).is_err());
}
