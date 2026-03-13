#![cfg(feature = "guest-kprobe")]

use axebpf::probe::kprobe::addr_translate::{
    register_guest_pt_read_hook, register_gva_to_hva_hook, register_vm_ttbr1_hook,
};
use axebpf::probe::kprobe::manager::{self, KprobeMode};
use axebpf::probe::kprobe::return_stack::{self, ReturnEntry};
use axerrno::AxResult;
use std::sync::{
    Mutex, MutexGuard, OnceLock,
    atomic::{AtomicBool, Ordering},
};

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn mock_vm_ttbr1(vm_id: u32) -> AxResult<u64> {
    Ok(0x2000_0000 + ((vm_id as u64) << 20))
}

static DEFERRED_TTBR1_READY: AtomicBool = AtomicBool::new(true);

fn mock_vm_ttbr1_deferred(vm_id: u32) -> AxResult<u64> {
    if !DEFERRED_TTBR1_READY.load(Ordering::Acquire) {
        return axerrno::ax_err!(BadState, "mock TTBR1_EL1 not ready");
    }
    mock_vm_ttbr1(vm_id)
}

fn mock_guest_pt_read(paddr: u64, vm_id: u32) -> AxResult<u64> {
    let ttbr1 = mock_vm_ttbr1(vm_id)?;
    let l1 = ttbr1 + 0x1000;
    let l2 = ttbr1 + 0x2000;
    let l3 = ttbr1 + 0x3000;

    let table_base = paddr & !0xfff;
    let index = (paddr & 0xfff) / 8;
    let desc = if table_base == ttbr1 {
        l1 | 0b11
    } else if table_base == l1 {
        l2 | 0b11
    } else if table_base == l2 {
        l3 | 0b11
    } else if table_base == l3 {
        (0x5000_0000 + (index << 12)) | 0b11
    } else {
        return axerrno::ax_err!(NotFound, "mock pte missing");
    };
    Ok(desc)
}

fn mock_stage2_exec(_vm_id: u32, _gpa: u64, _executable: bool) -> AxResult<()> {
    Ok(())
}

fn mock_stage2_exec_region(_vm_id: u32, gpa: u64) -> AxResult<(u64, u64)> {
    Ok((gpa & !0x1f_ffff, 0x20_0000))
}

fn setup_stage2_backends() {
    register_vm_ttbr1_hook(mock_vm_ttbr1);
    register_guest_pt_read_hook(mock_guest_pt_read);
    manager::register_stage2_exec_hook(mock_stage2_exec);
    manager::register_stage2_exec_region_hook(mock_stage2_exec_region);
    #[cfg(feature = "test-utils")]
    {
        manager::clear_stale_brk_for_test();
        manager::clear_return_brk_for_test();
        return_stack::clear_all_for_test();
    }
}

fn setup_deferred_stage2_backends() {
    register_vm_ttbr1_hook(mock_vm_ttbr1_deferred);
    register_guest_pt_read_hook(mock_guest_pt_read);
    manager::register_stage2_exec_hook(mock_stage2_exec);
    manager::register_stage2_exec_region_hook(mock_stage2_exec_region);
    #[cfg(feature = "test-utils")]
    {
        manager::clear_stale_brk_for_test();
        manager::clear_return_brk_for_test();
        return_stack::clear_all_for_test();
    }
}

static mut MOCK_GUEST_TEXT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
static mut MOCK_RETURN_TEXT: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];

const RETURN_ADDR_GVA: u64 = 0xffff_8000_0002_0000;
const ENTRY_ADDR_GVA: u64 = 0xffff_8000_8000_a000;

fn mock_gva_to_hva(gva: u64, _vm_id: u32) -> AxResult<usize> {
    if gva == RETURN_ADDR_GVA {
        return Ok(core::ptr::addr_of_mut!(MOCK_RETURN_TEXT) as usize);
    }
    Ok(core::ptr::addr_of_mut!(MOCK_GUEST_TEXT) as usize)
}

fn reset_mock_guest_text() {
    unsafe {
        MOCK_GUEST_TEXT = [0x78, 0x56, 0x34, 0x12];
        #[cfg(target_arch = "aarch64")]
        {
            MOCK_RETURN_TEXT = [0xc0, 0x03, 0x5f, 0xd6];
        }
        #[cfg(target_arch = "x86_64")]
        {
            MOCK_RETURN_TEXT = [0xc3, 0x90, 0x90, 0x90];
        }
    }
}

fn read_return_text() -> [u8; 4] {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MOCK_RETURN_TEXT)) }
}

fn expected_return_text() -> [u8; 4] {
    #[cfg(target_arch = "aarch64")]
    {
        [0xc0, 0x03, 0x5f, 0xd6]
    }
    #[cfg(target_arch = "x86_64")]
    {
        [0xc3, 0x90, 0x90, 0x90]
    }
}

#[cfg(feature = "test-utils")]
#[test]
fn attach_must_rollback_when_enable_fails() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    let vm_id = 1;
    let gva = 0x1000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::install_mock_backend_fail_on_enable(vm_id, gva);

    let ret = manager::attach(vm_id, gva, 1, false, KprobeMode::Stage2Fault);
    assert!(ret.is_err());

    assert!(manager::lookup_enabled(vm_id, gva).is_none());
    assert!(
        !manager::list_all()
            .iter()
            .any(|(v, a, _, _, _, _, _, _)| *v == vm_id && *a == gva)
    );
}

#[test]
fn duplicate_attach_same_key_returns_conflict() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    let vm_id = 2;
    let gva = 0x2000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 1, false, KprobeMode::Stage2Fault).unwrap();
    assert!(manager::attach(vm_id, gva, 2, false, KprobeMode::Stage2Fault).is_err());

    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn disable_and_detach_are_idempotent() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    let vm_id = 3;
    let gva = 0x3000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 1, false, KprobeMode::Stage2Fault).unwrap();

    assert!(manager::disable(vm_id, gva).is_ok());
    assert!(manager::disable(vm_id, gva).is_ok());

    assert!(manager::detach(vm_id, gva).is_ok());
    assert!(manager::detach(vm_id, gva).is_ok());
}

#[cfg(feature = "test-utils")]
#[test]
fn brk_inject_enable_then_disable_restores_instruction() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    register_gva_to_hva_hook(mock_gva_to_hva);
    let vm_id = 4;
    let gva = 0x4000_u64;
    let _ = manager::detach(vm_id, gva);

    unsafe {
        MOCK_GUEST_TEXT = [0x78, 0x56, 0x34, 0x12];
    }

    manager::attach(vm_id, gva, 7, false, KprobeMode::BrkInject).unwrap();

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0x00, 0x00, 0x20, 0xd4]);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0xcc, 0x56, 0x34, 0x12]);
    }

    manager::detach(vm_id, gva).unwrap();
    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
    }
}

#[test]
fn detach_all_for_vm_removes_only_target_vm() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();

    let vm_a = 10;
    let vm_b = 11;
    let gva1 = 0xa000_u64;
    let gva2 = 0xa100_u64;
    let gva3 = 0xb000_u64;

    // Clean up leftovers from prior runs.
    let _ = manager::detach(vm_a, gva1);
    let _ = manager::detach(vm_a, gva2);
    let _ = manager::detach(vm_b, gva3);

    manager::attach(vm_a, gva1, 1, false, KprobeMode::Stage2Fault).unwrap();
    manager::attach(vm_a, gva2, 2, false, KprobeMode::Stage2Fault).unwrap();
    manager::attach(vm_b, gva3, 3, false, KprobeMode::Stage2Fault).unwrap();

    let removed = manager::detach_all_for_vm(vm_a);
    assert_eq!(removed, 2);

    assert!(manager::lookup_enabled(vm_a, gva1).is_none());
    assert!(manager::lookup_enabled(vm_a, gva2).is_none());
    assert!(manager::lookup_enabled(vm_b, gva3).is_some());

    let _ = manager::detach(vm_b, gva3);
}

#[test]
fn brk_lookup_hit_must_include_resolved_gpa() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    register_gva_to_hva_hook(mock_gva_to_hva);

    let vm_id = 12;
    let gva = 0xffff_8000_8000_1000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 9, false, KprobeMode::BrkInject).unwrap();

    let expected_gpa = axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(gva, vm_id)
        .expect("mock GVA->GPA translation must succeed");
    let hit = manager::lookup_enabled_brk_hit(vm_id, gva).unwrap();
    assert_eq!(hit.gpa, Some(expected_gpa & !0x1f_ffff));
    assert_eq!(hit.gpa_size, 0x20_0000);

    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn attach_before_ttbr1_ready_must_defer_until_retry() {
    let _guard = test_guard();
    manager::init();
    DEFERRED_TTBR1_READY.store(false, Ordering::Release);
    setup_deferred_stage2_backends();

    let vm_id = 13;
    let gva = 0xffff_8000_8000_5000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 10, false, KprobeMode::Stage2Fault)
        .expect("attach should stay registered while TTBR1 is not ready");
    assert!(
        manager::lookup_enabled(vm_id, gva).is_none(),
        "probe must not become enabled before TTBR1 is ready"
    );
    assert!(
        manager::list_all()
            .iter()
            .any(|(vid, addr, _, _, enabled, _, _, _)| *vid == vm_id && *addr == gva && !enabled),
        "deferred probe must remain in registry"
    );
    assert_eq!(manager::try_enable_registered_for_vm(vm_id), 0);

    DEFERRED_TTBR1_READY.store(true, Ordering::Release);
    assert_eq!(manager::try_enable_registered_for_vm(vm_id), 1);
    assert_eq!(manager::lookup_enabled(vm_id, gva), Some((10, false)));

    manager::detach(vm_id, gva).unwrap();
}

#[cfg(feature = "test-utils")]
#[test]
fn brk_attach_before_ttbr1_ready_must_patch_after_retry() {
    let _guard = test_guard();
    manager::init();
    DEFERRED_TTBR1_READY.store(false, Ordering::Release);
    setup_deferred_stage2_backends();
    register_gva_to_hva_hook(mock_gva_to_hva);

    let vm_id = 14;
    let gva = 0xffff_8000_8000_6000_u64;
    let _ = manager::detach(vm_id, gva);

    unsafe {
        MOCK_GUEST_TEXT = [0x78, 0x56, 0x34, 0x12];
    }

    manager::attach(vm_id, gva, 11, false, KprobeMode::BrkInject)
        .expect("BRK attach should defer until TTBR1 is ready");

    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
    }
    assert_eq!(manager::try_enable_registered_for_vm(vm_id), 0);

    DEFERRED_TTBR1_READY.store(true, Ordering::Release);
    assert_eq!(manager::try_enable_registered_for_vm(vm_id), 1);

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0x00, 0x00, 0x20, 0xd4]);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let bytes = core::ptr::read_volatile(core::ptr::addr_of!(MOCK_GUEST_TEXT));
        assert_eq!(bytes, [0xcc, 0x56, 0x34, 0x12]);
    }

    manager::detach(vm_id, gva).unwrap();
    DEFERRED_TTBR1_READY.store(true, Ordering::Release);
}

#[cfg(feature = "test-utils")]
#[test]
fn detach_is_ret_must_cleanup_pending_return_state() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    register_gva_to_hva_hook(mock_gva_to_hva);
    reset_mock_guest_text();

    let vm_id = 15;
    let _ = manager::detach(vm_id, ENTRY_ADDR_GVA);

    manager::attach(vm_id, ENTRY_ADDR_GVA, 20, true, KprobeMode::BrkInject).unwrap();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, vm_id).unwrap();
    let (_refcount, saved_insn) =
        manager::acquire_return_brk(vm_id, RETURN_ADDR_GVA, ret_hva).unwrap();
    return_stack::push(
        0,
        ReturnEntry {
            vm_id,
            return_gva: RETURN_ADDR_GVA,
            return_hva: ret_hva,
            saved_insn,
            entry_gva: ENTRY_ADDR_GVA,
            prog_id: 20,
        },
    )
    .unwrap();

    manager::detach(vm_id, ENTRY_ADDR_GVA).unwrap();

    assert!(!return_stack::has_pending(0, vm_id, RETURN_ADDR_GVA));
    assert_eq!(read_return_text(), expected_return_text());
}

#[cfg(feature = "test-utils")]
#[test]
fn detach_all_for_vm_must_cleanup_pending_return_state() {
    let _guard = test_guard();
    manager::init();
    setup_stage2_backends();
    register_gva_to_hva_hook(mock_gva_to_hva);
    reset_mock_guest_text();

    let vm_id = 16;
    let _ = manager::detach(vm_id, ENTRY_ADDR_GVA);

    manager::attach(vm_id, ENTRY_ADDR_GVA, 21, true, KprobeMode::BrkInject).unwrap();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, vm_id).unwrap();
    let (_refcount, saved_insn) =
        manager::acquire_return_brk(vm_id, RETURN_ADDR_GVA, ret_hva).unwrap();
    return_stack::push(
        0,
        ReturnEntry {
            vm_id,
            return_gva: RETURN_ADDR_GVA,
            return_hva: ret_hva,
            saved_insn,
            entry_gva: ENTRY_ADDR_GVA,
            prog_id: 21,
        },
    )
    .unwrap();

    let removed = manager::detach_all_for_vm(vm_id);

    assert_eq!(removed, 1);
    assert!(!return_stack::has_pending(0, vm_id, RETURN_ADDR_GVA));
    assert_eq!(read_return_text(), expected_return_text());
}
