#![cfg(feature = "guest-kprobe")]

use axebpf::probe::kprobe::manager::{self, KprobeMode};
use axebpf::probe::kprobe::addr_translate::{
    register_guest_pt_read_hook, register_gva_to_hva_hook, register_vm_ttbr1_hook,
};
use axerrno::AxResult;

fn mock_vm_ttbr1(vm_id: u32) -> AxResult<u64> {
    Ok(0x2000_0000 + ((vm_id as u64) << 20))
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

fn setup_stage2_backends() {
    register_vm_ttbr1_hook(mock_vm_ttbr1);
    register_guest_pt_read_hook(mock_guest_pt_read);
    manager::register_stage2_exec_hook(mock_stage2_exec);
    #[cfg(feature = "test-utils")]
    manager::clear_stale_brk_for_test();
}

static mut MOCK_GUEST_TEXT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];

fn mock_gva_to_hva(_gva: u64, _vm_id: u32) -> AxResult<usize> {
    Ok(core::ptr::addr_of_mut!(MOCK_GUEST_TEXT) as usize)
}

#[cfg(feature = "test-utils")]
#[test]
fn attach_must_rollback_when_enable_fails() {
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
    manager::init();
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
