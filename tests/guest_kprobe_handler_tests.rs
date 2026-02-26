#![cfg(feature = "guest-kprobe")]

use axebpf::probe::kprobe::{
    addr_translate::{register_guest_pt_read_hook, register_gva_to_hva_hook, register_vm_ttbr1_hook},
    handler,
    manager::{self, KprobeMode},
};
use axerrno::AxResult;

static mut MOCK_GUEST_INSN: u32 = 0x1400_0000;

fn mock_vm_ttbr1(vm_id: u32) -> AxResult<u64> {
    Ok(0x1000_0000 + ((vm_id as u64) << 20))
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
        (0x4000_0000 + (index << 12)) | 0b11
    } else {
        return axerrno::ax_err!(NotFound, "mock pte missing");
    };
    Ok(desc)
}

fn mock_gva_to_hva(_gva: u64, _vm_id: u32) -> AxResult<usize> {
    let addr = core::ptr::addr_of_mut!(MOCK_GUEST_INSN) as usize;
    Ok(addr)
}

fn mock_stage2_exec(_vm_id: u32, _gpa: u64, _executable: bool) -> AxResult<()> {
    Ok(())
}

fn setup_mock_backends() {
    register_vm_ttbr1_hook(mock_vm_ttbr1);
    register_guest_pt_read_hook(mock_guest_pt_read);
    register_gva_to_hva_hook(mock_gva_to_hva);
    manager::register_stage2_exec_hook(mock_stage2_exec);
    #[cfg(feature = "test-utils")]
    manager::clear_stale_brk_for_test();
}

#[test]
fn stage2_match_must_return_true() {
    manager::init();
    setup_mock_backends();
    let vm_id = 7;
    let gva = 0xffff_8000_8000_1000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 1, false, KprobeMode::Stage2Fault).unwrap();
    let handled = handler::handle_stage2_exec_fault(vm_id, 0x1000, gva, true);
    assert!(handled, "matched stage2 fault must be handled");

    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn guest_brk_match_must_return_true() {
    manager::init();
    setup_mock_backends();
    let vm_id = 9;
    let pc = 0xffff_8000_8000_2000_u64;
    let _ = manager::detach(vm_id, pc);

    manager::attach(vm_id, pc, 2, false, KprobeMode::BrkInject).unwrap();
    let handled = handler::handle_guest_brk(vm_id, pc, 0x123);
    assert_eq!(
        handled,
        handler::GuestBrkHandleResult::ProbeHit,
        "matched guest brk must be handled as active probe hit"
    );

    manager::detach(vm_id, pc).unwrap();
}

#[test]
fn stale_guest_brk_after_detach_must_request_retry() {
    manager::init();
    setup_mock_backends();
    let vm_id = 10;
    let pc = 0xffff_8000_8000_3000_u64;
    let _ = manager::detach(vm_id, pc);

    manager::attach(vm_id, pc, 3, false, KprobeMode::BrkInject).unwrap();
    manager::detach(vm_id, pc).unwrap();

    let handled = handler::handle_guest_brk(vm_id, pc, 0);
    assert_eq!(
        handled,
        handler::GuestBrkHandleResult::RetryInstruction,
        "stale BRK after detach must be consumed and retried at same PC"
    );
}
