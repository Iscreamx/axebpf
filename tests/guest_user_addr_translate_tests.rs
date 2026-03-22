#![cfg(feature = "guest-uprobe")]

use std::sync::Mutex;

use axebpf::probe::uprobe::addr_translate::{
    gva_to_gpa_user_with_vm, register_guest_pt_read_hook, register_vm_ttbr0_hook,
};
use axebpf::probe::guest_runtime_state::{
    LiveGuestRuntimeState, clear_live_guest_runtime_state_for_test,
    install_live_guest_runtime_state,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn user_addr_translate_uses_ttbr0_hook() {
    let _guard = TEST_LOCK.lock().unwrap();
    register_vm_ttbr0_hook(|_| Ok(0x2000_0000));
    register_guest_pt_read_hook(|paddr, _| {
        let table_base = paddr & !0xfff;
        let desc = match table_base {
            0x2000_0000 => 0x2000_1000 | 0b11,
            0x2000_1000 => 0x2000_2000 | 0b11,
            0x2000_2000 => 0x2000_3000 | 0b11,
            _ => 0x4000_0000 | 0b11,
        };
        Ok(desc)
    });

    let gpa = gva_to_gpa_user_with_vm(0x7fff_1234_5000, 1).unwrap();
    assert_eq!(gpa, 0x4000_0000);
}

#[test]
fn user_l2_block_translate_ignores_descriptor_attribute_bits() {
    let _guard = TEST_LOCK.lock().unwrap();
    const TTBR0: u64 = 0x3000_0000;
    const L1: u64 = 0x3000_1000;
    const L2: u64 = 0x3000_2000;
    const BLOCK_BASE: u64 = 0x4780_0000;
    const GVA: u64 = 0x7fff_1234_5678;
    const XN: u64 = 1_u64 << 54;

    register_vm_ttbr0_hook(|_| Ok(TTBR0));
    register_guest_pt_read_hook(|paddr, _| {
        if paddr == TTBR0 + (((GVA >> 39) & 0x1ff) * 8) {
            return Ok(L1 | 0b11);
        }
        if paddr == L1 + (((GVA >> 30) & 0x1ff) * 8) {
            return Ok(L2 | 0b11);
        }
        if paddr == L2 + (((GVA >> 21) & 0x1ff) * 8) {
            return Ok(BLOCK_BASE | XN | 0b01);
        }
        axerrno::ax_err!(NotFound, "mock pte missing")
    });

    let gpa = gva_to_gpa_user_with_vm(GVA, 1).unwrap();
    assert_eq!(gpa, BLOCK_BASE | (GVA & ((1 << 21) - 1)));
}

#[test]
fn user_addr_translate_prefers_live_guest_ttbr0_over_cached_hook() {
    let _guard = TEST_LOCK.lock().unwrap();
    const STALE_TTBR0: u64 = 0x3100_0000;
    const LIVE_TTBR0: u64 = 0x3200_0000;
    const L1: u64 = 0x3200_1000;
    const L2: u64 = 0x3200_2000;
    const L3: u64 = 0x3200_3000;
    const PAGE_BASE: u64 = 0x4780_4000;
    const GVA: u64 = 0x7fff_1234_5000;

    clear_live_guest_runtime_state_for_test();
    register_vm_ttbr0_hook(|_| Ok(STALE_TTBR0));
    let _live_state = install_live_guest_runtime_state(LiveGuestRuntimeState {
        vm_id: 1,
        ttbr0_el1: LIVE_TTBR0,
        ttbr1_el1: 0,
        contextidr_el1: 0,
        sp_el0: 0,
        tpidr_el0: 0,
        guest_spsr: 0,
    });
    register_guest_pt_read_hook(|paddr, _| {
        if paddr == LIVE_TTBR0 + (((GVA >> 39) & 0x1ff) * 8) {
            return Ok(L1 | 0b11);
        }
        if paddr == L1 + (((GVA >> 30) & 0x1ff) * 8) {
            return Ok(L2 | 0b11);
        }
        if paddr == L2 + (((GVA >> 21) & 0x1ff) * 8) {
            return Ok(L3 | 0b11);
        }
        if paddr == L3 + (((GVA >> 12) & 0x1ff) * 8) {
            return Ok(PAGE_BASE | 0b11);
        }
        axerrno::ax_err!(NotFound, "mock pte missing")
    });

    let gpa = gva_to_gpa_user_with_vm(GVA, 1).unwrap();
    assert_eq!(gpa, PAGE_BASE);

    clear_live_guest_runtime_state_for_test();
}
