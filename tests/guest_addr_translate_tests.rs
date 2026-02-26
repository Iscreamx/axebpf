#![cfg(feature = "guest-kprobe")]

use alloc::collections::BTreeMap;
use axebpf::probe::kprobe::addr_translate::{GuestPtReader, gva_to_gpa_with};
use axerrno::AxResult;
#[cfg(feature = "test-utils")]
use axebpf::probe::kprobe::addr_translate::{
    clear_guest_pt_read_hook_for_test, clear_gva_to_hva_hook_for_test, clear_vm_ttbr1_hook_for_test,
    clear_gpa_to_hpa_hook_for_test, gpa_to_hpa, register_gpa_to_hpa_hook,
    gva_to_gpa_with_vm, gva_to_hva_for_vm, register_guest_pt_read_hook, register_gva_to_hva_hook,
    register_vm_ttbr1_hook,
};

extern crate alloc;

struct MockPtReader {
    entries: BTreeMap<u64, u64>,
}

impl MockPtReader {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    fn insert_entry(&mut self, table_base: u64, index: u64, entry: u64) {
        self.entries.insert(table_base + index * 8, entry);
    }
}

impl GuestPtReader for MockPtReader {
    fn read_u64(&self, paddr: u64) -> AxResult<u64> {
        self.entries
            .get(&paddr)
            .copied()
            .ok_or_else(|| axerrno::ax_err_type!(NotFound, "pte missing"))
    }
}

fn l0_index(gva: u64) -> u64 {
    (gva >> 39) & 0x1ff
}

fn l1_index(gva: u64) -> u64 {
    (gva >> 30) & 0x1ff
}

fn l2_index(gva: u64) -> u64 {
    (gva >> 21) & 0x1ff
}

fn l3_index(gva: u64) -> u64 {
    (gva >> 12) & 0x1ff
}

#[test]
fn l3_page_walk_translates_gva_to_gpa() {
    let mut mock = MockPtReader::new();
    let ttbr1 = 0x1000_0000_u64;
    let l1 = 0x1000_1000_u64;
    let l2 = 0x1000_2000_u64;
    let l3 = 0x1000_3000_u64;
    let gva = 0xffff_0000_1234_5678_u64;
    let page_base = 0x4000_5000_u64;

    mock.insert_entry(ttbr1, l0_index(gva), l1 | 0b11);
    mock.insert_entry(l1, l1_index(gva), l2 | 0b11);
    mock.insert_entry(l2, l2_index(gva), l3 | 0b11);
    mock.insert_entry(l3, l3_index(gva), page_base | 0b11);

    let gpa = gva_to_gpa_with(&mock, gva, ttbr1).unwrap();
    assert_eq!(gpa, page_base | (gva & 0xfff));
}

#[test]
fn l2_block_walk_translates_gva_to_gpa() {
    let mut mock = MockPtReader::new();
    let ttbr1 = 0x2000_0000_u64;
    let l1 = 0x2000_1000_u64;
    let l2 = 0x2000_2000_u64;
    let gva = 0xffff_8000_0065_4321_u64;
    let block_base = 0x6000_0000_u64;

    mock.insert_entry(ttbr1, l0_index(gva), l1 | 0b11);
    mock.insert_entry(l1, l1_index(gva), l2 | 0b11);
    mock.insert_entry(l2, l2_index(gva), block_base | 0b01);

    let gpa = gva_to_gpa_with(&mock, gva, ttbr1).unwrap();
    assert_eq!(gpa, block_base | (gva & ((1 << 21) - 1)));
}

#[test]
fn invalid_descriptor_returns_error() {
    let mut mock = MockPtReader::new();
    let ttbr1 = 0x3000_0000_u64;
    let gva = 0xffff_9000_0000_0000_u64;

    mock.insert_entry(ttbr1, l0_index(gva), 0);

    let ret = gva_to_gpa_with(&mock, gva, ttbr1);
    assert!(ret.is_err());
}

#[cfg(feature = "test-utils")]
#[test]
fn gpa_to_hpa_without_backend_returns_unsupported() {
    clear_gpa_to_hpa_hook_for_test();
    let err = gpa_to_hpa(0x2000, 1).unwrap_err();
    assert!(matches!(err, axerrno::AxError::Unsupported));
}

#[cfg(feature = "test-utils")]
fn mock_gpa_to_hpa(gpa: u64, vm_id: u32) -> AxResult<u64> {
    Ok(gpa + ((vm_id as u64) << 12))
}

#[cfg(feature = "test-utils")]
#[test]
fn gpa_to_hpa_uses_registered_backend() {
    clear_gpa_to_hpa_hook_for_test();
    register_gpa_to_hpa_hook(mock_gpa_to_hpa);
    let hpa = gpa_to_hpa(0x2000, 3).unwrap();
    assert_eq!(hpa, 0x5000);
    clear_gpa_to_hpa_hook_for_test();
}

#[cfg(feature = "test-utils")]
fn mock_vm_ttbr1(_vm_id: u32) -> AxResult<u64> {
    Ok(0x8000_0000)
}

#[cfg(feature = "test-utils")]
fn mock_guest_pt_read(paddr: u64, _vm_id: u32) -> AxResult<u64> {
    let l0 = 0x8000_0000_u64;
    let l1 = 0x8000_1000_u64;
    let l2 = 0x8000_2000_u64;
    let l3 = 0x8000_3000_u64;
    let gva = 0xffff_8000_0012_3456_u64;
    let page_base = 0x9000_5000_u64;

    if paddr == l0 + l0_index(gva) * 8 {
        return Ok(l1 | 0b11);
    }
    if paddr == l1 + l1_index(gva) * 8 {
        return Ok(l2 | 0b11);
    }
    if paddr == l2 + l2_index(gva) * 8 {
        return Ok(l3 | 0b11);
    }
    if paddr == l3 + l3_index(gva) * 8 {
        return Ok(page_base | 0b11);
    }

    axerrno::ax_err!(NotFound, "mock pte missing")
}

#[cfg(feature = "test-utils")]
#[test]
fn gva_to_gpa_with_vm_uses_registered_ttbr1_and_reader() {
    clear_vm_ttbr1_hook_for_test();
    clear_guest_pt_read_hook_for_test();
    register_vm_ttbr1_hook(mock_vm_ttbr1);
    register_guest_pt_read_hook(mock_guest_pt_read);

    let gva = 0xffff_8000_0012_3456_u64;
    let gpa = gva_to_gpa_with_vm(gva, 1).unwrap();
    assert_eq!(gpa, 0x9000_5456_u64);

    clear_guest_pt_read_hook_for_test();
    clear_vm_ttbr1_hook_for_test();
}

#[cfg(feature = "test-utils")]
fn mock_gva_to_hva(_gva: u64, vm_id: u32) -> AxResult<usize> {
    Ok(0x1000_0000 + vm_id as usize)
}

#[cfg(feature = "test-utils")]
#[test]
fn gva_to_hva_for_vm_prefers_direct_hook() {
    clear_gva_to_hva_hook_for_test();
    register_gva_to_hva_hook(mock_gva_to_hva);
    let hva = gva_to_hva_for_vm(0x1234, 7).unwrap();
    assert_eq!(hva, 0x1000_0007);
    clear_gva_to_hva_hook_for_test();
}
