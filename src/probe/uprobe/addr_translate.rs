//! Guest user address translation: user VA -> GPA/HVA.
//!
//! The runtime observer needs TTBR0_EL1-driven guest user page-table walking
//! plus a bounded helper for reading user-space strings.

extern crate alloc;

use alloc::string::String;

use axerrno::AxResult;

const DESC_TYPE_MASK: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const DESC_TABLE_OR_PAGE: u64 = 0b11;
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const PAGE_OFFSET_MASK: u64 = 0xfff;
const L1_BLOCK_OFFSET_MASK: u64 = (1 << 30) - 1;
const L2_BLOCK_OFFSET_MASK: u64 = (1 << 21) - 1;
const L1_BLOCK_ADDR_MASK: u64 = DESC_ADDR_MASK & !L1_BLOCK_OFFSET_MASK;
const L2_BLOCK_ADDR_MASK: u64 = DESC_ADDR_MASK & !L2_BLOCK_OFFSET_MASK;

type ReadGuestPteFn = fn(paddr: u64, vm_id: u32) -> AxResult<u64>;
type VmTtbr0Fn = fn(vm_id: u32) -> AxResult<u64>;
type GpaToHpaFn = fn(gpa: u64, vm_id: u32) -> AxResult<u64>;
type GvaToHvaFn = fn(gva: u64, vm_id: u32) -> AxResult<usize>;

pub trait GuestPtReader {
    fn read_u64(&self, paddr: u64) -> AxResult<u64>;
}

struct HookReader {
    vm_id: u32,
}

static GUEST_PT_READ_HOOK: spin::RwLock<Option<ReadGuestPteFn>> = spin::RwLock::new(None);
static VM_TTBR0_HOOK: spin::RwLock<Option<VmTtbr0Fn>> = spin::RwLock::new(None);
static GPA_TO_HPA_HOOK: spin::RwLock<Option<GpaToHpaFn>> = spin::RwLock::new(None);
static GVA_TO_HVA_HOOK: spin::RwLock<Option<GvaToHvaFn>> = spin::RwLock::new(None);

impl GuestPtReader for HookReader {
    fn read_u64(&self, paddr: u64) -> AxResult<u64> {
        let hook = *GUEST_PT_READ_HOOK.read();
        let Some(f) = hook else {
            return axerrno::ax_err!(Unsupported, "guest page-table reader not registered");
        };
        f(paddr, self.vm_id)
    }
}

#[inline]
fn table_index(gva: u64, shift: u64) -> u64 {
    (gva >> shift) & 0x1ff
}

#[inline]
fn read_entry<R: GuestPtReader>(reader: &R, table_base: u64, index: u64) -> AxResult<u64> {
    reader.read_u64(table_base + index * 8)
}

#[inline]
fn is_valid_desc(desc: u64) -> bool {
    (desc & 1) != 0
}

#[inline]
fn desc_type(desc: u64) -> u64 {
    desc & DESC_TYPE_MASK
}

pub fn gva_to_gpa_user_with<R: GuestPtReader>(
    reader: &R,
    gva: u64,
    ttbr0_el1: u64,
) -> AxResult<u64> {
    let l0_base = ttbr0_el1 & DESC_ADDR_MASK;

    let l0 = read_entry(reader, l0_base, table_index(gva, 39))?;
    if !is_valid_desc(l0) || desc_type(l0) != DESC_TABLE_OR_PAGE {
        return axerrno::ax_err!(BadState, "invalid L0 descriptor");
    }

    let l1_base = l0 & DESC_ADDR_MASK;
    let l1 = read_entry(reader, l1_base, table_index(gva, 30))?;
    if !is_valid_desc(l1) {
        return axerrno::ax_err!(BadState, "invalid L1 descriptor");
    }
    if desc_type(l1) == DESC_BLOCK {
        let base = l1 & L1_BLOCK_ADDR_MASK;
        return Ok(base | (gva & L1_BLOCK_OFFSET_MASK));
    }
    if desc_type(l1) != DESC_TABLE_OR_PAGE {
        return axerrno::ax_err!(BadState, "unsupported L1 descriptor");
    }

    let l2_base = l1 & DESC_ADDR_MASK;
    let l2 = read_entry(reader, l2_base, table_index(gva, 21))?;
    if !is_valid_desc(l2) {
        return axerrno::ax_err!(BadState, "invalid L2 descriptor");
    }
    if desc_type(l2) == DESC_BLOCK {
        let base = l2 & L2_BLOCK_ADDR_MASK;
        return Ok(base | (gva & L2_BLOCK_OFFSET_MASK));
    }
    if desc_type(l2) != DESC_TABLE_OR_PAGE {
        return axerrno::ax_err!(BadState, "unsupported L2 descriptor");
    }

    let l3_base = l2 & DESC_ADDR_MASK;
    let l3 = read_entry(reader, l3_base, table_index(gva, 12))?;
    if !is_valid_desc(l3) || desc_type(l3) != DESC_TABLE_OR_PAGE {
        return axerrno::ax_err!(BadState, "invalid L3 descriptor");
    }

    let page_base = l3 & DESC_ADDR_MASK;
    Ok(page_base | (gva & PAGE_OFFSET_MASK))
}

pub fn register_guest_pt_read_hook(f: ReadGuestPteFn) {
    *GUEST_PT_READ_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_guest_pt_read_hook_for_test() {
    *GUEST_PT_READ_HOOK.write() = None;
}

pub fn register_vm_ttbr0_hook(f: VmTtbr0Fn) {
    *VM_TTBR0_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_vm_ttbr0_hook_for_test() {
    *VM_TTBR0_HOOK.write() = None;
}

pub fn vm_ttbr0_el1(vm_id: u32) -> AxResult<u64> {
    if let Some(state) = crate::probe::guest_runtime_state::current_live_guest_runtime_state(vm_id)
        && state.ttbr0_el1 != 0
    {
        return Ok(state.ttbr0_el1);
    }
    let hook = *VM_TTBR0_HOOK.read();
    let Some(f) = hook else {
        return axerrno::ax_err!(Unsupported, "VM TTBR0_EL1 hook not registered");
    };
    f(vm_id)
}

pub fn register_gpa_to_hpa_hook(f: GpaToHpaFn) {
    *GPA_TO_HPA_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_gpa_to_hpa_hook_for_test() {
    *GPA_TO_HPA_HOOK.write() = None;
}

pub fn register_gva_to_hva_hook(f: GvaToHvaFn) {
    *GVA_TO_HVA_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_gva_to_hva_hook_for_test() {
    *GVA_TO_HVA_HOOK.write() = None;
}

pub fn gva_to_gpa_user_with_vm(gva: u64, vm_id: u32) -> AxResult<u64> {
    let ttbr0 = vm_ttbr0_el1(vm_id)?;
    let reader = HookReader { vm_id };
    gva_to_gpa_user_with(&reader, gva, ttbr0)
}

fn gpa_to_hpa(gpa: u64, vm_id: u32) -> AxResult<u64> {
    let hook = *GPA_TO_HPA_HOOK.read();
    let Some(f) = hook else {
        return axerrno::ax_err!(Unsupported, "GPA->HPA hook not registered");
    };
    f(gpa, vm_id)
}

pub fn gva_to_hva_user_with_vm(gva: u64, vm_id: u32) -> AxResult<usize> {
    let direct = *GVA_TO_HVA_HOOK.read();
    if let Some(f) = direct {
        return f(gva, vm_id);
    }

    let gpa = gva_to_gpa_user_with_vm(gva, vm_id)?;
    let hpa = gpa_to_hpa(gpa, vm_id)?;
    #[cfg(feature = "axhal")]
    {
        let hpa = usize::try_from(hpa)
            .map_err(|_| axerrno::ax_err_type!(InvalidInput, "HPA out of range"))?;
        Ok(axhal::mem::phys_to_virt(hpa.into()).as_usize())
    }
    #[cfg(not(feature = "axhal"))]
    {
        let _ = hpa;
        axerrno::ax_err!(
            Unsupported,
            "user GVA->HVA translation needs `axhal` feature or direct HVA hook"
        )
    }
}

pub fn read_user_cstring_with_vm(vm_id: u32, user_gva: u64, max_len: usize) -> AxResult<String> {
    if max_len == 0 {
        return axerrno::ax_err!(InvalidInput, "max_len must be greater than zero");
    }

    let mut bytes = alloc::vec::Vec::with_capacity(core::cmp::min(max_len, 256));
    for idx in 0..max_len {
        let gva = user_gva
            .checked_add(idx as u64)
            .ok_or_else(|| axerrno::ax_err_type!(InvalidInput, "user GVA overflow"))?;
        let hva = gva_to_hva_user_with_vm(gva, vm_id)?;
        let byte = unsafe { core::ptr::read_volatile(hva as *const u8) };
        if byte == 0 {
            return String::from_utf8(bytes)
                .map_err(|_| axerrno::ax_err_type!(InvalidData, "user string is not valid UTF-8"));
        }
        bytes.push(byte);
    }

    axerrno::ax_err!(InvalidInput, "user string exceeds max_len or missing NUL")
}
