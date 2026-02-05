//! Stage 1 page table operations for modifying kernel text permissions.
//!
//! Kprobe needs to temporarily make kernel code writable to insert breakpoints.
//! This module provides low-level page table manipulation for the Hypervisor's
//! own address space (Stage 1, EL2).

use crate::cache::flush_icache_range;

/// Page size (4KB)
const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// AArch64 Stage 1 page table entry bits
#[cfg(target_arch = "aarch64")]
mod pte_bits {
    /// Access Permission bit [7] - 0=RW, 1=RO for EL2
    pub const AP_RO_BIT: u64 = 1 << 7;
    /// Valid bit
    pub const VALID: u64 = 1 << 0;
    /// Table/Block bit
    pub const TABLE: u64 = 1 << 1;
    /// Address mask for next-level table or output address
    pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
}

/// Convert physical address to virtual address using axhal's mapping.
#[cfg(target_arch = "aarch64")]
#[inline]
fn phys_to_virt(paddr: u64) -> usize {
    let vaddr = axhal::mem::phys_to_virt((paddr as usize).into()).as_usize();
    log::trace!("page_table: phys_to_virt {:#x} -> {:#x}", paddr, vaddr);
    vaddr
}

/// Read TTBR0_EL2 to get Stage 1 page table root (physical address).
#[cfg(target_arch = "aarch64")]
fn get_page_table_root_phys() -> u64 {
    let ttbr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, ttbr0_el2",
            out(reg) ttbr,
            options(nostack, preserves_flags)
        );
    }
    // Clear ASID bits and get physical address
    ttbr & 0x0000_FFFF_FFFF_F000
}

/// Walk the 4-level page table to find the PTE for a virtual address.
/// Returns a mutable pointer to the PTE, or None if the mapping doesn't exist.
#[cfg(target_arch = "aarch64")]
unsafe fn walk_page_table(vaddr: usize) -> Option<*mut u64> {
    use pte_bits::*;

    let root_phys = get_page_table_root_phys();
    if root_phys == 0 {
        log::error!("page_table: TTBR0_EL2 is null");
        return None;
    }

    // Convert physical address to virtual address for access
    let root_virt = phys_to_virt(root_phys);

    log::trace!("page_table: root_phys={:#x}, root_virt={:#x}", root_phys, root_virt);

    // 4-level page table indices (9 bits each)
    let l0_idx = (vaddr >> 39) & 0x1FF;
    let l1_idx = (vaddr >> 30) & 0x1FF;
    let l2_idx = (vaddr >> 21) & 0x1FF;
    let l3_idx = (vaddr >> 12) & 0x1FF;

    // L0 -> L1
    let l0_table = root_virt as *const u64;
    let l0_entry = *l0_table.add(l0_idx);
    log::trace!("page_table: L0[{}] = {:#x}", l0_idx, l0_entry);
    if (l0_entry & VALID) == 0 {
        log::error!("page_table: L0 entry invalid for {:#x}", vaddr);
        return None;
    }
    let l1_table_phys = l0_entry & ADDR_MASK;
    let l1_table = phys_to_virt(l1_table_phys) as *const u64;

    // L1 -> L2 (check for 1GB block)
    let l1_entry = *l1_table.add(l1_idx);
    log::trace!("page_table: L1[{}] = {:#x}", l1_idx, l1_entry);
    if (l1_entry & VALID) == 0 {
        log::error!("page_table: L1 entry invalid for {:#x}", vaddr);
        return None;
    }
    if (l1_entry & TABLE) == 0 {
        // 1GB block mapping - return pointer to L1 entry
        log::trace!("page_table: 1GB block at L1");
        return Some(l1_table.add(l1_idx) as *mut u64);
    }
    let l2_table_phys = l1_entry & ADDR_MASK;
    let l2_table = phys_to_virt(l2_table_phys) as *const u64;

    // L2 -> L3 (check for 2MB block)
    let l2_entry = *l2_table.add(l2_idx);
    log::trace!("page_table: L2[{}] = {:#x}", l2_idx, l2_entry);
    if (l2_entry & VALID) == 0 {
        log::error!("page_table: L2 entry invalid for {:#x}", vaddr);
        return None;
    }
    if (l2_entry & TABLE) == 0 {
        // 2MB block mapping - return pointer to L2 entry
        log::trace!("page_table: 2MB block at L2");
        return Some(l2_table.add(l2_idx) as *mut u64);
    }
    let l3_table_phys = l2_entry & ADDR_MASK;
    let l3_table = phys_to_virt(l3_table_phys) as *mut u64;

    // L3 entry (4KB page)
    let l3_entry = *l3_table.add(l3_idx);
    log::trace!("page_table: L3[{}] = {:#x}", l3_idx, l3_entry);
    if (l3_entry & VALID) == 0 {
        log::error!("page_table: L3 entry invalid for {:#x}", vaddr);
        return None;
    }

    Some(l3_table.add(l3_idx))
}

/// Flush TLB for all entries at EL2.
#[cfg(target_arch = "aarch64")]
fn flush_tlb() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",        // Ensure PTE write is visible
            "tlbi alle2is",     // Invalidate all EL2 TLB entries (inner shareable)
            "dsb ish",          // Wait for TLB invalidation
            "isb",              // Synchronize context
            options(nostack, preserves_flags)
        );
    }
}

/// Temporarily modify kernel text permissions to allow writing.
///
/// # Safety
/// This function modifies page table entries. Caller must ensure:
/// - The address range is valid kernel text
/// - No concurrent modifications to the same pages
/// - Permissions are restored after modification
#[cfg(target_arch = "aarch64")]
pub fn set_kernel_text_writable(addr: usize, size: usize, writable: bool) -> bool {
    use pte_bits::*;

    let start_page = addr & PAGE_MASK;
    let end_page = (addr + size + PAGE_SIZE - 1) & PAGE_MASK;

    log::info!(
        "page_table: set_kernel_text_writable {:#x}-{:#x} writable={}",
        start_page, end_page, writable
    );

    // Read TTBR0_EL2 to verify it's accessible
    let ttbr = get_page_table_root_phys();
    log::info!("page_table: TTBR0_EL2 = {:#x}", ttbr);

    let mut success = true;

    for page in (start_page..end_page).step_by(PAGE_SIZE) {
        unsafe {
            if let Some(pte_ptr) = walk_page_table(page) {
                let mut pte = core::ptr::read_volatile(pte_ptr);
                let old_pte = pte;

                if writable {
                    pte &= !AP_RO_BIT;  // Clear AP[2] -> RW
                } else {
                    pte |= AP_RO_BIT;   // Set AP[2] -> RO
                }

                if pte != old_pte {
                    core::ptr::write_volatile(pte_ptr, pte);
                    log::trace!(
                        "page_table: modified PTE for {:#x}: {:#x} -> {:#x}",
                        page, old_pte, pte
                    );
                }
            } else {
                log::error!("page_table: failed to find PTE for {:#x}", page);
                success = false;
            }
        }
    }

    if success {
        flush_tlb();
    }

    success
}

/// Write data to kernel text after temporarily making it writable.
/// This is the main entry point for kprobe text patching.
#[cfg(target_arch = "aarch64")]
pub fn write_kernel_text(addr: usize, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    log::debug!("write_kernel_text: addr={:#x} len={}", addr, data.len());

    // Step 1: Make writable
    if !set_kernel_text_writable(addr, data.len(), true) {
        log::error!("write_kernel_text: failed to make {:#x} writable", addr);
        return false;
    }

    // Step 2: Write data
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }

    // Step 3: Restore read-only
    set_kernel_text_writable(addr, data.len(), false);

    // Step 4: Flush I-cache
    flush_icache_range(addr, addr + data.len());

    log::debug!("write_kernel_text: success");
    true
}

// Stub implementations for other architectures
#[cfg(not(target_arch = "aarch64"))]
pub fn set_kernel_text_writable(_addr: usize, _size: usize, _writable: bool) -> bool {
    log::warn!("set_kernel_text_writable: not implemented for this architecture");
    false
}

#[cfg(not(target_arch = "aarch64"))]
pub fn write_kernel_text(_addr: usize, _data: &[u8]) -> bool {
    log::warn!("write_kernel_text: not implemented for this architecture");
    false
}
