//! Virtual memory mapping for kbpf-basic RingBuf support.
//!
//! Provides vmap/unmap: maps arbitrary physical pages into a contiguous
//! virtual address range in the EL2 Stage-1 page table (TTBR0_EL2).
//! AArch64 only.

#[cfg(target_arch = "aarch64")]
use alloc::vec::Vec;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_arch = "aarch64")]
use spin::Mutex;

#[cfg(target_arch = "aarch64")]
const PAGE_SIZE: usize = 0x1000;

/// Base VA for vmap region.
///
/// Keep this in the same lower-half VA space used by the current EL2 kernel
/// mappings. Using a high-half address here can fault before TTBR1 is active.
#[cfg(target_arch = "aarch64")]
const VMAP_BASE: usize = 0x0000_F900_0000_0000;
#[cfg(target_arch = "aarch64")]
const VMAP_SIZE: usize = 0x0000_0100_0000_0000; // 1TB vmap region

/// Bump allocator for VA space
#[cfg(target_arch = "aarch64")]
static VMAP_NEXT: AtomicUsize = AtomicUsize::new(VMAP_BASE);

/// Track active mappings for unmap: (vaddr, page_count)
#[cfg(target_arch = "aarch64")]
static VMAP_REGIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

// AArch64 page table constants
#[cfg(target_arch = "aarch64")]
mod pte {
    pub const VALID: u64 = 1 << 0;
    pub const TABLE: u64 = 1 << 1;       // table descriptor (L0-L2)
    pub const PAGE: u64 = 1 << 1;        // page descriptor (L3, same bit)
    pub const AF: u64 = 1 << 10;         // access flag
    pub const SH_ISH: u64 = 0b11 << 8;   // inner shareable
    pub const AP_RW: u64 = 0b00 << 6;    // EL2 R/W
    pub const ATTR_IDX_NORMAL: u64 = 0 << 2; // normal memory (MAIR index 0)
    pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    /// Standard L3 page entry flags for normal RW memory
    pub const L3_PAGE_FLAGS: u64 = VALID | PAGE | AF | SH_ISH | AP_RW | ATTR_IDX_NORMAL;

    /// Table descriptor flags (L0/L1/L2 pointing to next-level table)
    pub const TABLE_FLAGS: u64 = VALID | TABLE;
}

/// Read TTBR0_EL2 to get page table root physical address
#[cfg(target_arch = "aarch64")]
fn page_table_root_phys() -> u64 {
    let ttbr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el2", out(reg) ttbr, options(nomem, nostack));
    }
    ttbr & pte::ADDR_MASK
}

#[cfg(target_arch = "aarch64")]
fn phys_to_virt(paddr: u64) -> usize {
    axhal::mem::phys_to_virt((paddr as usize).into()).as_usize()
}

#[cfg(target_arch = "aarch64")]
fn virt_to_phys(vaddr: usize) -> u64 {
    axhal::mem::virt_to_phys((vaddr).into()).as_usize() as u64
}

/// Flush all EL2 TLB entries (inner shareable domain)
#[cfg(target_arch = "aarch64")]
fn flush_tlb() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            options(nomem, nostack),
        );
    }
}

/// Allocate a zeroed physical page and return its physical address.
#[cfg(target_arch = "aarch64")]
fn alloc_table_page() -> Option<u64> {
    let vaddr = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE, axalloc::UsageKind::PageTable)
        .ok()?;
    unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, PAGE_SIZE); }
    Some(virt_to_phys(vaddr))
}

/// Get or create a page table entry at the given level.
/// `table_paddr` is the physical address of the current-level table.
/// `index` is the entry index within this table (0..511).
/// If the entry is not valid, allocates a new table page.
/// Returns the physical address of the next-level table.
#[cfg(target_arch = "aarch64")]
fn get_or_create_table(table_paddr: u64, index: usize) -> Option<u64> {
    let table_vaddr = phys_to_virt(table_paddr);
    let entry_ptr = (table_vaddr + index * 8) as *mut u64;
    let entry = unsafe { core::ptr::read_volatile(entry_ptr) };

    if entry & pte::VALID != 0 {
        // Entry exists — return next-level table address
        // Check it's a table descriptor (not a block)
        if entry & pte::TABLE == 0 {
            log::warn!("vmap: encountered block descriptor at index {}", index);
            return None;
        }
        Some(entry & pte::ADDR_MASK)
    } else {
        // Allocate new table page
        let new_table_paddr = alloc_table_page()?;
        let new_entry = new_table_paddr | pte::TABLE_FLAGS;
        unsafe { core::ptr::write_volatile(entry_ptr, new_entry); }
        Some(new_table_paddr)
    }
}

/// Install an L3 page entry mapping `vaddr` -> `paddr`.
#[cfg(target_arch = "aarch64")]
fn map_page(vaddr: usize, paddr: usize) -> bool {
    let root_paddr = page_table_root_phys();

    // AArch64 4-level page table indices (48-bit VA, 4KB granule)
    let l0_idx = (vaddr >> 39) & 0x1FF;
    let l1_idx = (vaddr >> 30) & 0x1FF;
    let l2_idx = (vaddr >> 21) & 0x1FF;
    let l3_idx = (vaddr >> 12) & 0x1FF;

    // Walk L0 -> L1 -> L2, creating tables as needed
    let l1_paddr = match get_or_create_table(root_paddr, l0_idx) {
        Some(p) => p,
        None => return false,
    };
    let l2_paddr = match get_or_create_table(l1_paddr, l1_idx) {
        Some(p) => p,
        None => return false,
    };
    let l3_paddr = match get_or_create_table(l2_paddr, l2_idx) {
        Some(p) => p,
        None => return false,
    };

    // Install L3 entry
    let l3_vaddr = phys_to_virt(l3_paddr);
    let entry_ptr = (l3_vaddr + l3_idx * 8) as *mut u64;
    let entry = (paddr as u64 & pte::ADDR_MASK) | pte::L3_PAGE_FLAGS;
    unsafe { core::ptr::write_volatile(entry_ptr, entry); }

    true
}

/// Unmap a single page by clearing its L3 PTE.
#[cfg(target_arch = "aarch64")]
fn unmap_page(vaddr: usize) {
    let root_paddr = page_table_root_phys();

    let l0_idx = (vaddr >> 39) & 0x1FF;
    let l1_idx = (vaddr >> 30) & 0x1FF;
    let l2_idx = (vaddr >> 21) & 0x1FF;
    let l3_idx = (vaddr >> 12) & 0x1FF;

    // Walk existing tables — don't create new ones
    let l0_vaddr = phys_to_virt(root_paddr);
    let l0_entry = unsafe { core::ptr::read_volatile((l0_vaddr + l0_idx * 8) as *const u64) };
    if l0_entry & pte::VALID == 0 { return; }

    let l1_vaddr = phys_to_virt(l0_entry & pte::ADDR_MASK);
    let l1_entry = unsafe { core::ptr::read_volatile((l1_vaddr + l1_idx * 8) as *const u64) };
    if l1_entry & pte::VALID == 0 { return; }

    let l2_vaddr = phys_to_virt(l1_entry & pte::ADDR_MASK);
    let l2_entry = unsafe { core::ptr::read_volatile((l2_vaddr + l2_idx * 8) as *const u64) };
    if l2_entry & pte::VALID == 0 { return; }

    let l3_vaddr = phys_to_virt(l2_entry & pte::ADDR_MASK);
    let entry_ptr = (l3_vaddr + l3_idx * 8) as *mut u64;
    unsafe { core::ptr::write_volatile(entry_ptr, 0); }
}

/// Map an array of physical pages into a contiguous virtual address range.
///
/// Called by kbpf-basic's RingBuf implementation. The `phys_addrs` slice
/// contains `nr_meta_pages + 2 * nr_data_pages` entries (data pages appear
/// twice for wrap-around zero-copy reads).
///
/// Returns the starting virtual address of the mapped region.
#[cfg(target_arch = "aarch64")]
pub fn vmap(phys_addrs: &[usize]) -> Option<usize> {
    let nr_pages = phys_addrs.len();
    if nr_pages == 0 {
        return None;
    }

    // Allocate VA range (bump allocator)
    let vaddr = VMAP_NEXT.fetch_add(nr_pages * PAGE_SIZE, Ordering::SeqCst);
    if vaddr + nr_pages * PAGE_SIZE > VMAP_BASE + VMAP_SIZE {
        log::error!("vmap: VA space exhausted");
        return None;
    }

    // Map each page
    for (i, &paddr) in phys_addrs.iter().enumerate() {
        let page_vaddr = vaddr + i * PAGE_SIZE;
        if !map_page(page_vaddr, paddr) {
            log::error!("vmap: failed to map page {} at vaddr={:#x} paddr={:#x}", i, page_vaddr, paddr);
            // Unmap already-mapped pages
            for j in 0..i {
                unmap_page(vaddr + j * PAGE_SIZE);
            }
            flush_tlb();
            return None;
        }
    }

    flush_tlb();

    // Record for unmap
    VMAP_REGIONS.lock().push((vaddr, nr_pages));

    log::info!(
        "vmap: mapped {} pages at {:#x}..{:#x}",
        nr_pages, vaddr, vaddr + nr_pages * PAGE_SIZE
    );

    Some(vaddr)
}

/// Unmap a previously vmapped region.
#[cfg(target_arch = "aarch64")]
pub fn unmap(vaddr: usize) {
    let nr_pages = {
        let mut regions = VMAP_REGIONS.lock();
        let idx = regions.iter().position(|(v, _)| *v == vaddr);
        match idx {
            Some(i) => {
                let (_, nr) = regions.remove(i);
                nr
            }
            None => {
                log::warn!("unmap: unknown vaddr {:#x}", vaddr);
                return;
            }
        }
    };

    for i in 0..nr_pages {
        unmap_page(vaddr + i * PAGE_SIZE);
    }

    flush_tlb();

    log::info!("unmap: unmapped {} pages at {:#x}", nr_pages, vaddr);
}

#[cfg(not(target_arch = "aarch64"))]
pub fn vmap(_phys_addrs: &[usize]) -> Option<usize> {
    None
}

#[cfg(not(target_arch = "aarch64"))]
pub fn unmap(_vaddr: usize) {}
