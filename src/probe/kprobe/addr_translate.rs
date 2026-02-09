//! Guest address translation: GVA → GPA → HVA.
//!
//! Walks the guest's page tables (read from TTBR1_EL1 in vCPU context)
//! and the Stage-2 page tables (managed by axaddrspace) to translate
//! guest virtual addresses to host virtual addresses accessible by VMM.

use axerrno::AxResult;

/// Translates a Guest Virtual Address (GVA) to a Guest Physical Address (GPA)
/// by walking the guest's EL1 page tables.
///
/// # Arguments
/// * `gva` - Guest virtual address to translate
/// * `ttbr1_el1` - Guest's TTBR1_EL1 register value (from vCPU context)
///
/// # Returns
/// The corresponding GPA, or error if translation fails.
pub fn gva_to_gpa(gva: u64, ttbr1_el1: u64) -> AxResult<u64> {
    // TODO: Implement AArch64 4-level page table walk
    // 1. Extract BADDR from TTBR1_EL1 (bits [47:1])
    // 2. Walk L0 → L1 → L2 → L3 tables using GVA index bits
    // 3. Each level: phys_to_virt(table_base), read entry, check valid bit
    // 4. Handle block entries (1GB at L1, 2MB at L2) and page entries (4KB at L3)
    let _ = (gva, ttbr1_el1);
    axerrno::ax_err!(Unsupported, "GVA→GPA translation not yet implemented")
}

/// Translates a Guest Physical Address (GPA) to a Host Physical Address (HPA)
/// by querying the Stage-2 page tables.
///
/// # Arguments
/// * `gpa` - Guest physical address
/// * `vm_id` - VM identifier to select the correct Stage-2 table
///
/// # Returns
/// The corresponding HPA, or error if not mapped.
pub fn gpa_to_hpa(gpa: u64, vm_id: u32) -> AxResult<u64> {
    // TODO: Query axaddrspace Stage-2 tables for this VM
    let _ = (gpa, vm_id);
    axerrno::ax_err!(Unsupported, "GPA→HPA translation not yet implemented")
}

/// Full translation chain: GVA → GPA → HPA → HVA.
///
/// # Arguments
/// * `gva` - Guest virtual address
/// * `ttbr1_el1` - Guest's TTBR1_EL1 register value
/// * `vm_id` - VM identifier
///
/// # Returns
/// Host virtual address that VMM can read/write directly.
pub fn gva_to_hva(gva: u64, ttbr1_el1: u64, vm_id: u32) -> AxResult<usize> {
    let gpa = gva_to_gpa(gva, ttbr1_el1)?;
    let _hpa = gpa_to_hpa(gpa, vm_id)?;
    // Linear mapping: HVA = phys_to_virt(HPA)
    // TODO: use axhal::mem::phys_to_virt or equivalent
    axerrno::ax_err!(Unsupported, "GVA→HVA translation not yet implemented")
}
