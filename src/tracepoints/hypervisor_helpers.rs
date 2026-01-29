//! Hypervisor-specific eBPF helper functions.
//!
//! These helpers provide VMM context to eBPF programs.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Helper function IDs for hypervisor helpers.
pub mod hypervisor_helper_ids {
    /// bpf_get_current_vm_id() -> vm_id
    pub const GET_CURRENT_VM_ID: u32 = 100;
    /// bpf_get_current_vcpu_id() -> vcpu_id
    pub const GET_CURRENT_VCPU_ID: u32 = 101;
    /// bpf_get_exit_reason() -> exit_reason
    pub const GET_EXIT_REASON: u32 = 102;
}

// Per-CPU context storage for current VM/vCPU info
// In a real implementation, this would use percpu variables
static CURRENT_VM_ID: AtomicU32 = AtomicU32::new(0);
static CURRENT_VCPU_ID: AtomicU32 = AtomicU32::new(0);
static CURRENT_EXIT_REASON: AtomicU64 = AtomicU64::new(0);

/// Set current VM context (called before eBPF program execution).
pub fn set_current_context(vm_id: u32, vcpu_id: u32, exit_reason: u64) {
    CURRENT_VM_ID.store(vm_id, Ordering::Relaxed);
    CURRENT_VCPU_ID.store(vcpu_id, Ordering::Relaxed);
    CURRENT_EXIT_REASON.store(exit_reason, Ordering::Relaxed);
}

/// Clear current VM context.
pub fn clear_current_context() {
    CURRENT_VM_ID.store(0, Ordering::Relaxed);
    CURRENT_VCPU_ID.store(0, Ordering::Relaxed);
    CURRENT_EXIT_REASON.store(0, Ordering::Relaxed);
}

/// bpf_get_current_vm_id - get current VM ID.
fn bpf_get_current_vm_id(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    CURRENT_VM_ID.load(Ordering::Relaxed) as u64
}

/// bpf_get_current_vcpu_id - get current vCPU ID.
fn bpf_get_current_vcpu_id(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    CURRENT_VCPU_ID.load(Ordering::Relaxed) as u64
}

/// bpf_get_exit_reason - get VM exit reason.
fn bpf_get_exit_reason(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    CURRENT_EXIT_REASON.load(Ordering::Relaxed)
}

/// Get a hypervisor helper function by ID.
pub fn get_hypervisor_helper(id: u32) -> Option<crate::helpers::HelperFn> {
    match id {
        hypervisor_helper_ids::GET_CURRENT_VM_ID => Some(bpf_get_current_vm_id),
        hypervisor_helper_ids::GET_CURRENT_VCPU_ID => Some(bpf_get_current_vcpu_id),
        hypervisor_helper_ids::GET_EXIT_REASON => Some(bpf_get_exit_reason),
        _ => None,
    }
}

/// List of supported hypervisor helper IDs.
pub const HYPERVISOR_HELPERS: &[u32] = &[
    hypervisor_helper_ids::GET_CURRENT_VM_ID,
    hypervisor_helper_ids::GET_CURRENT_VCPU_ID,
    hypervisor_helper_ids::GET_EXIT_REASON,
];

/// Register hypervisor helpers to an rbpf VM.
pub fn register_hypervisor_helpers(vm: &mut rbpf::EbpfVmNoData) {
    for &id in HYPERVISOR_HELPERS {
        if let Some(helper) = get_hypervisor_helper(id)
            && let Err(e) = vm.register_helper(id, helper)
        {
            log::warn!("Failed to register hypervisor helper {}: {:?}", id, e);
        }
    }
    log::debug!("Registered {} hypervisor helpers", HYPERVISOR_HELPERS.len());
}

/// Register hypervisor helpers to an rbpf EbpfVmRaw.
pub fn register_hypervisor_helpers_raw(vm: &mut rbpf::EbpfVmRaw) {
    for &id in HYPERVISOR_HELPERS {
        if let Some(helper) = get_hypervisor_helper(id)
            && let Err(e) = vm.register_helper(id, helper)
        {
            log::warn!("Failed to register hypervisor helper {}: {:?}", id, e);
        }
    }
    log::debug!("Registered {} hypervisor helpers", HYPERVISOR_HELPERS.len());
}
