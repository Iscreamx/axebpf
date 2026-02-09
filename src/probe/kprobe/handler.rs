//! Guest kprobe handler.
//!
//! Handles Stage-2 faults and guest BRK exceptions to implement
//! guest kernel probing from the VMM.

/// Handle a Stage-2 permission fault that may be a guest kprobe.
///
/// Called from the Stage-2 fault handler in the vCPU exit path.
///
/// # Arguments
/// * `vm_id` - VM that triggered the fault
/// * `gpa` - Guest physical address of the faulting access
/// * `gva` - Guest virtual address (from FAR_EL2 or reconstructed)
/// * `is_exec` - Whether this was an instruction fetch fault
///
/// # Returns
/// `true` if handled as a kprobe, `false` if not a kprobe fault.
pub fn handle_stage2_exec_fault(
    vm_id: u32,
    gpa: u64,
    gva: u64,
    is_exec: bool,
) -> bool {
    if !is_exec {
        return false;
    }

    // TODO: Check if GVA matches a registered guest kprobe
    // TODO: Build TraceContext from vCPU EL1 registers
    // TODO: Execute eBPF program
    // TODO: Temporarily restore execute permission for single-step
    // TODO: Re-mark as XN after single-step

    log::trace!(
        "guest_kprobe: Stage-2 exec fault vm{}:gpa={:#x} gva={:#x}",
        vm_id, gpa, gva
    );

    false // Not handled yet
}

/// Handle a guest BRK exception routed to EL2 (for BRK inject mode).
///
/// # Arguments
/// * `vm_id` - VM that triggered the BRK
/// * `pc` - Guest PC where BRK was hit (ELR_EL1 equivalent from vCPU context)
/// * `iss` - Instruction Specific Syndrome
///
/// # Returns
/// `true` if handled as a guest kprobe, `false` if not.
pub fn handle_guest_brk(
    vm_id: u32,
    pc: u64,
    iss: u64,
) -> bool {
    // TODO: Check BRK immediate to distinguish guest kprobe from other BRKs
    // TODO: Look up registered kprobe at (vm_id, pc)
    // TODO: Build TraceContext, execute eBPF
    // TODO: Restore original instruction, single-step, re-inject BRK

    log::trace!(
        "guest_kprobe: guest BRK vm{}:pc={:#x} iss={:#x}",
        vm_id, pc, iss
    );

    false // Not handled yet
}
