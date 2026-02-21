//! Guest kprobe handler.
//!
//! Handles Stage-2 faults and guest BRK exceptions to implement
//! guest kernel probing from the VMM.

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
fn emit_guest_event(vm_id: u32, pc_or_gva: u64, is_ret: bool, args: [u64; 4]) {
    let probe_type = if is_ret {
        crate::event::PROBE_KRETPROBE
    } else {
        crate::event::PROBE_KPROBE
    };
    let mut event = crate::event::TraceEvent::new(probe_type, (pc_or_gva & 0xffff_ffff) as u32);
    event.vm_id = vm_id as u16;
    event.name_offset = if is_ret {
        crate::event::register_event_name("kretprobe")
    } else {
        crate::event::register_event_name("kprobe")
    };
    event.nr_args = 4;
    event.args = args;
    crate::event::emit_event(&event);
}

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

    if let Some((prog_id, is_ret)) = super::manager::lookup_enabled(vm_id, gva) {
        let _ = super::manager::record_probe_hit(vm_id, gva);

        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        emit_guest_event(vm_id, gva, is_ret, [gva, gpa, 0, 0]);

        #[cfg(feature = "runtime")]
        {
            // Guest register context plumbing is not ready yet; execute with empty ctx.
            let _ = crate::runtime::run_program(prog_id, None);
        }

        log::debug!(
            "guest_kprobe: matched stage2 fault vm{} gva={:#x} prog_id={}",
            vm_id,
            gva,
            prog_id
        );
    }

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
    if let Some((prog_id, is_ret)) = super::manager::lookup_enabled(vm_id, pc) {
        let _ = super::manager::record_probe_hit(vm_id, pc);

        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        emit_guest_event(vm_id, pc, is_ret, [pc, iss, 0, 0]);

        #[cfg(feature = "runtime")]
        {
            // Guest register context plumbing is not ready yet; execute with empty ctx.
            let _ = crate::runtime::run_program(prog_id, None);
        }

        log::debug!(
            "guest_kprobe: matched guest BRK vm{} pc={:#x} prog_id={}",
            vm_id,
            pc,
            prog_id
        );
    }

    log::trace!(
        "guest_kprobe: guest BRK vm{}:pc={:#x} iss={:#x}",
        vm_id, pc, iss
    );

    false // Not handled yet
}
