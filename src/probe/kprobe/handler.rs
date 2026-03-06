//! Guest kprobe handler.
//!
//! Handles Stage-2 faults and guest BRK exceptions to implement
//! guest kernel probing from the VMM.

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
fn emit_guest_event(vm_id: u32, pc_or_gva: u64, is_ret: bool, regs: &[u64; 8]) {
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
    event.args = [regs[0], regs[1], regs[2], regs[3]];
    crate::event::emit_event(&event);
}

#[cfg(feature = "runtime")]
fn build_guest_ctx(
    vm_id: u32,
    is_ret: bool,
    a0: u64,
    a1: u64,
    regs: &[u64; 8],
) -> crate::TraceContext {
    let probe_type = if is_ret { 3 } else { 2 };
    crate::TraceContext::new(0)
        .with_vm(vm_id, 0)
        .with_args(a0, a1, 0, 0)
        .with_probe_type(probe_type)
        .with_regs(regs)
}

#[cfg(all(feature = "runtime", feature = "guest-kprobe"))]
pub fn build_guest_ctx_for_test(
    vm_id: u32,
    is_ret: bool,
    a0: u64,
    a1: u64,
    regs: &[u64; 8],
) -> crate::TraceContext {
    build_guest_ctx(vm_id, is_ret, a0, a1, regs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestBrkHandleResult {
    /// The BRK came from an enabled probe. Caller should enable single-step
    /// and keep PC unchanged so the restored instruction is executed.
    ProbeHitSingleStep,
    /// The BRK matched an enabled probe, but single-step setup failed.
    /// Caller should fallback to legacy behavior and advance PC.
    ProbeHitFallbackSkip,
    /// The BRK was stale after detach; caller should retry at current PC.
    RetryInstruction,
    /// Not a guest-kprobe BRK.
    Unhandled,
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
    regs: &[u64; 8],
) -> bool {
    if !is_exec {
        return false;
    }

    if should_busy_retry_gpa(vm_id, gpa) {
        return true;
    }

    if let Some((prog_id, is_ret)) = super::manager::lookup_enabled(vm_id, gva) {
        let _ = super::manager::record_probe_hit(vm_id, gva);

        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        emit_guest_event(vm_id, gva, is_ret, regs);

        #[cfg(feature = "runtime")]
        {
            let mut ctx = build_guest_ctx(vm_id, is_ret, gva, gpa, regs);
            crate::tracepoints::hypervisor_helpers::set_current_context(vm_id, 0, 0);
            let _ = crate::runtime::run_program(prog_id, Some(ctx.as_bytes_mut()));
            crate::tracepoints::hypervisor_helpers::clear_current_context();
        }

        log::debug!(
            "guest_kprobe: matched stage2 fault vm{} gva={:#x} prog_id={}",
            vm_id,
            gva,
            prog_id
        );
        return true;
    }

    log::trace!(
        "guest_kprobe: Stage-2 exec fault vm{}:gpa={:#x} gva={:#x}",
        vm_id, gpa, gva
    );

    false
}

fn should_busy_retry_gpa(vm_id: u32, gpa: u64) -> bool {
    if super::single_step::is_stepping_on_page(vm_id, gpa) {
        log::trace!(
            "guest_kprobe: busy-retry for stepping page vm{}:gpa={:#x}",
            vm_id,
            gpa
        );
        return true;
    }
    false
}

pub fn should_busy_retry_gva(vm_id: u32, gva: u64) -> bool {
    if gva == 0 {
        return false;
    }

    let cpu_id = crate::platform::cpu_id() as usize;
    if super::single_step::peek_pending(cpu_id).is_some() {
        return false;
    }

    let Ok(gpa) = super::addr_translate::gva_to_gpa_with_vm(gva, vm_id) else {
        return false;
    };

    should_busy_retry_gpa(vm_id, gpa)
}

/// Handle a guest BRK exception routed to EL2 (for BRK inject mode).
///
/// # Arguments
/// * `vm_id` - VM that triggered the BRK
/// * `pc` - Guest PC where BRK was hit (ELR_EL1 equivalent from vCPU context)
/// * `iss` - Instruction Specific Syndrome
///
/// # Returns
/// Handling decision for the caller.
pub fn handle_guest_brk(
    vm_id: u32,
    pc: u64,
    iss: u64,
    regs: &[u64; 8],
) -> GuestBrkHandleResult {
    if let Some(hit) = super::manager::lookup_enabled_brk_hit(vm_id, pc) {
        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        emit_guest_event(vm_id, pc, hit.is_ret, regs);

        #[cfg(feature = "runtime")]
        {
            let mut ctx = build_guest_ctx(vm_id, hit.is_ret, pc, iss, regs);
            crate::tracepoints::hypervisor_helpers::set_current_context(vm_id, 0, 0);
            let _ = crate::runtime::run_program(hit.prog_id, Some(ctx.as_bytes_mut()));
            crate::tracepoints::hypervisor_helpers::clear_current_context();
        }

        let step_gpa = match hit.gpa {
            Some(gpa) => match super::manager::set_stage2_executable(vm_id, gpa, false) {
                Ok(()) => gpa,
                Err(e) => {
                    log::warn!("guest_kprobe: failed to set XN for stepping: {}", e);
                    0
                }
            },
            None => 0,
        };

        let cpu_id = crate::platform::cpu_id() as usize;
        let state = super::single_step::KprobeSingleStepState {
            active: true,
            probe_gva: pc,
            saved_insn: hit.saved_insn,
            vm_id,
            hva: hit.hva,
            gpa: step_gpa,
            gpa_size: hit.gpa_size,
        };
        if let Err(e) = super::single_step::set_pending(cpu_id, state) {
            log::warn!("guest_kprobe: failed to set single-step pending state: {}", e);
            if step_gpa != 0 {
                if let Err(clear_err) = super::manager::set_stage2_executable(vm_id, step_gpa, true) {
                    log::warn!(
                        "guest_kprobe: failed to clear XN after pending-state failure: {}",
                        clear_err
                    );
                }
            }
            return GuestBrkHandleResult::ProbeHitFallbackSkip;
        }

        if let Err(e) = super::manager::restore_insn_for_step(hit.hva, hit.saved_insn) {
            log::warn!("guest_kprobe: failed to restore insn for step: {}", e);
            let _ = super::single_step::clear_pending(cpu_id);
            if step_gpa != 0 {
                if let Err(clear_err) = super::manager::set_stage2_executable(vm_id, step_gpa, true) {
                    log::warn!(
                        "guest_kprobe: failed to clear XN after restore failure: {}",
                        clear_err
                    );
                }
            }
            return GuestBrkHandleResult::ProbeHitFallbackSkip;
        }

        log::debug!(
            "guest_kprobe: BRK hit vm{}:{:#x}, pending single-step on cpu{}",
            vm_id,
            pc,
            cpu_id
        );
        return GuestBrkHandleResult::ProbeHitSingleStep;
    }

    if super::manager::consume_stale_brk(vm_id, pc) {
        log::debug!("guest_kprobe: recovered stale BRK vm{} pc={:#x}", vm_id, pc);
        return GuestBrkHandleResult::RetryInstruction;
    }

    log::trace!(
        "guest_kprobe: guest BRK vm{}:pc={:#x} iss={:#x}",
        vm_id, pc, iss
    );

    GuestBrkHandleResult::Unhandled
}

/// Handle SoftwareStepLowerEL exception for guest-kprobe single-step completion.
///
/// Returns `true` if the exception belongs to a pending kprobe single-step.
pub fn handle_software_step() -> bool {
    let cpu_id = crate::platform::cpu_id() as usize;
    let Some(state) = super::single_step::peek_pending(cpu_id) else {
        return false;
    };

    if let Err(e) = super::manager::reinject_brk(state.hva) {
        log::warn!(
            "guest_kprobe: failed to reinject BRK at hva={:#x}: {}",
            state.hva,
            e
        );
    }

    if state.gpa != 0 {
        if let Err(e) = super::manager::set_stage2_executable(state.vm_id, state.gpa, true) {
            log::warn!(
                "guest_kprobe: failed to clear XN after step vm{}:gpa={:#x}: {}",
                state.vm_id,
                state.gpa,
                e
            );
        }
    }

    let _ = super::single_step::clear_pending(cpu_id);

    log::debug!(
        "guest_kprobe: single-step complete vm{}:{:#x} on cpu{}, BRK reinjected",
        state.vm_id,
        state.probe_gva,
        cpu_id
    );

    true
}
