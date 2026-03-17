//! Guest kprobe handler.
//!
//! Handles Stage-2 faults and guest BRK exceptions to implement
//! guest kernel probing from the VMM.

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
fn emit_guest_event(vm_id: u32, pc_or_gva: u64, is_ret: bool, regs: &[u64; 31]) {
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
fn guest_arg_regs(regs: &[u64; 31]) -> [u64; 8] {
    [
        regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
    ]
}

#[cfg(feature = "runtime")]
fn build_guest_ctx(
    vm_id: u32,
    is_ret: bool,
    a0: u64,
    a1: u64,
    regs: &[u64; 31],
) -> crate::TraceContext {
    let probe_type = if is_ret { 3 } else { 2 };
    let regs = guest_arg_regs(regs);
    crate::TraceContext::new(0)
        .with_vm(vm_id, 0)
        .with_args(a0, a1, 0, 0)
        .with_probe_type(probe_type)
        .with_regs(&regs)
}

#[cfg(all(feature = "runtime", feature = "guest-kprobe"))]
pub fn build_guest_ctx_for_test(
    vm_id: u32,
    is_ret: bool,
    a0: u64,
    a1: u64,
    regs: &[u64; 31],
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
    /// A dynamic return-probe BRK was hit and single-step is armed.
    ReturnProbeHitSingleStep,
    /// Not a guest-kprobe BRK.
    Unhandled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2ExecFaultResult {
    /// The Stage-2 fault hit an enabled probe and armed single-step completion.
    ProbeHitSingleStep,
    /// The fault overlaps another CPU's single-step window and should be retried.
    BusyRetry,
    /// Not handled by guest-kprobe.
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
/// Stage-2 handling result for the caller.
pub fn handle_stage2_exec_fault(
    vm_id: u32,
    gpa: u64,
    gva: u64,
    is_exec: bool,
    regs: &[u64; 31],
) -> Stage2ExecFaultResult {
    if !is_exec {
        return Stage2ExecFaultResult::Unhandled;
    }

    if should_busy_retry_gpa(vm_id, gpa) {
        return Stage2ExecFaultResult::BusyRetry;
    }

    let arm_stage2_single_step =
        |probe_gva: u64, barrier_gpa: u64, barrier_size: u64| -> Stage2ExecFaultResult {
            if let Err(e) = super::manager::set_stage2_executable(vm_id, barrier_gpa, true) {
                log::warn!(
                    "guest_kprobe: failed to enable stepping window vm{}:gpa={:#x}: {}",
                    vm_id,
                    barrier_gpa,
                    e
                );
                return Stage2ExecFaultResult::Unhandled;
            }

            let cpu_id = crate::platform::cpu_id() as usize;
            let state = super::single_step::KprobeSingleStepState {
                active: true,
                probe_gva,
                saved_insn: 0,
                vm_id,
                hva: 0,
                gpa: barrier_gpa,
                gpa_size: barrier_size,
                mode: super::single_step::SingleStepMode::Stage2Fault,
            };
            if let Err(e) = super::single_step::set_pending(cpu_id, state) {
                log::warn!(
                    "guest_kprobe: failed to set stage2 single-step pending state: {}",
                    e
                );
                if let Err(clear_err) =
                    super::manager::set_stage2_executable(vm_id, barrier_gpa, false)
                {
                    log::warn!(
                        "guest_kprobe: failed to rollback stepping window vm{}:gpa={:#x}: {}",
                        vm_id,
                        barrier_gpa,
                        clear_err
                    );
                }
                return Stage2ExecFaultResult::Unhandled;
            }

            Stage2ExecFaultResult::ProbeHitSingleStep
        };

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

        let (barrier_gpa, barrier_size) =
            super::manager::lookup_stage2_barrier(vm_id, gva).unwrap_or((gpa & !0xfff, 0x1000));
        return arm_stage2_single_step(gva, barrier_gpa, barrier_size);
    }

    if let Some((probe_gva, barrier_gpa, barrier_size)) =
        super::manager::lookup_enabled_stage2_probe_by_gpa(vm_id, gpa)
    {
        log::debug!(
            "guest_kprobe: stage2 page-step vm{} fault_gva={:#x} probe_gva={:#x}",
            vm_id,
            gva,
            probe_gva
        );
        return arm_stage2_single_step(probe_gva, barrier_gpa, barrier_size);
    }

    log::trace!(
        "guest_kprobe: Stage-2 exec fault vm{}:gpa={:#x} gva={:#x}",
        vm_id,
        gpa,
        gva
    );

    Stage2ExecFaultResult::Unhandled
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
pub fn handle_guest_brk(vm_id: u32, pc: u64, iss: u64, regs: &[u64; 31]) -> GuestBrkHandleResult {
    if let Some(hit) = super::manager::lookup_enabled_brk_hit(vm_id, pc) {
        if !hit.is_ret {
            #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
            emit_guest_event(vm_id, pc, false, regs);

            #[cfg(feature = "runtime")]
            {
                let mut ctx = build_guest_ctx(vm_id, false, pc, iss, regs);
                crate::tracepoints::hypervisor_helpers::set_current_context(vm_id, 0, 0);
                let _ = crate::runtime::run_program(hit.prog_id, Some(ctx.as_bytes_mut()));
                crate::tracepoints::hypervisor_helpers::clear_current_context();
            }
        } else {
            let return_addr = regs[30];
            match super::addr_translate::gva_to_hva_for_vm(return_addr, vm_id) {
                Ok(ret_hva) => {
                    match super::manager::acquire_return_brk(vm_id, return_addr, ret_hva) {
                        Ok((_refcount, saved_insn)) => {
                            let ret_entry = super::return_stack::ReturnEntry {
                                vm_id,
                                return_gva: return_addr,
                                return_hva: ret_hva,
                                saved_insn,
                                entry_gva: pc,
                                prog_id: hit.prog_id,
                            };
                            let cpu_id = crate::platform::cpu_id() as usize;
                            if let Err(e) = super::return_stack::push(cpu_id, ret_entry) {
                                log::warn!(
                                    "guest_kprobe: return stack push failed vm{}:{:#x}: {}",
                                    vm_id,
                                    return_addr,
                                    e
                                );
                                let _ = super::manager::release_return_brk(vm_id, return_addr);
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "guest_kprobe: acquire return BRK failed vm{}:{:#x}: {}",
                                vm_id,
                                return_addr,
                                e
                            );
                        }
                    }
                }
                Err(_) => {
                    log::warn!(
                        "guest_kprobe: return addr GVA->HVA failed vm{}:{:#x}",
                        vm_id,
                        return_addr
                    );
                }
            }
        }

        let step_gpa = match hit.gpa {
            Some(gpa) => match super::manager::set_stage2_executable(vm_id, gpa, true) {
                Ok(()) => gpa,
                Err(e) => {
                    log::warn!(
                        "guest_kprobe: failed to open execute window for stepping: {}",
                        e
                    );
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
            mode: super::single_step::SingleStepMode::BrkInject,
        };
        if let Err(e) = super::single_step::set_pending(cpu_id, state) {
            log::warn!(
                "guest_kprobe: failed to set single-step pending state: {}",
                e
            );
            if step_gpa != 0
                && let Err(clear_err) = super::manager::set_stage2_executable(vm_id, step_gpa, true)
            {
                log::warn!(
                    "guest_kprobe: failed to clear XN after pending-state failure: {}",
                    clear_err
                );
            }
            return GuestBrkHandleResult::ProbeHitFallbackSkip;
        }

        if let Err(e) = super::manager::restore_insn_for_step(hit.hva, hit.saved_insn) {
            log::warn!("guest_kprobe: failed to restore insn for step: {}", e);
            let _ = super::single_step::clear_pending(cpu_id);
            if step_gpa != 0
                && let Err(clear_err) = super::manager::set_stage2_executable(vm_id, step_gpa, true)
            {
                log::warn!(
                    "guest_kprobe: failed to clear XN after restore failure: {}",
                    clear_err
                );
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

    let cpu_id = crate::platform::cpu_id() as usize;
    if let Some(ret_entry) = super::return_stack::pop_matching(cpu_id, vm_id, pc) {
        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        emit_guest_event(vm_id, ret_entry.entry_gva, true, regs);

        #[cfg(feature = "runtime")]
        {
            let mut ctx = build_guest_ctx(vm_id, true, ret_entry.entry_gva, pc, regs);
            crate::tracepoints::hypervisor_helpers::set_current_context(vm_id, 0, 0);
            let _ = crate::runtime::run_program(ret_entry.prog_id, Some(ctx.as_bytes_mut()));
            crate::tracepoints::hypervisor_helpers::clear_current_context();
        }

        let should_reinject = match super::manager::release_return_brk(vm_id, pc) {
            Ok(should_reinject) => should_reinject,
            Err(e) => {
                log::warn!(
                    "guest_kprobe: release return BRK failed vm{}:{:#x}: {}",
                    vm_id,
                    pc,
                    e
                );
                false
            }
        };

        let (step_gpa, step_gpa_size) = match super::addr_translate::gva_to_gpa_with_vm(pc, vm_id) {
            Ok(gpa) => {
                let (barrier_gpa, barrier_size) = super::manager::query_step_barrier(vm_id, gpa);
                match super::manager::set_stage2_executable(vm_id, barrier_gpa, true) {
                    Ok(()) => (barrier_gpa, barrier_size),
                    Err(e) => {
                        log::warn!(
                            "guest_kprobe: failed to open execute window for return probe step: {}",
                            e
                        );
                        (0, 0)
                    }
                }
            }
            Err(_) => (0, 0),
        };

        let state = super::single_step::KprobeSingleStepState {
            active: true,
            probe_gva: pc,
            saved_insn: ret_entry.saved_insn,
            vm_id,
            hva: ret_entry.return_hva,
            gpa: step_gpa,
            gpa_size: step_gpa_size,
            mode: super::single_step::SingleStepMode::ReturnProbe { should_reinject },
        };
        if let Err(e) = super::single_step::set_pending(cpu_id, state) {
            log::warn!(
                "guest_kprobe: failed to set return probe single-step pending: {}",
                e
            );
            if step_gpa != 0 {
                let _ = super::manager::set_stage2_executable(vm_id, step_gpa, true);
            }
            return GuestBrkHandleResult::Unhandled;
        }

        if let Err(e) =
            super::manager::restore_insn_for_step(ret_entry.return_hva, ret_entry.saved_insn)
        {
            log::warn!(
                "guest_kprobe: failed to restore insn for return probe step: {}",
                e
            );
            let _ = super::single_step::clear_pending(cpu_id);
            if step_gpa != 0 {
                let _ = super::manager::set_stage2_executable(vm_id, step_gpa, true);
            }
            return GuestBrkHandleResult::Unhandled;
        }

        log::debug!(
            "guest_kprobe: return probe hit vm{}:{:#x}, pending single-step on cpu{}",
            vm_id,
            pc,
            cpu_id
        );
        return GuestBrkHandleResult::ReturnProbeHitSingleStep;
    }

    if super::manager::consume_stale_brk(vm_id, pc) {
        log::debug!("guest_kprobe: recovered stale BRK vm{} pc={:#x}", vm_id, pc);
        return GuestBrkHandleResult::RetryInstruction;
    }

    log::trace!(
        "guest_kprobe: guest BRK vm{}:pc={:#x} iss={:#x}",
        vm_id,
        pc,
        iss
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

    match state.mode {
        super::single_step::SingleStepMode::BrkInject => {
            if let Err(e) = super::manager::reinject_brk(state.hva) {
                log::warn!(
                    "guest_kprobe: failed to reinject BRK at hva={:#x}: {}",
                    state.hva,
                    e
                );
            }
            if state.gpa != 0
                && let Err(e) = super::manager::set_stage2_executable(state.vm_id, state.gpa, true)
            {
                log::warn!(
                    "guest_kprobe: failed to clear XN after step vm{}:gpa={:#x}: {}",
                    state.vm_id,
                    state.gpa,
                    e
                );
            }
        }
        super::single_step::SingleStepMode::Stage2Fault => {
            if state.gpa != 0
                && let Err(e) = super::manager::set_stage2_executable(state.vm_id, state.gpa, false)
            {
                log::warn!(
                    "guest_kprobe: failed to restore XN after step vm{}:gpa={:#x}: {}",
                    state.vm_id,
                    state.gpa,
                    e
                );
            }
        }
        super::single_step::SingleStepMode::ReturnProbe { should_reinject } => {
            if should_reinject && let Err(e) = super::manager::reinject_brk(state.hva) {
                log::warn!(
                    "guest_kprobe: failed to reinject return BRK at hva={:#x}: {}",
                    state.hva,
                    e
                );
            }
            if state.gpa != 0
                && let Err(e) = super::manager::set_stage2_executable(state.vm_id, state.gpa, true)
            {
                log::warn!(
                    "guest_kprobe: failed to clear XN after return probe step vm{}:gpa={:#x}: {}",
                    state.vm_id,
                    state.gpa,
                    e
                );
            }
        }
    }

    let _ = super::single_step::clear_pending(cpu_id);

    match state.mode {
        super::single_step::SingleStepMode::BrkInject => {
            log::debug!(
                "guest_kprobe: single-step complete vm{}:{:#x} on cpu{}, BRK reinjected",
                state.vm_id,
                state.probe_gva,
                cpu_id
            );
        }
        super::single_step::SingleStepMode::Stage2Fault => {
            log::debug!(
                "guest_kprobe: single-step complete vm{}:{:#x} on cpu{}, XN restored",
                state.vm_id,
                state.probe_gva,
                cpu_id
            );
        }
        super::single_step::SingleStepMode::ReturnProbe { should_reinject } => {
            log::debug!(
                "guest_kprobe: return probe single-step complete vm{}:{:#x} on cpu{}, reinject={}",
                state.vm_id,
                state.probe_gva,
                cpu_id,
                should_reinject
            );
        }
    }

    true
}
