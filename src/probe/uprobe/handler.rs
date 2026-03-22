//! Uprobe helper logic and BRK/single-step handling.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFilter {
    pub pid: Option<u32>,
    pub tgid: Option<u32>,
    pub comm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UprobeBrkHandleResult {
    ProbeHitSingleStep,
    ProbeHitFallbackSkip,
    Unhandled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UprobeStage2ExecFaultResult {
    ProbeHitSingleStep,
    RetryInstruction,
    Unhandled,
}

#[derive(Debug, Clone, Copy)]
enum UprobeSingleStepState {
    ReinjectBrk {
        vm_id: u32,
        pc: u64,
        hva: usize,
    },
    ExecBarrier {
        vm_id: u32,
        barrier_gpa: u64,
        barrier_size: u64,
    },
}

static SINGLE_STEP_STATE: Mutex<BTreeMap<usize, UprobeSingleStepState>> = Mutex::new(BTreeMap::new());

pub fn should_emit_for_filter(
    pid_filter: Option<u32>,
    tgid_filter: Option<u32>,
    comm_filter: Option<&str>,
    pid: u32,
    tgid: u32,
    comm: &str,
) -> bool {
    pid_filter.is_none_or(|target| target == pid)
        && tgid_filter.is_none_or(|target| target == tgid)
        && comm_filter.is_none_or(|target| target == comm)
}

pub fn is_guest_user_mode(spsr: u64) -> bool {
    (spsr & 0b1111) == 0
}

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
fn emit_uprobe_event(entry: &super::manager::ActiveUprobeEntry, pc: u64) {
    let probe_type = if entry.is_ret {
        crate::event::PROBE_URETPROBE
    } else {
        crate::event::PROBE_UPROBE
    };
    let mut event = crate::event::TraceEvent::new(probe_type, (pc & 0xffff_ffff) as u32);
    event.vm_id = entry.vm_id as u16;
    event.name_offset = if entry.is_ret {
        crate::event::register_event_name("uretprobe")
    } else {
        crate::event::register_event_name("uprobe")
    };
    event.nr_args = 4;
    event.args = [entry.pid as u64, entry.tgid as u64, entry.mm, pc];
    crate::event::emit_event(&event);
}

#[cfg(feature = "runtime")]
fn guest_arg_regs(regs: &[u64; 31]) -> [u64; 8] {
    [
        regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
    ]
}

fn build_uprobe_ctx(
    vm_id: u32,
    vcpu_id: u32,
    pid: u32,
    tgid: u32,
    mm: u64,
    is_ret: bool,
) -> crate::TraceContext {
    let probe_type = if is_ret { 6 } else { 5 };
    crate::TraceContext::new(0)
        .with_vm(vm_id, vcpu_id)
        .with_args(pid as u64, tgid as u64, mm, 0)
        .with_probe_type(probe_type)
}

pub fn build_uprobe_ctx_for_test(
    vm_id: u32,
    vcpu_id: u32,
    pid: u32,
    tgid: u32,
    mm: u64,
    is_ret: bool,
) -> crate::TraceContext {
    build_uprobe_ctx(vm_id, vcpu_id, pid, tgid, mm, is_ret)
}

pub fn handle_guest_brk(
    vm_id: u32,
    pc: u64,
    _iss: u64,
    regs: &[u64; 31],
    spsr: u64,
) -> UprobeBrkHandleResult {
    if !is_guest_user_mode(spsr) {
        return UprobeBrkHandleResult::Unhandled;
    }

    let Some(entry) = super::manager::record_active_hit(vm_id, pc) else {
        return UprobeBrkHandleResult::Unhandled;
    };
    log::info!(
        "guest_uprobe_hit: vm{} path={} symbol={} pc={:#x} mm={:#x} pid={} tgid={} hits={} prog_id={}",
        entry.vm_id,
        entry.guest_path,
        entry.symbol,
        pc,
        entry.mm,
        entry.pid,
        entry.tgid,
        entry.hits,
        entry.prog_id
    );

    #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
    emit_uprobe_event(&entry, pc);

    #[cfg(feature = "runtime")]
    {
        let regs = guest_arg_regs(regs);
        let mut ctx =
            build_uprobe_ctx(entry.vm_id, 0, entry.pid, entry.tgid, entry.mm, entry.is_ret)
                .with_regs(&regs);
        crate::tracepoints::hypervisor_helpers::set_current_context(entry.vm_id, 0, 0);
        let _ = crate::runtime::run_program(entry.prog_id, Some(ctx.as_bytes_mut()));
        crate::tracepoints::hypervisor_helpers::clear_current_context();
    }

    let cpu_id = crate::platform::cpu_id() as usize;
    {
        let mut pending = SINGLE_STEP_STATE.lock();
        if pending.contains_key(&cpu_id) {
            return UprobeBrkHandleResult::ProbeHitFallbackSkip;
        }
        pending.insert(
            cpu_id,
            UprobeSingleStepState::ReinjectBrk {
                vm_id,
                pc,
                hva: entry.hva,
            },
        );
    }

    if let Err(err) = super::manager::restore_instruction_for_step(entry.hva, entry.saved_insn) {
        let _ = SINGLE_STEP_STATE.lock().remove(&cpu_id);
        let _ = super::manager::remove_active(vm_id, pc);
        log::warn!(
            "guest_uprobe: failed to restore instruction vm{} pc={:#x}: {}",
            vm_id,
            pc,
            err
        );
        return UprobeBrkHandleResult::ProbeHitFallbackSkip;
    }

    UprobeBrkHandleResult::ProbeHitSingleStep
}

pub fn handle_software_step() -> bool {
    let cpu_id = crate::platform::cpu_id() as usize;
    let Some(state) = SINGLE_STEP_STATE.lock().remove(&cpu_id) else {
        return false;
    };

    match state {
        UprobeSingleStepState::ReinjectBrk { vm_id, pc, hva } => {
            if let Err(err) = super::manager::reinject_breakpoint(hva) {
                let _ = super::manager::remove_active(vm_id, pc);
                log::warn!(
                    "guest_uprobe: failed to reinject BRK vm{} pc={:#x}: {}",
                    vm_id,
                    pc,
                    err
                );
            }
        }
        UprobeSingleStepState::ExecBarrier {
            vm_id,
            barrier_gpa,
            barrier_size: _,
        } => {
            if let Err(err) = super::manager::rearm_exec_barrier_after_step(vm_id, barrier_gpa) {
                log::warn!(
                    "guest_uprobe: failed to rearm Stage-2 exec barrier vm{} gpa={:#x}: {}",
                    vm_id,
                    barrier_gpa,
                    err
                );
            }
        }
    }
    true
}

fn is_stepping_exec_barrier(vm_id: u32, fault_gpa: u64) -> bool {
    if fault_gpa == 0 {
        return false;
    }

    SINGLE_STEP_STATE.lock().values().any(|state| match state {
        UprobeSingleStepState::ExecBarrier {
            vm_id: state_vm_id,
            barrier_gpa,
            barrier_size,
        } => {
            *state_vm_id == vm_id
                && (*barrier_gpa..barrier_gpa.saturating_add(*barrier_size)).contains(&fault_gpa)
        }
        UprobeSingleStepState::ReinjectBrk { .. } => false,
    })
}

pub fn handle_stage2_exec_fault(vm_id: u32, gpa: u64) -> UprobeStage2ExecFaultResult {
    if is_stepping_exec_barrier(vm_id, gpa) {
        return UprobeStage2ExecFaultResult::RetryInstruction;
    }

    match super::manager::handle_exec_barrier_fault(vm_id, gpa) {
        Ok(super::manager::ExecBarrierFaultAction::ProbeHitSingleStep {
            barrier_gpa,
            barrier_size,
        }) => {
            let cpu_id = crate::platform::cpu_id() as usize;
            let mut pending = SINGLE_STEP_STATE.lock();
            if pending.contains_key(&cpu_id) {
                drop(pending);
                let _ = super::manager::rearm_exec_barrier_after_step(vm_id, barrier_gpa);
                return UprobeStage2ExecFaultResult::RetryInstruction;
            }
            pending.insert(
                cpu_id,
                UprobeSingleStepState::ExecBarrier {
                    vm_id,
                    barrier_gpa,
                    barrier_size,
                },
            );
            UprobeStage2ExecFaultResult::ProbeHitSingleStep
        }
        Ok(super::manager::ExecBarrierFaultAction::RetryInstruction) => {
            UprobeStage2ExecFaultResult::RetryInstruction
        }
        Ok(super::manager::ExecBarrierFaultAction::Unhandled) => {
            UprobeStage2ExecFaultResult::Unhandled
        }
        Err(err) => {
            log::warn!(
                "guest_uprobe: failed to handle Stage-2 exec barrier vm{} fault_gpa={:#x}: {}",
                vm_id,
                gpa,
                err
            );
            UprobeStage2ExecFaultResult::Unhandled
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub fn handle_guest_brk_for_test(
    vm_id: u32,
    pc: u64,
    iss: u64,
    regs: &[u64; 31],
    spsr: u64,
) -> UprobeBrkHandleResult {
    handle_guest_brk(vm_id, pc, iss, regs, spsr)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_state_for_test() {
    SINGLE_STEP_STATE.lock().clear();
}

#[cfg(any(test, feature = "test-utils"))]
pub fn handle_stage2_exec_fault_for_test(
    vm_id: u32,
    gpa: u64,
) -> UprobeStage2ExecFaultResult {
    handle_stage2_exec_fault(vm_id, gpa)
}
