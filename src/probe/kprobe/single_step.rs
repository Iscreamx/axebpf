//! Per-vCPU single-step state for guest kprobe.
//!
//! Tracks CPUs currently single-stepping restored instructions so
//! SoftwareStep exceptions can re-inject the BRK instruction.

extern crate alloc;

use alloc::collections::BTreeMap;
#[cfg(any(test, feature = "test-utils"))]
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Single-step completion mode for guest kprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleStepMode {
    /// Complete a BRK-inject probe by re-injecting BRK after one instruction.
    BrkInject,
    /// Complete a Stage-2 fault probe by restoring execute-never after one instruction.
    Stage2Fault,
    /// Complete a return probe by optionally re-injecting the dynamic return BRK.
    ReturnProbe { should_reinject: bool },
}

/// Per-vCPU single-step tracking.
#[derive(Clone, Copy)]
pub struct KprobeSingleStepState {
    /// Whether this CPU is currently in single-step mode.
    pub active: bool,
    /// Guest virtual address of the probe point.
    pub probe_gva: u64,
    /// The original instruction restored for this step.
    pub saved_insn: u32,
    /// VM ID owning this probe.
    pub vm_id: u32,
    /// HVA of the probe point for BRK re-injection.
    pub hva: usize,
    /// GPA of the probe page used for Stage-2 XN busy-retry.
    pub gpa: u64,
    /// Size of the protected Stage-2 execute barrier region.
    pub gpa_size: u64,
    /// Completion path for this pending single-step state.
    pub mode: SingleStepMode,
}

static SS_STATE: Mutex<BTreeMap<usize, KprobeSingleStepState>> = Mutex::new(BTreeMap::new());
#[cfg(any(test, feature = "test-utils"))]
static FORCE_SET_PENDING_FAIL: AtomicBool = AtomicBool::new(false);

/// Record that a CPU is about to single-step.
pub fn set_pending(cpu: usize, state: KprobeSingleStepState) -> Result<(), &'static str> {
    if !state.active {
        return Err("single-step state must be active");
    }
    #[cfg(any(test, feature = "test-utils"))]
    if FORCE_SET_PENDING_FAIL.load(Ordering::Relaxed) {
        return Err("single-step pending set forced failure");
    }
    SS_STATE.lock().insert(cpu, state);
    Ok(())
}

/// Consume pending single-step state for a CPU.
pub fn take_pending(cpu: usize) -> Option<KprobeSingleStepState> {
    SS_STATE.lock().remove(&cpu).filter(|state| state.active)
}

/// Read pending single-step state without consuming it.
pub fn peek_pending(cpu: usize) -> Option<KprobeSingleStepState> {
    SS_STATE
        .lock()
        .get(&cpu)
        .copied()
        .filter(|state| state.active)
}

/// Clear pending single-step state for a CPU.
pub fn clear_pending(cpu: usize) -> Option<KprobeSingleStepState> {
    SS_STATE.lock().remove(&cpu)
}

/// Check if a CPU has pending single-step state.
pub fn is_pending(cpu: usize) -> bool {
    SS_STATE
        .lock()
        .get(&cpu)
        .map(|state| state.active)
        .unwrap_or(false)
}

/// Check whether any CPU is single-stepping on the same 4K page.
pub fn is_stepping_on_page(vm_id: u32, gpa: u64) -> bool {
    if gpa == 0 {
        return false;
    }
    SS_STATE.lock().values().any(|state| {
        if !state.active || state.vm_id != vm_id || state.gpa == 0 {
            return false;
        }
        let size = if state.gpa_size == 0 {
            0x1000
        } else {
            state.gpa_size
        };
        gpa >= state.gpa && gpa < state.gpa.saturating_add(size)
    })
}

#[cfg(any(test, feature = "test-utils"))]
pub fn set_force_pending_fail_for_test(fail: bool) {
    FORCE_SET_PENDING_FAIL.store(fail, Ordering::Relaxed);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_pending_for_test() {
    SS_STATE.lock().clear();
    FORCE_SET_PENDING_FAIL.store(false, Ordering::Relaxed);
}
