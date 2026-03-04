//! Per-vCPU single-step state for guest kprobe.
//!
//! Tracks CPUs currently single-stepping restored instructions so
//! SoftwareStep exceptions can re-inject the BRK instruction.

extern crate alloc;

use alloc::collections::BTreeMap;
#[cfg(any(test, feature = "test-utils"))]
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

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

/// Check if a CPU has pending single-step state.
pub fn is_pending(cpu: usize) -> bool {
    SS_STATE
        .lock()
        .get(&cpu)
        .map(|state| state.active)
        .unwrap_or(false)
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
