//! Live guest runtime state captured while handling a guest exception.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveGuestRuntimeState {
    pub vm_id: u32,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub contextidr_el1: u32,
    pub sp_el0: u64,
    pub tpidr_el0: u64,
    pub guest_spsr: u64,
}

static LIVE_GUEST_RUNTIME_STATES: Mutex<BTreeMap<u32, LiveGuestRuntimeState>> =
    Mutex::new(BTreeMap::new());

pub struct LiveGuestRuntimeStateGuard {
    cpu_id: u32,
}

impl Drop for LiveGuestRuntimeStateGuard {
    fn drop(&mut self) {
        LIVE_GUEST_RUNTIME_STATES.lock().remove(&self.cpu_id);
    }
}

pub fn install_live_guest_runtime_state(
    state: LiveGuestRuntimeState,
) -> LiveGuestRuntimeStateGuard {
    let cpu_id = crate::platform::cpu_id();
    LIVE_GUEST_RUNTIME_STATES.lock().insert(cpu_id, state);
    LiveGuestRuntimeStateGuard { cpu_id }
}

pub fn clear_live_guest_runtime_state() {
    LIVE_GUEST_RUNTIME_STATES
        .lock()
        .remove(&crate::platform::cpu_id());
}

pub fn current_live_guest_runtime_state(vm_id: u32) -> Option<LiveGuestRuntimeState> {
    LIVE_GUEST_RUNTIME_STATES
        .lock()
        .get(&crate::platform::cpu_id())
        .copied()
        .filter(|state| state.vm_id == vm_id)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_live_guest_runtime_state_for_test() {
    LIVE_GUEST_RUNTIME_STATES.lock().clear();
}
