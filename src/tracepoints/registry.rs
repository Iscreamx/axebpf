//! Tracepoint ID ↔ Name registry.
//!
//! Provides mapping between numeric tracepoint IDs and string names.
//! Used by eBPF helpers to return tracepoint names.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

static REGISTRY: Mutex<BTreeMap<u32, &'static str>> = Mutex::new(BTreeMap::new());

/// Register a tracepoint with its ID and name.
pub fn register(id: u32, name: &'static str) {
    REGISTRY.lock().insert(id, name);
}

/// Get tracepoint name by ID.
pub fn get_name(id: u32) -> Option<&'static str> {
    REGISTRY.lock().get(&id).copied()
}

/// Get tracepoint ID by name.
pub fn get_id(name: &str) -> Option<u32> {
    REGISTRY
        .lock()
        .iter()
        .find(|(_, n)| **n == name)
        .map(|(id, _)| *id)
}

/// List all registered tracepoints.
pub fn list_all() -> Vec<(u32, &'static str)> {
    REGISTRY
        .lock()
        .iter()
        .map(|(id, name)| (*id, *name))
        .collect()
}

/// Initialize registry with all known tracepoints.
pub fn init() {
    // VM lifecycle
    register(4, "vmm:vm_destroy");

    // System initialization
    register(50, "vmm:vmm_init");
    register(52, "vmm:config_load");
    register(53, "vmm:image_load");

    // Timer
    register(60, "vmm:timer_tick");
    register(61, "vmm:timer_event");

    // Shell
    register(100, "shell:shell_command");
    register(101, "shell:shell_init");

    log::debug!(
        "Tracepoint registry initialized with {} entries",
        REGISTRY.lock().len()
    );
}
