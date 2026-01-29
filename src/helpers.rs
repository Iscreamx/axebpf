//! eBPF helper functions.
//!
//! Standard helpers available to eBPF programs running in AxVisor.
//! These follow Linux BPF helper IDs where applicable.

use crate::maps;

/// Helper function signature matching rbpf expectations.
/// Arguments: r1, r2, r3, r4, r5 (from eBPF registers)
/// Returns: u64 (stored in r0)
pub type HelperFn = fn(u64, u64, u64, u64, u64) -> u64;

/// Standard BPF helper function IDs.
pub mod id {
    /// bpf_map_lookup_elem(map_id, key) -> value_ptr or 0
    pub const MAP_LOOKUP_ELEM: u32 = 1;
    /// bpf_map_update_elem(map_id, key, value, flags) -> 0 or error
    pub const MAP_UPDATE_ELEM: u32 = 2;
    /// bpf_map_delete_elem(map_id, key) -> 0 or error
    pub const MAP_DELETE_ELEM: u32 = 3;
    /// bpf_ktime_get_ns() -> nanoseconds
    pub const KTIME_GET_NS: u32 = 5;
    /// bpf_trace_printk(fmt, fmt_size, args...) -> bytes written
    pub const TRACE_PRINTK: u32 = 6;
    /// bpf_get_smp_processor_id() -> CPU ID
    pub const GET_SMP_PROCESSOR_ID: u32 = 8;
}

// =============================================================================
// Helper Implementations
// =============================================================================

/// bpf_map_lookup_elem - lookup map element by key.
///
/// For simplified model: r1 = map_id, r2 = key (as u64 for small keys)
/// Returns: value as u64, or 0 if not found.
fn bpf_map_lookup_elem(map_id: u64, key: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    let key_bytes = key.to_le_bytes();
    match maps::lookup_elem(map_id as u32, &key_bytes) {
        Some(value) => {
            // Return first 8 bytes as u64
            let mut buf = [0u8; 8];
            let len = value.len().min(8);
            buf[..len].copy_from_slice(&value[..len]);
            u64::from_le_bytes(buf)
        }
        None => 0,
    }
}

/// bpf_map_update_elem - update or insert map element.
///
/// r1 = map_id, r2 = key, r3 = value, r4 = flags
/// Returns: 0 on success, non-zero on error.
fn bpf_map_update_elem(map_id: u64, key: u64, value: u64, flags: u64, _r5: u64) -> u64 {
    let key_bytes = key.to_le_bytes();
    let value_bytes = value.to_le_bytes();
    match maps::update_elem(map_id as u32, &key_bytes, &value_bytes, flags) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// bpf_map_delete_elem - delete map element.
///
/// r1 = map_id, r2 = key
/// Returns: 0 on success, non-zero on error.
fn bpf_map_delete_elem(map_id: u64, key: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    let key_bytes = key.to_le_bytes();
    match maps::delete_elem(map_id as u32, &key_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// bpf_ktime_get_ns - get current time in nanoseconds.
///
/// Returns: current monotonic time in nanoseconds.
fn bpf_ktime_get_ns(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    crate::platform::time_ns()
}

/// bpf_trace_printk - print debug message.
///
/// Simplified: r1 = value to print
/// Returns: 0
fn bpf_trace_printk(value: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    log::info!("[bpf_trace] value={}", value);
    0
}

/// bpf_get_smp_processor_id - get current CPU ID.
///
/// Returns: current CPU ID.
fn bpf_get_smp_processor_id(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    crate::platform::cpu_id() as u64
}

// =============================================================================
// Helper Registration
// =============================================================================

/// Get a helper function by ID.
///
/// # Arguments
/// * `id` - Helper function ID from the `id` module.
///
/// # Returns
/// The helper function if supported, None otherwise.
pub fn get_helper(id: u32) -> Option<HelperFn> {
    match id {
        id::MAP_LOOKUP_ELEM => Some(bpf_map_lookup_elem),
        id::MAP_UPDATE_ELEM => Some(bpf_map_update_elem),
        id::MAP_DELETE_ELEM => Some(bpf_map_delete_elem),
        id::KTIME_GET_NS => Some(bpf_ktime_get_ns),
        id::TRACE_PRINTK => Some(bpf_trace_printk),
        id::GET_SMP_PROCESSOR_ID => Some(bpf_get_smp_processor_id),
        _ => None,
    }
}

/// List of all supported helper IDs.
pub const SUPPORTED_HELPERS: &[u32] = &[
    id::MAP_LOOKUP_ELEM,
    id::MAP_UPDATE_ELEM,
    id::MAP_DELETE_ELEM,
    id::KTIME_GET_NS,
    id::TRACE_PRINTK,
    id::GET_SMP_PROCESSOR_ID,
];

/// Register all standard helpers to an rbpf VM.
///
/// # Arguments
/// * `vm` - Mutable reference to an rbpf VM (EbpfVmNoData or EbpfVmRaw).
pub fn register_all_nodata(vm: &mut rbpf::EbpfVmNoData) {
    for &id in SUPPORTED_HELPERS {
        let Some(helper) = get_helper(id) else {
            continue;
        };
        if let Err(e) = vm.register_helper(id, helper) {
            log::warn!("Failed to register helper {}: {:?}", id, e);
        }
    }
    log::debug!("Registered {} helpers", SUPPORTED_HELPERS.len());
}

/// Register all standard helpers to an rbpf EbpfVmRaw.
pub fn register_all_raw(vm: &mut rbpf::EbpfVmRaw) {
    for &id in SUPPORTED_HELPERS {
        let Some(helper) = get_helper(id) else {
            continue;
        };
        if let Err(e) = vm.register_helper(id, helper) {
            log::warn!("Failed to register helper {}: {:?}", id, e);
        }
    }
    log::debug!("Registered {} helpers", SUPPORTED_HELPERS.len());
}

// =============================================================================
// Extended Helper Registration (includes hypervisor helpers)
// =============================================================================

/// Register all helpers including hypervisor-specific ones.
#[cfg(feature = "tracepoint-support")]
pub fn register_all_with_hypervisor(vm: &mut rbpf::EbpfVmNoData) {
    register_all_nodata(vm);
    crate::tracepoints::register_hypervisor_helpers(vm);
}

/// Register all helpers including hypervisor-specific ones (raw version).
#[cfg(feature = "tracepoint-support")]
pub fn register_all_with_hypervisor_raw(vm: &mut rbpf::EbpfVmRaw) {
    register_all_raw(vm);
    crate::tracepoints::hypervisor_helpers::register_hypervisor_helpers_raw(vm);
}
