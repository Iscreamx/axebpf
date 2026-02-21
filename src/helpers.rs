//! eBPF helper functions.
//!
//! Standard helpers available to eBPF programs running in AxVisor.
//! These follow Linux BPF helper IDs where applicable.

use crate::map_ops;
use crate::maps;
use spin::Mutex;

/// Static buffer for returning lookup results.
/// Linux BPF returns a pointer to map-internal storage; we simulate this
/// with a static buffer. Max value size supported: 512 bytes.
pub const MAX_VALUE_SIZE: usize = 512;
static LOOKUP_BUFFER: Mutex<[u8; MAX_VALUE_SIZE]> = Mutex::new([0u8; MAX_VALUE_SIZE]);

/// Static buffer for returning tracepoint names.
pub const MAX_NAME_SIZE: usize = 64;
static NAME_BUFFER: Mutex<[u8; MAX_NAME_SIZE]> = Mutex::new([0u8; MAX_NAME_SIZE]);

/// Get the memory range of LOOKUP_BUFFER for registering with rbpf VM.
///
/// This allows eBPF programs to access the buffer returned by bpf_map_lookup_elem.
/// Must be called and registered before VM execution.
///
/// # Returns
/// Memory range (start..end) of the static LOOKUP_BUFFER.
pub fn get_lookup_buffer_range() -> core::ops::Range<u64> {
    let buffer = LOOKUP_BUFFER.lock();
    let start = buffer.as_ptr() as u64;
    let end = start + MAX_VALUE_SIZE as u64;
    start..end
}

/// Get the memory range of NAME_BUFFER for registering with rbpf VM.
pub fn get_name_buffer_range() -> core::ops::Range<u64> {
    let buffer = NAME_BUFFER.lock();
    let start = buffer.as_ptr() as u64;
    let end = start + MAX_NAME_SIZE as u64;
    start..end
}

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
    /// bpf_probe_read(dst, size, src) -> 0 or error
    pub const PROBE_READ: u32 = 4;
    /// bpf_ktime_get_ns() -> nanoseconds
    pub const KTIME_GET_NS: u32 = 5;
    /// bpf_trace_printk(fmt, fmt_size, args...) -> bytes written
    pub const TRACE_PRINTK: u32 = 6;
    /// bpf_get_smp_processor_id() -> CPU ID
    pub const GET_SMP_PROCESSOR_ID: u32 = 8;
    /// bpf_get_tracepoint_name(tracepoint_id) -> name_ptr or 0
    pub const GET_TRACEPOINT_NAME: u32 = 10;
    /// bpf_probe_read_kernel(dst, size, src) -> 0 or error
    /// Same semantics as PROBE_READ, but uses the Linux kernel helper ID.
    pub const PROBE_READ_KERNEL: u32 = 113;
}

// =============================================================================
// Helper Implementations
// =============================================================================

/// bpf_map_lookup_elem - lookup map element by key.
///
/// Linux/Aya semantics:
/// - r1 = map_fd (from ld_map_fd instruction)
/// - r2 = pointer to key (on eBPF stack)
///
/// Returns: pointer to value in static buffer, or 0 if not found.
///
/// SAFETY: Assumes eBPF program is trusted and pointers are valid.
fn bpf_map_lookup_elem(map_fd: u64, key_ptr: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    // Get key_size from Map metadata
    let Some((key_size, _value_size)) = map_ops::get_map_sizes(map_fd as u32) else {
        log::warn!("bpf_map_lookup_elem: map {} not found", map_fd);
        return 0;
    };

    // Read key from pointer (UNSAFE: trusting eBPF program)
    let key_bytes = unsafe {
        let ptr = key_ptr as *const u8;
        core::slice::from_raw_parts(ptr, key_size as usize)
    };

    // Lookup in map
    match maps::lookup_elem(map_fd as u32, key_bytes) {
        Some(value) => {
            // Copy value to static buffer and return pointer
            let mut buffer = LOOKUP_BUFFER.lock();
            let len = value.len().min(MAX_VALUE_SIZE);
            buffer[..len].copy_from_slice(&value[..len]);
            buffer.as_ptr() as u64
        }
        None => 0,
    }
}

/// bpf_map_update_elem - update or insert map element.
///
/// Linux/Aya semantics:
/// - r1 = map_fd
/// - r2 = pointer to key
/// - r3 = pointer to value
/// - r4 = flags (0 = create or update)
///
/// Returns: 0 on success, negative on error.
///
/// SAFETY: Assumes eBPF program is trusted and pointers are valid.
fn bpf_map_update_elem(map_fd: u64, key_ptr: u64, value_ptr: u64, flags: u64, _r5: u64) -> u64 {
    // Get sizes from Map metadata
    let Some((key_size, value_size)) = map_ops::get_map_sizes(map_fd as u32) else {
        log::warn!("bpf_map_update_elem: map {} not found", map_fd);
        return (-1i64) as u64;
    };

    // Read key and value from pointers (UNSAFE: trusting eBPF program)
    let (key_bytes, value_bytes) = unsafe {
        let key = core::slice::from_raw_parts(key_ptr as *const u8, key_size as usize);
        let value = core::slice::from_raw_parts(value_ptr as *const u8, value_size as usize);
        (key, value)
    };

    match maps::update_elem(map_fd as u32, key_bytes, value_bytes, flags) {
        Ok(()) => 0,
        Err(_) => (-1i64) as u64,
    }
}

/// bpf_map_delete_elem - delete map element.
///
/// Linux/Aya semantics:
/// - r1 = map_fd
/// - r2 = pointer to key
///
/// Returns: 0 on success, negative on error.
///
/// SAFETY: Assumes eBPF program is trusted and pointers are valid.
fn bpf_map_delete_elem(map_fd: u64, key_ptr: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    // Get key_size from Map metadata
    let Some((key_size, _value_size)) = map_ops::get_map_sizes(map_fd as u32) else {
        log::warn!("bpf_map_delete_elem: map {} not found", map_fd);
        return (-1i64) as u64;
    };

    // Read key from pointer (UNSAFE: trusting eBPF program)
    let key_bytes = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_size as usize) };

    match maps::delete_elem(map_fd as u32, key_bytes) {
        Ok(()) => 0,
        Err(_) => (-1i64) as u64,
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
/// If r1 is a pointer to NAME_BUFFER, prints as: "[trace] <name> count=<r2>"
/// Otherwise prints: "[bpf_trace] r1=<r1> r2=<r2> r3=<r3>"
fn bpf_trace_printk(r1: u64, r2: u64, r3: u64, _r4: u64, _r5: u64) -> u64 {
    let name_range = get_name_buffer_range();

    if r1 >= name_range.start && r1 < name_range.end {
        // r1 is a pointer to name string in NAME_BUFFER
        let name = unsafe {
            let ptr = r1 as *const u8;
            let mut len = 0;
            while len < MAX_NAME_SIZE && *ptr.add(len) != 0 {
                len += 1;
            }
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
        };
        log::info!("[trace] {} count={}", name, r2);
    } else {
        log::info!("[bpf_trace] r1={:#x} r2={:#x} r3={:#x}", r1, r2, r3);
    }
    0
}

/// bpf_get_smp_processor_id - get current CPU ID.
///
/// Returns: current CPU ID.
fn bpf_get_smp_processor_id(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    crate::platform::cpu_id() as u64
}

/// bpf_probe_read - safely read from kernel memory.
///
/// r1 = destination pointer
/// r2 = size to read
/// r3 = source pointer
/// Returns: 0 on success, negative on error.
///
/// SAFETY: Assumes eBPF program is trusted and pointers are valid.
fn bpf_probe_read(dst: u64, size: u64, src: u64, _r4: u64, _r5: u64) -> u64 {
    if size == 0 || size > 4096 {
        return (-1i64) as u64;
    }

    unsafe {
        let src_ptr = src as *const u8;
        let dst_ptr = dst as *mut u8;
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size as usize);
    }

    0
}

/// bpf_get_tracepoint_name - get tracepoint name by ID.
///
/// r1 = tracepoint_id
/// Returns: pointer to null-terminated name string, or 0 if not found.
fn bpf_get_tracepoint_name(id: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    use crate::tracepoints::registry;

    let Some(name) = registry::get_name(id as u32) else {
        return 0;
    };

    let mut buffer = NAME_BUFFER.lock();
    let len = name.len().min(MAX_NAME_SIZE - 1);
    buffer[..len].copy_from_slice(&name.as_bytes()[..len]);
    buffer[len] = 0; // null terminate
    buffer.as_ptr() as u64
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
        id::PROBE_READ => Some(bpf_probe_read),
        id::KTIME_GET_NS => Some(bpf_ktime_get_ns),
        id::TRACE_PRINTK => Some(bpf_trace_printk),
        id::GET_SMP_PROCESSOR_ID => Some(bpf_get_smp_processor_id),
        id::GET_TRACEPOINT_NAME => Some(bpf_get_tracepoint_name),
        id::PROBE_READ_KERNEL => Some(bpf_probe_read),
        _ => None,
    }
}

/// List of all supported helper IDs.
pub const SUPPORTED_HELPERS: &[u32] = &[
    id::MAP_LOOKUP_ELEM,
    id::MAP_UPDATE_ELEM,
    id::MAP_DELETE_ELEM,
    id::PROBE_READ,
    id::KTIME_GET_NS,
    id::TRACE_PRINTK,
    id::GET_SMP_PROCESSOR_ID,
    id::GET_TRACEPOINT_NAME,
    id::PROBE_READ_KERNEL,
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
