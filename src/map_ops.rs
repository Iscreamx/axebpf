//! kbpf-basic KernelAuxiliaryOps implementation for AxVisor.
//!
//! Provides the minimal kernel operations required by kbpf-basic Map types.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt::Debug;

use kbpf_basic::map::{PerCpuVariants, PerCpuVariantsOps, UnifiedMap};
use kbpf_basic::{BpfError, KernelAuxiliaryOps, Result};
use spin::Mutex;

/// Global Map registry storing all created UnifiedMaps.
/// Maps are accessed by index (map_fd).
pub static MAP_REGISTRY: Mutex<Vec<Option<UnifiedMap>>> = Mutex::new(Vec::new());

/// AxVisor implementation of KernelAuxiliaryOps.
///
/// Provides minimal implementation for basic Map operations.
/// Advanced features (RingBuf, PerCpu, Perf) return NotSupported.
pub struct AxKernelAuxOps;

impl KernelAuxiliaryOps for AxKernelAuxOps {
    fn get_unified_map_from_ptr<F, R>(_ptr: *const u8, _func: F) -> Result<R>
    where
        F: FnOnce(&mut UnifiedMap) -> Result<R>,
    {
        Err(BpfError::NotSupported)
    }

    fn get_unified_map_from_fd<F, R>(map_fd: u32, func: F) -> Result<R>
    where
        F: FnOnce(&mut UnifiedMap) -> Result<R>,
    {
        let mut registry = MAP_REGISTRY.lock();
        let map = registry
            .get_mut(map_fd as usize)
            .ok_or(BpfError::NotFound)?
            .as_mut()
            .ok_or(BpfError::NotFound)?;
        func(map)
    }

    fn get_unified_map_ptr_from_fd(map_fd: u32) -> Result<*const u8> {
        let registry = MAP_REGISTRY.lock();
        let map = registry
            .get(map_fd as usize)
            .ok_or(BpfError::NotFound)?
            .as_ref()
            .ok_or(BpfError::NotFound)?;
        Ok(map as *const UnifiedMap as *const u8)
    }

    fn copy_from_user(_src: *const u8, _size: usize, _dst: &mut [u8]) -> Result<()> {
        // Hypervisor runs in kernel space, no user/kernel separation
        Err(BpfError::NotSupported)
    }

    fn copy_to_user(_dest: *mut u8, _size: usize, _src: &[u8]) -> Result<()> {
        // Hypervisor runs in kernel space, no user/kernel separation
        Err(BpfError::NotSupported)
    }

    fn current_cpu_id() -> u32 {
        crate::platform::cpu_id()
    }

    fn perf_event_output(_ctx: *mut c_void, _fd: u32, _flags: u32, _data: &[u8]) -> Result<()> {
        // PerfEventArray not supported in this phase
        Err(BpfError::NotSupported)
    }

    fn string_from_user_cstr(_ptr: *const u8) -> Result<String> {
        // Hypervisor runs in kernel space, no user/kernel separation
        Err(BpfError::NotSupported)
    }

    fn ebpf_write_str(s: &str) -> Result<()> {
        log::info!("[ebpf] {}", s);
        Ok(())
    }

    fn ebpf_time_ns() -> Result<u64> {
        Ok(crate::platform::time_ns())
    }

    fn alloc_page() -> Result<usize> {
        // RingBuf not supported in this phase
        Err(BpfError::NotSupported)
    }

    fn free_page(_phys_addr: usize) {
        // RingBuf not supported in this phase
    }

    fn vmap(_phys_addrs: &[usize]) -> Result<usize> {
        // RingBuf not supported in this phase
        Err(BpfError::NotSupported)
    }

    fn unmap(_vaddr: usize) {
        // RingBuf not supported in this phase
    }
}

/// Register a new UnifiedMap in the registry.
/// Returns the map_fd (index).
pub fn register_map(map: UnifiedMap) -> u32 {
    let mut registry = MAP_REGISTRY.lock();

    // Find empty slot or append
    for (i, slot) in registry.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(map);
            return i as u32;
        }
    }

    let id = registry.len() as u32;
    registry.push(Some(map));
    id
}

/// Unregister a map from the registry.
pub fn unregister_map(map_fd: u32) -> Result<()> {
    let mut registry = MAP_REGISTRY.lock();
    let slot = registry
        .get_mut(map_fd as usize)
        .ok_or(BpfError::NotFound)?;
    if slot.is_none() {
        return Err(BpfError::NotFound);
    }
    *slot = None;
    Ok(())
}

/// Get the number of active maps in the registry.
pub fn map_count() -> usize {
    let registry = MAP_REGISTRY.lock();
    registry.iter().filter(|s| s.is_some()).count()
}

// =============================================================================
// PerCpuVariantsOps Placeholder Implementation
// =============================================================================

/// Dummy PerCpu implementation.
///
/// Returns None for all create calls, effectively disabling PerCpu Map types.
/// This is acceptable for Phase 1 as we only support basic Map types.
#[derive(Debug)]
pub struct DummyPerCpuOps;

impl PerCpuVariantsOps for DummyPerCpuOps {
    fn create<T: Clone + Sync + Send + 'static>(_value: T) -> Option<Box<dyn PerCpuVariants<T>>> {
        // PerCpu Maps not supported in this phase
        None
    }

    fn num_cpus() -> u32 {
        // Return 1 as fallback
        1
    }
}
