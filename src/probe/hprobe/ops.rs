//! Implementation of KprobeAuxiliaryOps trait for AxVisor.
//!
//! This module provides the "glue layer" between the generic kprobe library
//! and AxVisor's specific memory management and CPU abstractions.

extern crate alloc;

use core::fmt::Debug;

use crate::insn_slot;
use crate::page_table;

/// AxVisor implementation of KprobeAuxiliaryOps.
#[derive(Clone, Copy, Debug)]
pub struct AxKprobeOps;

impl kprobe::KprobeAuxiliaryOps for AxKprobeOps {
    /// Copy memory from source to destination.
    /// For hypervisor kprobes, user_pid is always None (kernel space only).
    ///
    /// If the destination is in the instruction slot region (.text.kprobe_slots),
    /// we need to temporarily make it writable since .text is read-only.
    fn copy_memory(src: *const u8, dst: *mut u8, len: usize, _user_pid: Option<i32>) {
        let dst_addr = dst as usize;
        let is_slot = insn_slot::is_slot_address(dst_addr);

        log::info!(
            "copy_memory: src={:#x} dst={:#x} len={} is_slot={}",
            src as usize, dst_addr, len, is_slot
        );

        // Check if destination is in instruction slot region (part of .text)
        if is_slot {
            // Instruction slots are in .text, need to make writable first
            log::info!("copy_memory: making slot writable");
            if !page_table::set_kernel_text_writable(dst_addr, len, true) {
                log::error!("copy_memory: failed to make slot {:#x} writable", dst_addr);
                return;
            }

            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, len);
            }

            // Restore read-only and flush I-cache
            page_table::set_kernel_text_writable(dst_addr, len, false);
            crate::cache::flush_icache_range(dst_addr, dst_addr + len);
            log::info!("copy_memory: slot write complete");
        } else {
            // Regular memory, just copy
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, len);
            }
        }
    }

    /// Modify page permissions to allow writing to kernel text, execute action, then restore.
    fn set_writeable_for_address<F: FnOnce(*mut u8)>(
        address: usize,
        len: usize,
        _user_pid: Option<i32>,
        action: F,
    ) {
        log::info!("set_writeable_for_address: addr={:#x} len={}", address, len);

        // Read original instruction before modification
        let orig_insn = unsafe { core::ptr::read_volatile(address as *const u32) };
        log::info!("set_writeable_for_address: original insn at {:#x} = {:#010x}", address, orig_insn);

        // Make writable
        if !page_table::set_kernel_text_writable(address, len, true) {
            log::error!(
                "kprobe_ops: failed to make {:#x} writable",
                address
            );
            return;
        }

        // Execute the action
        action(address as *mut u8);

        // Read instruction after modification
        let new_insn = unsafe { core::ptr::read_volatile(address as *const u32) };
        log::info!("set_writeable_for_address: new insn at {:#x} = {:#010x}", address, new_insn);

        // Restore read-only
        page_table::set_kernel_text_writable(address, len, false);

        // Flush I-cache
        crate::cache::flush_icache_range(address, address + len);
        log::info!("set_writeable_for_address: I-cache flushed");
    }

    /// Allocate an executable memory page for instruction slots.
    ///
    /// The allocated slot is in .text.kprobe_slots which is read-only by default.
    /// We make it writable here since the kprobe library will write to it directly.
    fn alloc_kernel_exec_memory() -> *mut u8 {
        match insn_slot::alloc_slot() {
            Some(addr) => {
                // Make the slot writable since kprobe library writes to it directly
                log::info!("alloc_kernel_exec_memory: making slot {:#x} writable", addr);
                if !page_table::set_kernel_text_writable(addr, insn_slot::SLOT_SIZE, true) {
                    log::error!("alloc_kernel_exec_memory: failed to make slot writable");
                    insn_slot::free_slot(addr);
                    return core::ptr::null_mut();
                }
                addr as *mut u8
            }
            None => {
                log::error!("kprobe_ops: failed to allocate instruction slot");
                core::ptr::null_mut()
            }
        }
    }

    /// Free an executable memory page.
    fn free_kernel_exec_memory(ptr: *mut u8) {
        if !ptr.is_null() {
            let addr = ptr as usize;
            // Restore read-only before freeing
            page_table::set_kernel_text_writable(addr, insn_slot::SLOT_SIZE, false);
            crate::cache::flush_icache_range(addr, addr + insn_slot::SLOT_SIZE);
            insn_slot::free_slot(addr);
        }
    }

    /// Allocate user executable memory - not supported in hypervisor context.
    fn alloc_user_exec_memory<F: FnOnce(*mut u8)>(_pid: Option<i32>, _action: F) -> *mut u8 {
        log::warn!("kprobe_ops: alloc_user_exec_memory not supported in hypervisor");
        core::ptr::null_mut()
    }

    /// Free user executable memory - not supported in hypervisor context.
    fn free_user_exec_memory(_pid: Option<i32>, _ptr: *mut u8) {
        log::warn!("kprobe_ops: free_user_exec_memory not supported in hypervisor");
    }

    /// Insert a kretprobe instance to the current task.
    /// For hypervisor, we use per-CPU storage since there are no traditional tasks.
    fn insert_kretprobe_instance_to_task(instance: kprobe::retprobe::RetprobeInstance) {
        per_cpu::push_retprobe_instance(instance);
    }

    /// Pop a kretprobe instance from the current task.
    fn pop_kretprobe_instance_from_task() -> kprobe::retprobe::RetprobeInstance {
        per_cpu::pop_retprobe_instance()
    }
}

/// Per-CPU storage for kretprobe instances.
mod per_cpu {
    use alloc::vec::Vec;
    use kprobe::retprobe::RetprobeInstance;
    use spin::Mutex;

    const MAX_CPUS: usize = 8;

    struct PerCpuRetprobeStack {
        stacks: [Mutex<Vec<RetprobeInstance>>; MAX_CPUS],
    }

    impl PerCpuRetprobeStack {
        const fn new() -> Self {
            Self {
                stacks: [
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                    Mutex::new(Vec::new()),
                ],
            }
        }
    }

    static RETPROBE_STACKS: PerCpuRetprobeStack = PerCpuRetprobeStack::new();

    pub fn push_retprobe_instance(instance: RetprobeInstance) {
        let cpu = crate::platform::cpu_id() as usize;
        if cpu < MAX_CPUS {
            RETPROBE_STACKS.stacks[cpu].lock().push(instance);
        }
    }

    pub fn pop_retprobe_instance() -> RetprobeInstance {
        let cpu = crate::platform::cpu_id() as usize;
        if cpu < MAX_CPUS {
            if let Some(instance) = RETPROBE_STACKS.stacks[cpu].lock().pop() {
                return instance;
            }
        }
        // This should not happen in normal operation - panic for debugging
        panic!("kprobe_ops: no retprobe instance on stack for CPU {}", cpu);
    }
}

/// Breakpoint instruction bytes for AArch64.
#[cfg(target_arch = "aarch64")]
pub const BRK_INSN: [u8; 4] = [0x00, 0x00, 0x20, 0xD4]; // BRK #0 little-endian

/// Breakpoint instruction bytes for x86_64.
#[cfg(target_arch = "x86_64")]
pub const BRK_INSN: [u8; 1] = [0xCC]; // INT3

/// Size of a breakpoint instruction in bytes.
#[cfg(target_arch = "aarch64")]
pub const BRK_INSN_SIZE: usize = 4;

#[cfg(target_arch = "x86_64")]
pub const BRK_INSN_SIZE: usize = 1;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub const BRK_INSN: [u8; 4] = [0; 4];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub const BRK_INSN_SIZE: usize = 4;
