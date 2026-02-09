//! Kprobe exception handlers for breakpoint and single-step events.
//!
//! The kprobe library uses a software-based single-step mechanism:
//! 1. BRK #4 (ISS=0x4) - Main breakpoint, inserted at probe address
//! 2. Execute original instruction in the instruction slot
//! 3. BRK #6 (ISS=0x6) - Single-step complete, placed after original instruction in slot
//!
//! This module handles both BRK exceptions to complete the kprobe flow.

use crate::insn_slot;
use crate::probe::hprobe::manager as kprobe_manager;

/// BRK immediate values used by kprobe library (from arch/aarch64/mod.rs)
/// ISS field in ESR contains the immediate value
const KPROBES_BRK_IMM: u64 = 0x004;      // Main breakpoint (BRK #4)
const KPROBES_BRK_SS_IMM: u64 = 0x006;   // Single-step complete (BRK #6)

/// Handle BRK (breakpoint) exception.
/// Called from arm_vcpu exception handler when EC == BRK64.
///
/// Returns true if this was a kprobe breakpoint and was handled.
/// Returns false if not a kprobe (should be handled by default handler).
///
/// # Arguments
/// * `pc` - The program counter where breakpoint was hit (ELR_EL2)
/// * `iss` - Instruction Specific Syndrome (contains BRK immediate value)
/// * `spsr` - Mutable reference to saved program status register
/// * `regs` - Raw pointer and size of the TrapFrame for eBPF context
/// * `set_pc` - Callback to set new PC value
pub fn handle_breakpoint<F>(pc: usize, iss: u64, spsr: &mut u64, regs: Option<(*mut u8, usize)>, set_pc: F) -> bool
where
    F: FnOnce(usize),
{
    log::info!("kprobe_handler: BRK exception at pc={:#x}, iss={:#x}", pc, iss);

    match iss {
        KPROBES_BRK_IMM => {
            // Main breakpoint (BRK #4) - hit at probe address
            handle_main_breakpoint(pc, regs, set_pc)
        }
        KPROBES_BRK_SS_IMM => {
            // Single-step complete (BRK #6) - hit after executing original instruction
            handle_single_step_complete(pc, set_pc)
        }
        _ => {
            log::warn!("kprobe_handler: unknown BRK immediate {:#x} at {:#x}", iss, pc);
            false
        }
    }
}

/// Handle the main breakpoint (BRK #4) at the probe address.
/// This is triggered when execution reaches the probed function.
fn handle_main_breakpoint<F>(pc: usize, regs: Option<(*mut u8, usize)>, set_pc: F) -> bool
where
    F: FnOnce(usize),
{
    log::info!("kprobe_handler: main breakpoint (BRK #4) at {:#x}", pc);

    // Check if this is a registered kprobe
    let is_enabled = match kprobe_manager::lookup(pc) {
        Some(enabled) => {
            log::info!("kprobe_handler: found kprobe at {:#x}, enabled={}", pc, enabled);
            enabled
        }
        None => {
            log::warn!("kprobe_handler: no kprobe registered at {:#x}", pc);
            return false;
        }
    };

    if !is_enabled {
        log::trace!("kprobe_handler: kprobe at {:#x} is disabled", pc);
        return false;
    }

    // Record the hit
    kprobe_manager::record_hit(pc);
    log::info!("kprobe_handler: recorded hit at {:#x}", pc);

    // Execute the attached eBPF program
    if let Some(prog_id) = kprobe_manager::lookup_prog_id(pc) {
        log::info!("kprobe_handler: executing eBPF program {} for {:#x}", prog_id, pc);

        // Use the TrapFrame as context if available
        if let Some((regs_ptr, regs_size)) = regs {
            let ctx = unsafe { core::slice::from_raw_parts_mut(regs_ptr, regs_size) };
            if let Err(e) = crate::runtime::run_program(prog_id, Some(ctx)) {
                log::warn!("kprobe_handler: eBPF program {} failed: {:?}", prog_id, e);
            }
        } else {
            log::warn!("kprobe_handler: no TrapFrame context available for eBPF program");
        }
    }

    // Save original PC for return after single-step
    save_original_pc(pc);

    // Get the instruction slot address where original instruction was copied
    // The slot contains: [original_instruction (4 bytes)][BRK #6 (4 bytes)]
    let slot_addr = get_instruction_slot_for_probe(pc);

    if slot_addr != 0 {
        log::info!(
            "kprobe_handler: jumping to instruction slot at {:#x}",
            slot_addr
        );
        // Set PC to instruction slot to execute the original instruction
        // After executing, we'll hit BRK #6 at slot_addr + 4
        set_pc(slot_addr);
    } else {
        // Fallback: skip the breakpoint instruction (not ideal)
        log::warn!(
            "kprobe_handler: no slot found for {:#x}, skipping breakpoint",
            pc
        );
        set_pc(pc + 4);
    }

    true
}

/// Handle the single-step complete breakpoint (BRK #6) in the instruction slot.
/// This is triggered after executing the original instruction.
fn handle_single_step_complete<F>(pc: usize, set_pc: F) -> bool
where
    F: FnOnce(usize),
{
    log::info!("kprobe_handler: single-step complete (BRK #6) at {:#x}", pc);

    // Verify this is in the instruction slot region
    // BRK #6 is at slot_base + 4 (after the original instruction)
    let slot_base = pc.saturating_sub(4);
    if !insn_slot::is_slot_address(slot_base) {
        log::warn!(
            "kprobe_handler: BRK #6 at {:#x} not in slot region (base would be {:#x})",
            pc, slot_base
        );
        return false;
    }

    // Get the original PC that was saved when we hit the main breakpoint
    let original_pc = get_original_pc();
    if original_pc == 0 {
        log::error!("kprobe_handler: no original PC saved, cannot return");
        return false;
    }

    // Return to the instruction after the original probe point
    let return_pc = original_pc + 4;
    log::info!(
        "kprobe_handler: returning to {:#x} (original was {:#x})",
        return_pc, original_pc
    );

    set_pc(return_pc);
    true
}

/// Get the instruction slot address for a given probe point.
/// This queries the kprobe library to find where the original instruction was stored.
fn get_instruction_slot_for_probe(_probe_addr: usize) -> usize {
    // For now, use the first allocated slot
    // TODO: The kprobe library should provide a way to get the slot for a specific probe
    // This is a simplified implementation that works for single kprobe

    let base = insn_slot::slots_base();
    if insn_slot::free_count() < insn_slot::NUM_SLOTS {
        // At least one slot is allocated, assume it's for this probe
        log::trace!("kprobe_handler: using slot base {:#x}", base);
        return base;
    }

    0
}

/// Per-CPU state for tracking kprobe execution.
/// Stores the original PC so we know where to return after single-step.
mod per_cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Simple per-CPU storage using array indexed by CPU ID
    // Assumes max 8 CPUs for now
    const MAX_CPUS: usize = 8;
    static ORIGINAL_PC: [AtomicUsize; MAX_CPUS] = [
        AtomicUsize::new(0), AtomicUsize::new(0),
        AtomicUsize::new(0), AtomicUsize::new(0),
        AtomicUsize::new(0), AtomicUsize::new(0),
        AtomicUsize::new(0), AtomicUsize::new(0),
    ];

    pub fn save(pc: usize) {
        let cpu = crate::platform::cpu_id() as usize;
        if cpu < MAX_CPUS {
            ORIGINAL_PC[cpu].store(pc, Ordering::SeqCst);
        }
    }

    pub fn get() -> usize {
        let cpu = crate::platform::cpu_id() as usize;
        if cpu < MAX_CPUS {
            ORIGINAL_PC[cpu].load(Ordering::SeqCst)
        } else {
            0
        }
    }
}

/// Save the original PC before single-stepping.
pub fn save_original_pc(pc: usize) {
    per_cpu::save(pc);
}

/// Get the original PC saved before single-stepping.
pub fn get_original_pc() -> usize {
    per_cpu::get()
}
