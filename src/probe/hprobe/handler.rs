//! Hprobe exception handlers for BRK breakpoint events.
//!
//! Delegates to the kprobe library's `kprobe_handler_from_break` and
//! `kprobe_handler_from_debug` for proper kprobe/kretprobe handling.
//!
//! The kprobe library manages the full lifecycle:
//! - BRK #4 (ISS=0x4): main breakpoint at probe address
//!   → calls pre_handler (kprobe) or pre_handler_kretprobe (kretprobe, replaces LR)
//!   → redirects PC to instruction slot for single-stepping
//! - BRK #6 (ISS=0x6): single-step complete in instruction slot
//!   → calls post_handler
//!   → restores PC to original return address

use super::manager::KPROBE_REGISTRY;

/// BRK immediate values used by kprobe library.
const KPROBES_BRK_IMM: u64 = 0x004;    // Main breakpoint (BRK #4)
const KPROBES_BRK_SS_IMM: u64 = 0x006; // Single-step complete (BRK #6)

/// Size of TrapFrame (Aarch64ContextFrame) that overlaps with kprobe::PtRegs.
/// Layout: gpr[31] (248B) + sp_el0 (8B) + elr (8B) + spsr (8B) = 272B.
const TRAPFRAME_COMPAT_SIZE: usize = 272;

#[inline]
fn probe_pc(pt_regs: &kprobe::PtRegs) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        return pt_regs.pc as usize;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // On x86_64, INT3 advances RIP by 1, so the probe point is RIP - 1.
        return pt_regs.rip.saturating_sub(1);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = pt_regs;
        0
    }
}

#[inline]
fn arg_at(pt_regs: &kprobe::PtRegs, idx: usize) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        return pt_regs.regs[idx];
    }
    #[cfg(target_arch = "x86_64")]
    {
        return match idx {
            0 => pt_regs.rdi as u64,
            1 => pt_regs.rsi as u64,
            2 => pt_regs.rdx as u64,
            3 => pt_regs.rcx as u64,
            _ => 0,
        };
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (pt_regs, idx);
        0
    }
}

/// Handle BRK (breakpoint) exception from current EL.
///
/// Called from arm_vcpu exception handler when EC == BRK64.
/// Constructs a kprobe::PtRegs from the TrapFrame, delegates to the
/// kprobe library, then writes back any register modifications
/// (PC redirect, LR replacement for kretprobe).
///
/// # Arguments
/// * `regs_ptr` - Pointer to TrapFrame (Aarch64ContextFrame), must be valid and writable
/// * `regs_size` - Size of TrapFrame in bytes, must be >= 272
/// * `iss` - Instruction Specific Syndrome (contains BRK immediate value)
///
/// # Returns
/// `true` if handled as hprobe/hretprobe breakpoint, `false` otherwise.
///
/// # Safety
/// `regs_ptr` must point to a valid, writable TrapFrame of at least `regs_size` bytes.
pub fn handle_breakpoint(regs_ptr: *mut u8, regs_size: usize, iss: u64) -> bool {
    if regs_ptr.is_null() || regs_size < TRAPFRAME_COMPAT_SIZE {
        log::warn!(
            "hprobe_handler: invalid regs_ptr ({:?}) or size ({} < {})",
            regs_ptr, regs_size, TRAPFRAME_COMPAT_SIZE
        );
        return false;
    }

    // Construct PtRegs on stack: copy first 272B from TrapFrame, zero-fill tail.
    // TrapFrame and PtRegs share identical layout for the first 272 bytes:
    //   gpr[31]/regs[31], sp_el0/sp, elr/pc, spsr/pstate
    let mut pt_regs: kprobe::PtRegs = unsafe { core::mem::zeroed() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            regs_ptr,
            &mut pt_regs as *mut kprobe::PtRegs as *mut u8,
            TRAPFRAME_COMPAT_SIZE,
        );
    }

    let handled = match iss {
        KPROBES_BRK_IMM => handle_brk_main(&mut pt_regs),
        KPROBES_BRK_SS_IMM => handle_brk_single_step(&mut pt_regs),
        _ => {
            log::debug!("hprobe_handler: unrecognized BRK ISS {:#x}", iss);
            false
        }
    };

    // Write back modified registers (LR, PC, etc.) to TrapFrame
    if handled {
        unsafe {
            core::ptr::copy_nonoverlapping(
                &pt_regs as *const kprobe::PtRegs as *const u8,
                regs_ptr,
                TRAPFRAME_COMPAT_SIZE,
            );
        }
    }

    handled
}

/// Handle main breakpoint (BRK #4) at probe address.
///
/// Delegates to `kprobe::kprobe_handler_from_break` which:
/// - For kprobe: calls pre_handler, sets PC to instruction slot
/// - For kretprobe: calls pre_handler_kretprobe (replaces LR with trampoline),
///   then sets PC to instruction slot
fn handle_brk_main(pt_regs: &mut kprobe::PtRegs) -> bool {
    let mut registry = KPROBE_REGISTRY.lock();
    let reg = match registry.as_mut() {
        Some(r) => r,
        None => {
            log::warn!(
                "handle_brk_main: registry not initialized, BRK at pc={:#x}",
                probe_pc(pt_regs)
            );
            return false;
        }
    };

    let probe_addr = probe_pc(pt_regs);
    let result = kprobe::kprobe_handler_from_break(reg.manager_mut(), pt_regs);

    if result.is_some() {
        let (entry_hit, _ret_hit) = reg.record_break_hit(probe_addr);
        log::debug!("handle_brk_main: hit recorded at {:#x}", probe_addr);

        #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
        if entry_hit {
            let mut event = crate::event::TraceEvent::new(
                crate::event::PROBE_HPROBE,
                probe_addr as u32,
            );
            event.name_offset = crate::event::register_event_name("hprobe");
            event.nr_args = 4;
            event.args[0] = arg_at(pt_regs, 0);
            event.args[1] = arg_at(pt_regs, 1);
            event.args[2] = arg_at(pt_regs, 2);
            event.args[3] = arg_at(pt_regs, 3);
            crate::event::emit_event(&event);
        }

        true
    } else {
        log::warn!("handle_brk_main: no probe found for pc={:#x}", probe_addr);
        false
    }
}

/// Handle single-step complete breakpoint (BRK #6) in instruction slot.
///
/// Delegates to `kprobe::kprobe_handler_from_debug` which:
/// - Calls post_handler for any registered probes
/// - Sets PC to the return address (original probe point + 4)
fn handle_brk_single_step(pt_regs: &mut kprobe::PtRegs) -> bool {
    let mut registry = KPROBE_REGISTRY.lock();
    let reg = match registry.as_mut() {
        Some(r) => r,
        None => return false,
    };

    kprobe::kprobe_handler_from_debug(reg.manager_mut(), pt_regs).is_some()
}
