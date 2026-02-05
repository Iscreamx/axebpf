//! Instruction slot allocator for out-of-line execution.
//!
//! When a kprobe is triggered, the original instruction at the probe point
//! is replaced with a breakpoint. The original instruction is copied to an
//! "instruction slot" where it can be safely executed via single-stepping.

use core::ptr::addr_of;
use spin::Mutex;

/// Size of each instruction slot in bytes.
/// Must be large enough for one instruction + optional jump back.
/// AArch64: 4 bytes per instruction, reserve 32 for future expansion.
pub const SLOT_SIZE: usize = 32;

/// Number of available instruction slots.
/// 64 slots = 2KB total, sufficient for typical usage.
pub const NUM_SLOTS: usize = 64;

/// Pre-allocated instruction slots in the .text section.
/// These are executable by virtue of being in .text.
#[unsafe(link_section = ".text.kprobe_slots")]
#[used]
static mut INSN_SLOTS: [[u8; SLOT_SIZE]; NUM_SLOTS] = [[0u8; SLOT_SIZE]; NUM_SLOTS];

/// Bitmap tracking which slots are allocated.
/// Bit N = 1 means slot N is in use.
static SLOT_BITMAP: Mutex<u64> = Mutex::new(0);

/// Allocate an instruction slot.
/// Returns the address of the allocated slot, or None if all slots are in use.
pub fn alloc_slot() -> Option<usize> {
    let mut bitmap = SLOT_BITMAP.lock();

    for i in 0..NUM_SLOTS.min(64) {
        if (*bitmap & (1u64 << i)) == 0 {
            *bitmap |= 1u64 << i;
            let addr = unsafe { addr_of!(INSN_SLOTS[i]) as usize };
            log::info!("insn_slot: allocated slot {} at {:#x} (base={:#x})", i, addr, slots_base());
            return Some(addr);
        }
    }

    log::warn!("insn_slot: no free slots available");
    None
}

/// Free a previously allocated instruction slot.
pub fn free_slot(addr: usize) {
    let base = slots_base();
    let end = base + NUM_SLOTS * SLOT_SIZE;

    if addr < base || addr >= end {
        log::warn!("insn_slot: invalid slot address {:#x}", addr);
        return;
    }

    let idx = (addr - base) / SLOT_SIZE;
    let mut bitmap = SLOT_BITMAP.lock();
    *bitmap &= !(1u64 << idx);
    log::debug!("insn_slot: freed slot {} at {:#x}", idx, addr);
}

/// Get the base address of the instruction slot region.
pub fn slots_base() -> usize {
    addr_of!(INSN_SLOTS) as usize
}

/// Get the end address of the instruction slot region.
pub fn slots_end() -> usize {
    slots_base() + NUM_SLOTS * SLOT_SIZE
}

/// Check if an address is within the instruction slot region.
pub fn is_slot_address(addr: usize) -> bool {
    addr >= slots_base() && addr < slots_end()
}

/// Get number of free slots.
pub fn free_count() -> usize {
    let bitmap = SLOT_BITMAP.lock();
    NUM_SLOTS - (*bitmap).count_ones() as usize
}
