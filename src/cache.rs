//! Instruction and data cache maintenance for code patching.

/// Flush instruction cache for the specified address range.
/// Required after modifying kernel text to ensure CPU fetches updated instructions.
///
/// On AArch64:
/// 1. DC CVAU - Clean data cache to Point of Unification
/// 2. DSB ISH - Data synchronization barrier (inner shareable)
/// 3. IC IVAU - Invalidate instruction cache to PoU
/// 4. DSB ISH - Ensure completion
/// 5. ISB - Instruction synchronization barrier
#[cfg(target_arch = "aarch64")]
pub fn flush_icache_range(start: usize, end: usize) {
    // Cache line size is typically 64 bytes on modern ARM cores
    const CACHE_LINE_SIZE: usize = 64;

    let start_aligned = start & !(CACHE_LINE_SIZE - 1);

    unsafe {
        for addr in (start_aligned..end).step_by(CACHE_LINE_SIZE) {
            core::arch::asm!(
                "dc cvau, {0}",     // Clean data cache to PoU
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }

        core::arch::asm!(
            "dsb ish",              // Data synchronization barrier
            options(nostack, preserves_flags)
        );

        for addr in (start_aligned..end).step_by(CACHE_LINE_SIZE) {
            core::arch::asm!(
                "ic ivau, {0}",     // Invalidate instruction cache
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }

        core::arch::asm!(
            "dsb ish",              // Ensure IC invalidation complete
            "isb",                  // Instruction synchronization
            options(nostack, preserves_flags)
        );
    }

    log::trace!("flush_icache_range: {:#x} - {:#x}", start, end);
}

#[cfg(target_arch = "x86_64")]
pub fn flush_icache_range(_start: usize, _end: usize) {
    // x86_64 has cache coherency between I-cache and D-cache.
    // A serializing instruction is sufficient.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub fn flush_icache_range(_start: usize, _end: usize) {
    log::warn!("flush_icache_range: not implemented for this architecture");
}
