//! Platform abstraction layer for kernel operations.
//!
//! This module provides an abstraction over platform-specific operations
//! (time, CPU ID) to allow testing in user space.

use core::sync::atomic::{AtomicU64, Ordering};

/// Platform operations trait.
///
/// Abstracts over kernel-specific operations to enable mock testing.
pub trait PlatformOps {
    /// Get current monotonic time in nanoseconds.
    fn time_ns() -> u64;

    /// Get current CPU ID.
    fn cpu_id() -> u32;
}

// =============================================================================
// Real Implementation (kernel environment with axhal)
// =============================================================================

/// Real platform operations using axhal.
#[cfg(all(not(test), feature = "axhal"))]
pub struct RealPlatform;

#[cfg(all(not(test), feature = "axhal"))]
impl PlatformOps for RealPlatform {
    fn time_ns() -> u64 {
        axhal::time::monotonic_time().as_nanos() as u64
    }

    fn cpu_id() -> u32 {
        axhal::percpu::this_cpu_id() as u32
    }
}

// =============================================================================
// Mock Implementation (test environment or no axhal)
// =============================================================================

/// Mock time value for testing.
static MOCK_TIME_NS: AtomicU64 = AtomicU64::new(1_000_000_000); // 1 second

/// Mock CPU ID for testing.
static MOCK_CPU_ID: AtomicU64 = AtomicU64::new(0);

/// Mock platform operations for testing.
#[cfg(any(test, not(feature = "axhal")))]
pub struct MockPlatform;

#[cfg(any(test, not(feature = "axhal")))]
impl PlatformOps for MockPlatform {
    fn time_ns() -> u64 {
        MOCK_TIME_NS.load(Ordering::Relaxed)
    }

    fn cpu_id() -> u32 {
        MOCK_CPU_ID.load(Ordering::Relaxed) as u32
    }
}

/// Set mock time for testing.
pub fn set_mock_time(ns: u64) {
    MOCK_TIME_NS.store(ns, Ordering::Relaxed);
}

/// Advance mock time by given nanoseconds.
pub fn advance_mock_time(ns: u64) {
    MOCK_TIME_NS.fetch_add(ns, Ordering::Relaxed);
}

/// Set mock CPU ID for testing.
pub fn set_mock_cpu_id(id: u32) {
    MOCK_CPU_ID.store(id as u64, Ordering::Relaxed);
}

// =============================================================================
// Platform Type Alias
// =============================================================================

/// The active platform implementation.
///
/// In kernel environment with axhal: RealPlatform (uses axhal)
/// In test environment or without axhal: MockPlatform (uses atomic counters)
#[cfg(all(not(test), feature = "axhal"))]
pub type Platform = RealPlatform;

#[cfg(any(test, not(feature = "axhal")))]
pub type Platform = MockPlatform;

// =============================================================================
// Convenience Functions
// =============================================================================

/// Get current time in nanoseconds.
#[inline]
pub fn time_ns() -> u64 {
    Platform::time_ns()
}

/// Get current CPU ID.
#[inline]
pub fn cpu_id() -> u32 {
    Platform::cpu_id()
}

/// Get current VM ID.
///
/// Returns 0 when in host context (not handling a VM).
/// In kernel environment, this should query the VMM's current VM state.
#[cfg(not(test))]
pub fn current_vm_id() -> u32 {
    // TODO: Integrate with axvisor's VM tracking
    // For now, return 0 (host context)
    0
}

#[cfg(test)]
pub fn current_vm_id() -> u32 {
    0
}

/// Get current vCPU ID.
///
/// Returns 0 when not in vCPU context.
/// In kernel environment, this should query the VMM's current vCPU state.
#[cfg(not(test))]
pub fn current_vcpu_id() -> u32 {
    // TODO: Integrate with axvisor's vCPU tracking
    // For now, return 0 (not in vCPU context)
    0
}

#[cfg(test)]
pub fn current_vcpu_id() -> u32 {
    0
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_time() {
        set_mock_time(5000);
        assert_eq!(time_ns(), 5000);

        advance_mock_time(1000);
        assert_eq!(time_ns(), 6000);
    }

    #[test]
    fn test_mock_cpu_id() {
        set_mock_cpu_id(3);
        assert_eq!(cpu_id(), 3);

        set_mock_cpu_id(7);
        assert_eq!(cpu_id(), 7);
    }
}
