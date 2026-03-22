//! Unified probe framework for AxVisor.
//!
//! Provides a common abstraction over different probe types:
//! - hprobe: VMM self-introspection (EL2 breakpoints)
//! - kprobe: Guest kernel probing (Stage-2 faults or BRK injection)
//! - tracepoint: VMM static instrumentation points

extern crate alloc;

#[cfg(feature = "hprobe")]
pub mod hprobe;

#[cfg(feature = "guest-kprobe")]
pub mod kprobe;

#[cfg(any(feature = "guest-kprobe", feature = "guest-uprobe"))]
pub mod guest_runtime_state;

#[cfg(feature = "guest-uprobe")]
pub mod uprobe;

/// Probe type classification by privilege level and direction.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    /// VMM function entry (EL2 self-introspection)
    Hprobe = 0,
    /// VMM function return
    Hretprobe = 1,
    /// Guest kernel function entry (cross-privilege probing)
    Kprobe = 2,
    /// Guest kernel function return
    Kretprobe = 3,
    /// VMM static instrumentation point
    Tracepoint = 4,
    /// Guest user function entry
    Uprobe = 5,
    /// Guest user function return
    Uretprobe = 6,
}

impl ProbeType {
    /// Whether this probe targets guest VM code (vs VMM/host code).
    pub fn is_guest_probe(&self) -> bool {
        matches!(
            self,
            ProbeType::Kprobe | ProbeType::Kretprobe | ProbeType::Uprobe | ProbeType::Uretprobe
        )
    }

    /// Whether this is a return probe.
    pub fn is_return_probe(&self) -> bool {
        matches!(
            self,
            ProbeType::Hretprobe | ProbeType::Kretprobe | ProbeType::Uretprobe
        )
    }

    /// Short label for display.
    pub fn label(&self) -> &'static str {
        match self {
            ProbeType::Hprobe => "hprobe",
            ProbeType::Hretprobe => "hretprobe",
            ProbeType::Kprobe => "kprobe",
            ProbeType::Kretprobe => "kretprobe",
            ProbeType::Tracepoint => "tracepoint",
            ProbeType::Uprobe => "uprobe",
            ProbeType::Uretprobe => "uretprobe",
        }
    }
}
