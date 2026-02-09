//! Pre-compiled eBPF bytecode.
//!
//! These are embedded at compile time using include_bytes!().
//! Build eBPF programs from the axebpf-programs repository.

/// Debug printk program bytecode
#[cfg(feature = "precompiled-ebpf")]
pub const PRINTK: &[u8] = include_bytes!("../../../../target/bpf/printk.o");

/// Hprobe entry tracer bytecode (captures x0-x3 arguments)
#[cfg(feature = "precompiled-ebpf")]
pub const HPROBE_ENTRY: &[u8] = include_bytes!("../../../../target/bpf/hprobe_entry.o");

/// Hprobe exit tracer bytecode (captures return value x0)
#[cfg(feature = "precompiled-ebpf")]
pub const HPROBE_EXIT: &[u8] = include_bytes!("../../../../target/bpf/hprobe_exit.o");

// Fallback when precompiled programs are not available
#[cfg(not(feature = "precompiled-ebpf"))]
pub const PRINTK: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const HPROBE_ENTRY: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const HPROBE_EXIT: &[u8] = &[];
