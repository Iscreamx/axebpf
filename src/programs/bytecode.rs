//! Pre-compiled eBPF bytecode.
//!
//! These are embedded at compile time using include_bytes!().
//! Run `cargo xtask build-ebpf` to generate the .o files.

/// Stats program bytecode (merged counter + latency)
#[cfg(feature = "precompiled-ebpf")]
pub const STATS: &[u8] = include_bytes!("../../../../target/bpf/stats.o");

/// Debug printk program bytecode
#[cfg(feature = "precompiled-ebpf")]
pub const PRINTK: &[u8] = include_bytes!("../../../../target/bpf/printk.o");

/// Kprobe argument tracer bytecode
#[cfg(feature = "precompiled-ebpf")]
pub const KPROBE_ARGS: &[u8] = include_bytes!("../../../../target/bpf/kprobe_args.o");

/// Simple kprobe tracer bytecode (captures x0 only)
#[cfg(feature = "precompiled-ebpf")]
pub const KPROBE_SIMPLE: &[u8] = include_bytes!("../../../../target/bpf/kprobe_simple.o");

/// Minimal noop kprobe bytecode (just returns 1)
#[cfg(feature = "precompiled-ebpf")]
pub const KPROBE_NOOP: &[u8] = include_bytes!("../../../../target/bpf/kprobe_noop.o");

// Fallback when precompiled programs are not available
#[cfg(not(feature = "precompiled-ebpf"))]
pub const STATS: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const PRINTK: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const KPROBE_ARGS: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const KPROBE_SIMPLE: &[u8] = &[];
#[cfg(not(feature = "precompiled-ebpf"))]
pub const KPROBE_NOOP: &[u8] = &[];
