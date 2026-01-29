//! AxVisor tracepoint definition macros.
//!
//! Provides re-exports and documentation for defining tracepoints in AxVisor VMM code.
//!
//! # Note on Macro Hygiene
//!
//! Due to Rust's macro hygiene rules, wrapper macros cannot properly pass the `__entry`
//! identifier across macro boundaries. For defining tracepoints, use the `tracepoint::define_event_trace!`
//! macro directly with AxVisor-specific types:
//!
//! ```ignore
//! use axebpf::trace_ops::AxKops;
//!
//! tracepoint::define_event_trace!(
//!     my_tracepoint,
//!     TP_lock(spin::Mutex<()>),
//!     TP_kops(AxKops),
//!     TP_system(vmm),
//!     TP_PROTO(arg1: u32, arg2: u32),
//!     TP_STRUCT__entry { arg1: u32, arg2: u32 },
//!     TP_fast_assign { arg1: arg1, arg2: arg2 },
//!     TP_ident(__entry),
//!     TP_printk(format_args!("arg1={} arg2={}", __entry.arg1, __entry.arg2))
//! );
//! ```
//!
//! # AxVisor Defaults
//!
//! When defining tracepoints for AxVisor, use these types:
//! - Lock: `spin::Mutex<()>`
//! - KernelOps: `axebpf::trace_ops::AxKops`

// Re-export the define_event_trace macro for convenience
pub use tracepoint::define_event_trace;
