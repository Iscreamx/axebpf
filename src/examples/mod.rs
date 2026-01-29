//! Example tracepoint definitions.
//!
//! This module contains example tracepoints demonstrating how to define
//! tracepoints using the ktracepoint library with AxVisor's AxKops.
//!
//! These examples are for reference only and should be defined in the
//! appropriate modules (e.g., VMM tracepoints should be in axvm or kernel).

// Note: vmm_tracepoints moved to modules/axebpf/src/vmm_tracepoints/

#[cfg(feature = "runtime")]
pub mod runtime_example;
