//! Hypervisor Probe (hprobe) — VMM self-introspection.
//!
//! Probes VMM's own code (EL2) using BRK instruction injection
//! and instruction slot single-stepping. This is the renamed
//! former "kprobe" module, now called "hprobe" to distinguish
//! from guest kernel probes.

pub mod handler;
pub mod manager;
pub mod ops;

pub use manager::{
    attach, detach, disable, enable, init, list_all, register,
    unregister, KprobeEntry, KprobeRegistry, KprobeState,
};
pub use handler::handle_breakpoint;
pub use ops::AxKprobeOps;
