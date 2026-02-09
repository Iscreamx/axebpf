//! Tracepoints for AxVisor.
//!
//! This module provides tracepoint definitions and built-in statistics
//! for monitoring hypervisor performance.
//!
//! # Subsystems
//!
//! - `vmm` - VMM layer tracepoints (system init, VM lifecycle, timer)
//! - `shell` - Shell tracepoints (command execution, initialization)

pub mod histogram;
pub mod hypervisor_helpers;
pub mod registry;
pub mod shell;
pub mod stats;
pub mod vmm;

// Re-export VMM tracepoint trigger functions
pub use vmm::{
    trace_config_load,
    trace_image_load,
    trace_timer_event,
    trace_timer_tick,
    trace_vm_destroy,
    trace_vmm_init,
};

// Re-export Shell tracepoint trigger functions
pub use shell::{trace_shell_command, trace_shell_init};

// Re-export histogram types
pub use histogram::{BUCKET_BOUNDS_NS, BUCKET_LABELS, HistogramSnapshot, LatencyHistogram};

// Re-export stats execution functions
pub use stats::{execute_attached_program, record_duration, record_hit};

// Re-export hypervisor helpers
pub use hypervisor_helpers::{
    clear_current_context, get_hypervisor_helper, hypervisor_helper_ids,
    register_hypervisor_helpers, register_hypervisor_helpers_raw, set_current_context,
};

/// Initialize tracepoints subsystem.
pub fn init() {
    registry::init();
    log::info!("Tracepoints initialized");
}
