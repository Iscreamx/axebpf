//! Tracepoints for AxVisor.
//!
//! This module provides tracepoint definitions and built-in statistics
//! for monitoring hypervisor performance.
//!
//! # Subsystems
//!
//! - `vmm` - VMM layer tracepoints (VM lifecycle, vCPU, memory, device, timer)
//! - `shell` - Shell tracepoints (command execution, initialization)
//!
//! # Usage
//!
//! ```ignore
//! use axebpf::tracepoints::*;
//!
//! // In vcpu_run loop:
//! let start = ktime_get_ns();
//! trace_vcpu_run_enter(vm_id, vcpu_id);
//! let exit_reason = vm.run_vcpu(vcpu_id);
//! let duration = ktime_get_ns() - start;
//! trace_vcpu_run_exit(vm_id, vcpu_id, exit_reason, duration);
//! ```

pub mod histogram;
pub mod hypervisor_helpers;
pub mod registry;
pub mod shell;
pub mod stats;
pub mod vmm;

// Re-export VMM tracepoint trigger functions
pub use vmm::{
    trace_config_load,
    trace_cpu_up,
    // Device & IRQ
    trace_device_access,
    trace_external_interrupt,
    trace_hypercall,
    trace_image_load,
    trace_ipi_send,
    trace_irq_handle,
    trace_irq_inject,
    // Memory
    trace_memory_map,
    trace_memory_unmap,
    trace_page_fault,
    trace_task_switch,
    trace_timer_event,
    // Timer & Scheduling
    trace_timer_tick,
    // vCPU Lifecycle
    trace_vcpu_create,
    trace_vcpu_destroy,
    trace_vcpu_halt,
    // vCPU Runtime
    trace_vcpu_run_enter,
    trace_vcpu_run_exit,
    trace_vcpu_state_change,
    trace_vhal_init,
    trace_vm_boot,
    // VM Lifecycle
    trace_vm_create,
    trace_vm_destroy,
    trace_vm_shutdown,
    // System
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
