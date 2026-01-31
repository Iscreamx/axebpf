//! Shell subsystem tracepoint definitions.
//!
//! Defines tracepoints for the AxVisor shell:
//! - shell_init: Shell initialization
//! - shell_command: Shell command execution

use crate::trace_ops::AxKops;
use crate::tracepoint::KernelTraceOps;

use super::stats::execute_attached_program;

// =============================================================================
// Shell Tracepoints (internal module to avoid name collision)
// =============================================================================

mod internal {
    use crate::trace_ops::AxKops;

    tracepoint::define_event_trace!(
        shell_command,
        TP_lock(spin::Mutex<()>),
        TP_kops(AxKops),
        TP_system(shell),
        TP_PROTO(cmd_id: u32, duration_ns: u64),
        TP_STRUCT__entry { cmd_id: u32, duration_ns: u64 },
        TP_fast_assign { cmd_id: cmd_id, duration_ns: duration_ns },
        TP_ident(__entry),
        TP_printk(format_args!("cmd_id={} duration_ns={}", __entry.cmd_id, __entry.duration_ns))
    );

    tracepoint::define_event_trace!(
        shell_init,
        TP_lock(spin::Mutex<()>),
        TP_kops(AxKops),
        TP_system(shell),
        TP_PROTO(duration_ns: u64),
        TP_STRUCT__entry { duration_ns: u64 },
        TP_fast_assign { duration_ns: duration_ns },
        TP_ident(__entry),
        TP_printk(format_args!("duration_ns={}", __entry.duration_ns))
    );
}

// =============================================================================
// Wrapper functions that trigger tracepoint AND execute attached eBPF program
// =============================================================================

/// Trace shell command execution.
/// Triggers the tracepoint and executes any attached eBPF program.
#[inline]
pub fn trace_shell_command(cmd_id: u32, duration_ns: u64) {
    // Trigger the tracepoint macro
    internal::trace_shell_command(cmd_id, duration_ns);

    // Execute attached eBPF program
    let timestamp = AxKops::time_now();
    execute_attached_program("shell:shell_command", timestamp, duration_ns);
}

/// Trace shell initialization.
/// Triggers the tracepoint and executes any attached eBPF program.
#[inline]
pub fn trace_shell_init(duration_ns: u64) {
    // Trigger the tracepoint macro
    internal::trace_shell_init(duration_ns);

    // Execute attached eBPF program
    let timestamp = AxKops::time_now();
    execute_attached_program("shell:shell_init", timestamp, duration_ns);
}
