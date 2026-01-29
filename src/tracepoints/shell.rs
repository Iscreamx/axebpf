//! Shell subsystem tracepoint definitions.
//!
//! Defines tracepoints for the AxVisor shell:
//! - shell_init: Shell initialization
//! - shell_command: Shell command execution

use crate::kops::AxKops;

// =============================================================================
// Shell Tracepoints
// =============================================================================

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
