//! VMM subsystem tracepoint definitions.
//!
//! Defines tracepoints for the hypervisor VMM layer:
//! - System: vmm_init, config_load, image_load
//! - VM Lifecycle: vm_destroy
//! - Timer: timer_tick, timer_event

use crate::trace_ops::AxKops;

// =============================================================================
// System Initialization Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    vmm_init,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(cpu_count: u32, duration_ns: u64),
    TP_STRUCT__entry { cpu_count: u32, duration_ns: u64 },
    TP_fast_assign { cpu_count: cpu_count, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("cpu_count={} duration_ns={}", __entry.cpu_count, __entry.duration_ns))
);

tracepoint::define_event_trace!(
    config_load,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} duration_ns={}", __entry.vm_id, __entry.duration_ns))
);

tracepoint::define_event_trace!(
    image_load,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, image_size: u64, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, image_size: u64, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, image_size: image_size, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} image_size={} duration_ns={}", __entry.vm_id, __entry.image_size, __entry.duration_ns))
);

// =============================================================================
// VM Lifecycle Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    vm_destroy,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32),
    TP_STRUCT__entry { vm_id: u32 },
    TP_fast_assign { vm_id: vm_id },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={}", __entry.vm_id))
);

// =============================================================================
// Timer & Scheduling Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    timer_tick,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(timestamp: u64),
    TP_STRUCT__entry { timestamp: u64 },
    TP_fast_assign { timestamp: timestamp },
    TP_ident(__entry),
    TP_printk(format_args!("timestamp={}", __entry.timestamp))
);

tracepoint::define_event_trace!(
    timer_event,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(event_type: u32, vm_id: u32),
    TP_STRUCT__entry { event_type: u32, vm_id: u32 },
    TP_fast_assign { event_type: event_type, vm_id: vm_id },
    TP_ident(__entry),
    TP_printk(format_args!("event_type={} vm_id={}", __entry.event_type, __entry.vm_id))
);
