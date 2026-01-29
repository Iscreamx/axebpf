//! VMM subsystem tracepoint definitions.
//!
//! Defines tracepoints for the hypervisor VMM layer:
//! - VM Lifecycle: vm_create, vm_boot, vm_shutdown, vm_destroy
//! - vCPU Lifecycle: vcpu_create, vcpu_destroy, vcpu_state_change
//! - vCPU Runtime: vcpu_run_enter, vcpu_run_exit, hypercall, external_interrupt, vcpu_halt, cpu_up, ipi_send
//! - Memory: memory_map, memory_unmap, page_fault
//! - Device/IRQ: device_access, irq_inject, irq_handle
//! - System: vmm_init, vhal_init, config_load, image_load
//! - Timer: timer_tick, timer_event, task_switch

use crate::trace_ops::AxKops;

// =============================================================================
// VM Lifecycle Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    vm_create,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_num: u32, memory_size: u64),
    TP_STRUCT__entry { vm_id: u32, vcpu_num: u32, memory_size: u64 },
    TP_fast_assign { vm_id: vm_id, vcpu_num: vcpu_num, memory_size: memory_size },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpus={} memory={}MB", __entry.vm_id, __entry.vcpu_num, __entry.memory_size / 1024 / 1024))
);

tracepoint::define_event_trace!(
    vm_boot,
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
    vm_shutdown,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, reason: u32, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, reason: u32, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, reason: reason, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} reason={} duration_ns={}", __entry.vm_id, __entry.reason, __entry.duration_ns))
);

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
// vCPU Lifecycle Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    vcpu_create,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={}", __entry.vm_id, __entry.vcpu_id))
);

tracepoint::define_event_trace!(
    vcpu_destroy,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={}", __entry.vm_id, __entry.vcpu_id))
);

tracepoint::define_event_trace!(
    vcpu_state_change,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, old_state: u32, new_state: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, old_state: u32, new_state: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, old_state: old_state, new_state: new_state },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={} old={} new={}", __entry.vm_id, __entry.vcpu_id, __entry.old_state, __entry.new_state))
);

// =============================================================================
// vCPU Runtime Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    vcpu_run_enter,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={}", __entry.vm_id, __entry.vcpu_id))
);

tracepoint::define_event_trace!(
    vcpu_run_exit,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, exit_reason: u32, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, exit_reason: u32, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, exit_reason: exit_reason, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} vcpu_id={} exit_reason={} duration_ns={}",
        __entry.vm_id, __entry.vcpu_id, __entry.exit_reason, __entry.duration_ns
    ))
);

tracepoint::define_event_trace!(
    hypercall,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, nr: u64, ret_val: i64, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, nr: u64, ret_val: i64, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, nr: nr, ret_val: ret_val, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} vcpu_id={} nr={:#x} ret_val={} duration_ns={}",
        __entry.vm_id, __entry.vcpu_id, __entry.nr, __entry.ret_val, __entry.duration_ns
    ))
);

tracepoint::define_event_trace!(
    external_interrupt,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, vector: u64),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, vector: u64 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, vector: vector },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} vcpu_id={} vector={}",
        __entry.vm_id, __entry.vcpu_id, __entry.vector
    ))
);

tracepoint::define_event_trace!(
    vcpu_halt,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={}", __entry.vm_id, __entry.vcpu_id))
);

tracepoint::define_event_trace!(
    cpu_up,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, source_vcpu: u32, target_vcpu: u32, entry_point: u64),
    TP_STRUCT__entry { vm_id: u32, source_vcpu: u32, target_vcpu: u32, entry_point: u64 },
    TP_fast_assign { vm_id: vm_id, source_vcpu: source_vcpu, target_vcpu: target_vcpu, entry_point: entry_point },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} source_vcpu={} target_vcpu={} entry_point={:#x}",
        __entry.vm_id, __entry.source_vcpu, __entry.target_vcpu, __entry.entry_point
    ))
);

tracepoint::define_event_trace!(
    ipi_send,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, target_cpu: u64, vector: u64),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, target_cpu: u64, vector: u64 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, target_cpu: target_cpu, vector: vector },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} vcpu_id={} target_cpu={} vector={}",
        __entry.vm_id, __entry.vcpu_id, __entry.target_cpu, __entry.vector
    ))
);

// =============================================================================
// Memory Management Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    memory_map,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, gpa: u64, hpa: u64, size: u64, flags: u32),
    TP_STRUCT__entry { vm_id: u32, gpa: u64, hpa: u64, size: u64, flags: u32 },
    TP_fast_assign { vm_id: vm_id, gpa: gpa, hpa: hpa, size: size, flags: flags },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} gpa={:#x} hpa={:#x} size={:#x} flags={:#x}",
        __entry.vm_id, __entry.gpa, __entry.hpa, __entry.size, __entry.flags
    ))
);

tracepoint::define_event_trace!(
    memory_unmap,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, gpa: u64, size: u64),
    TP_STRUCT__entry { vm_id: u32, gpa: u64, size: u64 },
    TP_fast_assign { vm_id: vm_id, gpa: gpa, size: size },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} gpa={:#x} size={:#x}", __entry.vm_id, __entry.gpa, __entry.size))
);

tracepoint::define_event_trace!(
    page_fault,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, gpa: u64, access_type: u32, duration_ns: u64),
    TP_STRUCT__entry { vm_id: u32, gpa: u64, access_type: u32, duration_ns: u64 },
    TP_fast_assign { vm_id: vm_id, gpa: gpa, access_type: access_type, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} gpa={:#x} access_type={} duration_ns={}",
        __entry.vm_id, __entry.gpa, __entry.access_type, __entry.duration_ns
    ))
);

// =============================================================================
// Device & IRQ Tracepoints
// =============================================================================

tracepoint::define_event_trace!(
    device_access,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, device_id: u32, addr: u64, is_write: u32),
    TP_STRUCT__entry { vm_id: u32, device_id: u32, addr: u64, is_write: u32 },
    TP_fast_assign { vm_id: vm_id, device_id: device_id, addr: addr, is_write: is_write },
    TP_ident(__entry),
    TP_printk(format_args!(
        "vm_id={} device_id={} addr={:#x} is_write={}",
        __entry.vm_id, __entry.device_id, __entry.addr, __entry.is_write
    ))
);

tracepoint::define_event_trace!(
    irq_inject,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(vm_id: u32, vcpu_id: u32, irq_num: u32),
    TP_STRUCT__entry { vm_id: u32, vcpu_id: u32, irq_num: u32 },
    TP_fast_assign { vm_id: vm_id, vcpu_id: vcpu_id, irq_num: irq_num },
    TP_ident(__entry),
    TP_printk(format_args!("vm_id={} vcpu_id={} irq_num={}", __entry.vm_id, __entry.vcpu_id, __entry.irq_num))
);

tracepoint::define_event_trace!(
    irq_handle,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(irq_num: u32, duration_ns: u64),
    TP_STRUCT__entry { irq_num: u32, duration_ns: u64 },
    TP_fast_assign { irq_num: irq_num, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("irq_num={} duration_ns={}", __entry.irq_num, __entry.duration_ns))
);

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
    vhal_init,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(cpu_id: u32, duration_ns: u64),
    TP_STRUCT__entry { cpu_id: u32, duration_ns: u64 },
    TP_fast_assign { cpu_id: cpu_id, duration_ns: duration_ns },
    TP_ident(__entry),
    TP_printk(format_args!("cpu_id={} duration_ns={}", __entry.cpu_id, __entry.duration_ns))
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

tracepoint::define_event_trace!(
    task_switch,
    TP_lock(spin::Mutex<()>),
    TP_kops(AxKops),
    TP_system(vmm),
    TP_PROTO(from_task: u64, to_task: u64),
    TP_STRUCT__entry { from_task: u64, to_task: u64 },
    TP_fast_assign { from_task: from_task, to_task: to_task },
    TP_ident(__entry),
    TP_printk(format_args!("from_task={:#x} to_task={:#x}", __entry.from_task, __entry.to_task))
);
