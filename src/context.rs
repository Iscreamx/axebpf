//! Trace context passed to eBPF programs.

use crate::platform;

/// Tracepoint context passed to eBPF programs.
///
/// Constructed when a tracepoint fires and passed as input data to eBPF programs.
/// Must match the definition in eBPF programs (C ABI).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceContext {
    /// Tracepoint unique identifier
    pub tracepoint_id: u32,
    /// Trigger timestamp (nanoseconds)
    pub timestamp_ns: u64,
    /// VM ID (0 means not associated)
    pub vm_id: u32,
    /// vCPU ID (0 means not associated)
    pub vcpu_id: u32,
    /// Tracepoint argument 0
    pub arg0: u64,
    /// Tracepoint argument 1
    pub arg1: u64,
    /// Tracepoint argument 2
    pub arg2: u64,
    /// Tracepoint argument 3
    pub arg3: u64,
    /// Probe type (0=hprobe, 1=hretprobe, 2=kprobe, 3=kretprobe, 4=tracepoint)
    pub probe_type: u32,
    /// Reserved for alignment
    pub _reserved: u32,
}

impl TraceContext {
    /// Create a new trace context.
    pub fn new(tracepoint_id: u32) -> Self {
        Self {
            tracepoint_id,
            timestamp_ns: platform::time_ns(),
            ..Default::default()
        }
    }

    /// Set VM information.
    pub fn with_vm(mut self, vm_id: u32, vcpu_id: u32) -> Self {
        self.vm_id = vm_id;
        self.vcpu_id = vcpu_id;
        self
    }

    /// Set arguments.
    pub fn with_args(mut self, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Self {
        self.arg0 = arg0;
        self.arg1 = arg1;
        self.arg2 = arg2;
        self.arg3 = arg3;
        self
    }

    /// Set probe type
    pub fn with_probe_type(mut self, probe_type: u32) -> Self {
        self.probe_type = probe_type;
        self
    }

    /// Convert to byte slice (for passing to eBPF VM).
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Convert to mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
