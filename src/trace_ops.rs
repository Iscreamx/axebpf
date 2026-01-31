//! AxVisor-specific kernel trace operations.
//!
//! Implements the KernelTraceOps trait required by ktracepoint.

use spin::Mutex;
use tracepoint::{KernelTraceOps, TraceCmdLineCache, TracePipeRaw};

/// Size of the trace pipe buffer (number of events).
const TRACE_PIPE_SIZE: usize = 1024;

/// Size of the command line cache (number of entries).
const CMDLINE_CACHE_SIZE: usize = 128;

/// Global trace pipe for raw trace records.
pub static TRACE_PIPE: Mutex<TracePipeRaw> = Mutex::new(TracePipeRaw::new(TRACE_PIPE_SIZE));

/// Global command line cache for process names.
pub static CMDLINE_CACHE: Mutex<TraceCmdLineCache> =
    Mutex::new(TraceCmdLineCache::new(CMDLINE_CACHE_SIZE));

/// AxVisor kernel trace operations implementation.
pub struct AxKops;

impl KernelTraceOps for AxKops {
    fn time_now() -> u64 {
        crate::platform::time_ns()
    }

    fn cpu_id() -> u32 {
        crate::platform::cpu_id()
    }

    fn current_pid() -> u32 {
        // AxVisor doesn't have traditional PIDs; use 0 for hypervisor context
        // In VM context, this could be vm_id << 16 | vcpu_id
        0
    }

    fn trace_pipe_push_raw_record(buf: &[u8]) {
        let mut pipe = TRACE_PIPE.lock();
        pipe.push_event(buf.to_vec());
    }

    fn trace_cmdline_push(pid: u32) {
        let mut cache = CMDLINE_CACHE.lock();
        cache.insert(pid, alloc::string::String::from("axvisor"));
    }

    fn write_kernel_text(addr: *mut core::ffi::c_void, data: &[u8]) {
        // For now, this is a no-op. Implementing code patching requires
        // architecture-specific memory protection manipulation.
        // TODO: Implement for x86_64 and aarch64
        log::debug!(
            "write_kernel_text called at {:p} with {} bytes (not implemented)",
            addr,
            data.len()
        );
    }
}
