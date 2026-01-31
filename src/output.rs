//! eBPF execution output formatting.
//!
//! Provides structured output for eBPF program execution results.

use crate::platform;

/// Print structured eBPF execution result.
///
/// Output format: [eBPF] prog=NAME tp=TRACEPOINT count=VALUE ts_ns=TIMESTAMP
///
/// # Arguments
/// * `prog_name` - Name of the eBPF program
/// * `tp_name` - Tracepoint name in format "subsystem:event"
/// * `key` - Map key bytes (interpreted as u32)
/// * `value` - Map value bytes (interpreted as u64)
pub fn print_ebpf_result(prog_name: &str, tp_name: &str, key: &[u8], value: &[u8]) {
    let _key_val = if key.len() >= 4 {
        u32::from_le_bytes(key[..4].try_into().unwrap_or([0; 4]))
    } else {
        0
    };

    let value_val = if value.len() >= 8 {
        u64::from_le_bytes(value[..8].try_into().unwrap_or([0; 8]))
    } else if value.len() >= 4 {
        u32::from_le_bytes(value[..4].try_into().unwrap_or([0; 4])) as u64
    } else {
        0
    };

    let ts_ns = platform::time_ns();

    log::info!(
        "[eBPF] prog={} tp={} count={} ts_ns={}",
        prog_name,
        tp_name,
        value_val,
        ts_ns
    );
}

/// Print eBPF result for a specific tracepoint after execution.
///
/// Reads the Map entry for the given tracepoint ID and prints if verbose mode is enabled.
///
/// # Arguments
/// * `prog_name` - Name of the eBPF program
/// * `tp_name` - Tracepoint name
/// * `tp_id` - Tracepoint numeric ID (used as Map key)
/// * `map_fd` - Map FD to read from
pub fn print_if_verbose(prog_name: &str, tp_name: &str, tp_id: u32, map_fd: u32) {
    if !crate::attach::is_verbose() {
        return;
    }

    let key = tp_id.to_le_bytes();
    if let Some(value) = crate::maps::lookup_elem(map_fd, &key) {
        print_ebpf_result(prog_name, tp_name, &key, &value);
    }
}
