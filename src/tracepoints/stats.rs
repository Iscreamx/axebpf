//! Tracepoint execution support.
//!
//! Statistics collection is now handled by eBPF programs (stats program).
//! This module provides the eBPF program execution infrastructure.

use crate::context::TraceContext;
use crate::{attach, output, runtime};

use super::registry;

/// Execute eBPF program attached to a tracepoint.
///
/// Called by tracepoint trigger functions to run attached eBPF programs.
pub fn execute_attached_program(tracepoint_name: &str, timestamp: u64, duration_ns: u64) {
    log::debug!("execute_attached_program called for '{}'", tracepoint_name);

    // Check if there is an attached program
    if let Some(info) = attach::get_attached(tracepoint_name) {
        log::info!("Found attached program '{}' (id={}) for '{}'", info.prog_name, info.prog_id, tracepoint_name);
        // Get tracepoint ID from registry
        let tp_id = registry::get_id(tracepoint_name).unwrap_or(0);

        // Build context
        let mut ctx = TraceContext {
            tracepoint_id: tp_id,
            timestamp_ns: timestamp,
            vm_id: 0,
            vcpu_id: 0,
            arg0: duration_ns,
            arg1: 0,
            arg2: 0,
            arg3: 0,
        };

        // Execute program
        if let Err(e) = runtime::run_program(info.prog_id, Some(ctx.as_bytes_mut())) {
            log::warn!(
                "eBPF program execution failed for '{}': {:?}",
                tracepoint_name,
                e
            );
            return;
        }

        // Print verbose output if enabled
        if let Some(map_fds) = runtime::get_program_map_fds(info.prog_id) {
            for (map_name, map_fd) in map_fds {
                if map_name.contains("COUNTER") || map_name.contains("MAP") {
                    output::print_if_verbose(&info.prog_name, tracepoint_name, tp_id, map_fd);
                    break;
                }
            }
        }
    }
}

/// Record a hit for a tracepoint (executes attached eBPF program).
pub fn record_hit(name: &str, timestamp: u64) {
    execute_attached_program(name, timestamp, 0);
}

/// Record a duration for a tracepoint (executes attached eBPF program).
pub fn record_duration(name: &str, timestamp: u64, duration_ns: u64) {
    execute_attached_program(name, timestamp, duration_ns);
}
