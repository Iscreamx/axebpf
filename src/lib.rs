//! AxVisor eBPF Framework
//!
//! This module provides eBPF runtime, symbol table management,
//! and tracepoint infrastructure for AxVisor hypervisor.
//!
//! # Features
//!
//! - `symbols` - Kernel symbol table lookup (default)
//! - `tracepoint-support` - Tracepoint framework (default, requires symbols)
//! - `runtime` - eBPF bytecode execution engine (default)
//!
//! # Quick Start
//!
//! ```ignore
//! use axebpf::tracepoint::TracepointManager;
//!
//! // Initialize the subsystem (call once during boot)
//! axebpf::init();
//!
//! // Get the tracepoint manager
//! let mgr = TracepointManager::global();
//!
//! // List all tracepoints
//! for tp in mgr.list_tracepoints() {
//!     println!("{}: {}", tp.name, if tp.enabled { "on" } else { "off" });
//! }
//!
//! // Enable a tracepoint
//! mgr.enable("vmm:vcpu_run_enter").unwrap();
//! ```

#![no_std]

extern crate alloc;

#[macro_use]
extern crate log;

// =============================================================================
// Platform Abstraction (for testing support)
// =============================================================================

pub mod platform;

// =============================================================================
// Symbols Module
// =============================================================================

#[cfg(feature = "symbols")]
pub mod symbols;

// =============================================================================
// Tracepoint Module
// =============================================================================

#[cfg(feature = "tracepoint-support")]
pub mod trace_ops;

#[cfg(feature = "tracepoint-support")]
pub mod macros;

#[cfg(feature = "tracepoint-support")]
pub mod tracepoint;

#[cfg(feature = "tracepoint-support")]
pub mod examples;

#[cfg(feature = "tracepoint-support")]
pub mod tracepoints;

// =============================================================================
// Runtime Module
// =============================================================================

#[cfg(feature = "runtime")]
pub mod map_ops;

#[cfg(feature = "runtime")]
pub mod maps;

#[cfg(feature = "runtime")]
pub mod helpers;

#[cfg(feature = "runtime")]
pub mod runtime;

#[cfg(feature = "runtime")]
pub mod attach;

#[cfg(feature = "runtime")]
pub mod context;

#[cfg(feature = "runtime")]
pub mod programs;

#[cfg(feature = "runtime")]
pub mod output;

// Re-export key types for convenience
#[cfg(feature = "runtime")]
pub use maps::{Error as MapError, MapDef, MapType, iter_entries};

#[cfg(feature = "runtime")]
pub use runtime::{EbpfProgram, Error as RuntimeError, get_program_map_fds};

#[cfg(feature = "runtime")]
pub use context::TraceContext;

#[cfg(feature = "runtime")]
pub use programs::{PrecompiledProgram, ProgramRegistry};

#[cfg(feature = "runtime")]
pub use attach::{AttachmentInfo, is_verbose, set_verbose};

#[cfg(feature = "runtime")]
pub use output::{print_ebpf_result, print_if_verbose};

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the axebpf subsystem.
///
/// This should be called during kernel boot after the memory allocator is ready.
///
/// # Initialization Order
///
/// 1. Symbols module (if enabled)
/// 2. Tracepoint subsystem (if enabled) - includes static_keys init
/// 3. Runtime module (if enabled)
pub fn init() {
    info!("Initializing axebpf...");

    #[cfg(feature = "symbols")]
    info!("  - symbols module enabled");

    #[cfg(feature = "tracepoint-support")]
    {
        info!("  - tracepoint module enabled");
        tracepoint::init();
        tracepoints::init();
    }

    #[cfg(feature = "runtime")]
    {
        info!("  - runtime module enabled");
        info!("    - maps: Array, HashMap, LRU, Queue");
        info!(
            "    - helpers: {} standard functions",
            helpers::SUPPORTED_HELPERS.len()
        );
        runtime::init();
    }

    info!("axebpf initialization complete");
}
