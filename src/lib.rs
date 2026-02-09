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
pub mod cache;

#[cfg(feature = "tracepoint-support")]
pub mod insn_slot;

#[cfg(feature = "tracepoint-support")]
pub mod page_table;

#[cfg(feature = "hprobe")]
pub mod probe;

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

#[cfg(feature = "hprobe")]
pub use kprobe::PtRegs;

#[cfg(feature = "hprobe")]
pub use probe::hprobe::manager as hprobe_manager;
#[cfg(feature = "hprobe")]
pub use probe::hprobe::handler as hprobe_handler;
#[cfg(feature = "hprobe")]
pub use probe::hprobe::ops as hprobe_ops;

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the axebpf subsystem.
///
/// This should be called during kernel boot after the memory allocator is ready.
/// Note: This does NOT initialize the symbol table. Use `init_with_symbols()` for kprobe support.
///
/// # Initialization Order
///
/// 1. Symbols module (if enabled)
/// 2. Tracepoint subsystem (if enabled) - includes static_keys init
/// 3. Runtime module (if enabled)
pub fn init() {
    info!("Initializing axebpf...");

    #[cfg(feature = "symbols")]
    info!("  - symbols module enabled (call init_with_symbols for kprobe)");

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

/// Initialize the axebpf subsystem with symbol table support.
///
/// This should be called during kernel boot after the memory allocator is ready.
/// This version loads the kernel symbol table, which is required for kprobe support.
///
/// # Arguments
/// * `kallsyms_data` - The kallsyms.bin binary blob (static lifetime required)
/// * `stext` - Start address of kernel text section (_stext)
/// * `etext` - End address of kernel text section (_etext)
///
/// # Example
/// ```ignore
/// extern "C" {
///     static _stext: u8;
///     static _etext: u8;
/// }
/// let stext = unsafe { &_stext as *const u8 as u64 };
/// let etext = unsafe { &_etext as *const u8 as u64 };
/// axebpf::init_with_symbols(include_bytes!("../../kallsyms.bin"), stext, etext);
/// ```
#[cfg(feature = "symbols")]
pub fn init_with_symbols(kallsyms_data: &'static [u8], stext: u64, etext: u64) {
    info!("Initializing axebpf with symbol table...");

    // Initialize symbol table first
    info!("  - symbols module enabled");
    info!("    - kallsyms data at {:p}, len={}", kallsyms_data.as_ptr(), kallsyms_data.len());

    // The ksym library expects the blob to be page-aligned in memory.
    // Check alignment and warn if not aligned.
    let ptr = kallsyms_data.as_ptr() as usize;
    if ptr % 4096 != 0 {
        warn!("    - kallsyms data is not page-aligned (ptr % 4096 = {})", ptr % 4096);
        warn!("    - this may cause parsing issues with ksym library");
    }

    match symbols::init(kallsyms_data, stext, etext) {
        Ok(()) => {
            info!("    - symbol table loaded ({} bytes)", kallsyms_data.len());
            info!("    - text range: {:#x} - {:#x}", stext, etext);
        }
        Err(e) => {
            error!("    - failed to load symbol table: {}", e);
        }
    }

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
