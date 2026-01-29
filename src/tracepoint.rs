//! Tracepoint framework for AxVisor.
//!
//! Provides a simplified API for managing tracepoints in AxVisor.
//! Wraps the ktracepoint library with AxVisor-specific conventions.
//!
//! # Example
//!
//! ```ignore
//! use axebpf::tracepoint::TracepointManager;
//!
//! // Initialize the tracepoint subsystem
//! axebpf::tracepoint::init();
//!
//! // Get the global manager
//! let mgr = TracepointManager::global();
//!
//! // List all tracepoints
//! for tp in mgr.list_tracepoints() {
//!     log::info!("{}: {}", tp.name, if tp.enabled { "on" } else { "off" });
//! }
//!
//! // Enable a tracepoint
//! mgr.enable("vmm:vcpu_run_enter").unwrap();
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;
use tracepoint::{TracingEventsManager, global_init_events};

use crate::kops::AxKops;

// Re-export KernelTraceOps for use in kernel code
pub use tracepoint::KernelTraceOps;

/// Lock type used for tracepoint synchronization.
type Lock = spin::Mutex<()>;

/// The global tracepoint manager instance.
static MANAGER: Mutex<Option<TracingEventsManager<Lock, AxKops>>> = Mutex::new(None);

/// Whether the tracepoint subsystem has been initialized.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Error types for tracepoint operations.
#[derive(Debug, Clone)]
pub enum Error {
    /// Tracepoint subsystem not initialized.
    NotInitialized,
    /// Tracepoint not found.
    NotFound(String),
    /// Invalid tracepoint name format.
    InvalidName(String),
    /// Already initialized.
    AlreadyInitialized,
    /// Initialization failed.
    InitFailed(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "Tracepoint subsystem not initialized"),
            Self::NotFound(name) => write!(f, "Tracepoint not found: {}", name),
            Self::InvalidName(name) => write!(f, "Invalid tracepoint name format: {}", name),
            Self::AlreadyInitialized => write!(f, "Tracepoint subsystem already initialized"),
            Self::InitFailed(msg) => write!(f, "Tracepoint initialization failed: {}", msg),
        }
    }
}

impl core::error::Error for Error {}

/// Information about a single tracepoint.
#[derive(Debug, Clone)]
pub struct TracepointInfo {
    /// Full name in format "subsystem:event"
    pub name: String,
    /// Subsystem name
    pub subsystem: String,
    /// Event name
    pub event: String,
    /// Whether the tracepoint is currently enabled
    pub enabled: bool,
    /// Tracepoint ID
    pub id: u32,
}

/// Global tracepoint manager.
///
/// Provides a simplified interface to manage tracepoints in AxVisor.
pub struct TracepointManager;

impl TracepointManager {
    /// Get the global TracepointManager instance.
    ///
    /// Returns a reference to the singleton manager.
    /// Panics if the tracepoint subsystem has not been initialized.
    pub fn global() -> Self {
        if !INITIALIZED.load(Ordering::SeqCst) {
            panic!("TracepointManager::global() called before init()");
        }
        Self
    }

    /// Try to get the global TracepointManager instance.
    ///
    /// Returns None if the tracepoint subsystem has not been initialized.
    pub fn try_global() -> Option<Self> {
        if INITIALIZED.load(Ordering::SeqCst) {
            Some(Self)
        } else {
            None
        }
    }

    /// List all registered tracepoints.
    pub fn list_tracepoints(&self) -> Vec<TracepointInfo> {
        let mut result = Vec::new();

        let guard = MANAGER.lock();
        let manager = match guard.as_ref() {
            Some(m) => m,
            None => return result,
        };

        for subsys_name in manager.subsystem_names() {
            if let Some(subsys) = manager.get_subsystem(&subsys_name) {
                for event_name in subsys.event_names() {
                    if let Some(event_info) = subsys.get_event(&event_name) {
                        let tp = event_info.tracepoint();
                        result.push(TracepointInfo {
                            name: alloc::format!("{}:{}", subsys_name, event_name),
                            subsystem: subsys_name.clone(),
                            event: event_name.clone(),
                            enabled: tp.default_is_enabled(),
                            id: tp.id(),
                        });
                    }
                }
            }
        }

        result
    }

    /// Get information about a specific tracepoint.
    ///
    /// # Arguments
    /// * `name` - Tracepoint name in format "subsystem:event"
    pub fn get(&self, name: &str) -> Result<TracepointInfo, Error> {
        let (subsys_name, event_name) = parse_tracepoint_name(name)?;

        let guard = MANAGER.lock();
        let manager = guard.as_ref().ok_or(Error::NotInitialized)?;

        let subsys = manager
            .get_subsystem(subsys_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        let event_info = subsys
            .get_event(event_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        let tp = event_info.tracepoint();
        Ok(TracepointInfo {
            name: name.into(),
            subsystem: subsys_name.into(),
            event: event_name.into(),
            enabled: tp.default_is_enabled(),
            id: tp.id(),
        })
    }

    /// Enable a tracepoint.
    ///
    /// # Arguments
    /// * `name` - Tracepoint name in format "subsystem:event"
    pub fn enable(&self, name: &str) -> Result<(), Error> {
        let (subsys_name, event_name) = parse_tracepoint_name(name)?;

        let guard = MANAGER.lock();
        let manager = guard.as_ref().ok_or(Error::NotInitialized)?;

        let subsys = manager
            .get_subsystem(subsys_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        let event_info = subsys
            .get_event(event_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        event_info.enable_file().write('1');
        log::debug!("Enabled tracepoint: {}", name);
        Ok(())
    }

    /// Disable a tracepoint.
    ///
    /// # Arguments
    /// * `name` - Tracepoint name in format "subsystem:event"
    pub fn disable(&self, name: &str) -> Result<(), Error> {
        let (subsys_name, event_name) = parse_tracepoint_name(name)?;

        let guard = MANAGER.lock();
        let manager = guard.as_ref().ok_or(Error::NotInitialized)?;

        let subsys = manager
            .get_subsystem(subsys_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        let event_info = subsys
            .get_event(event_name)
            .ok_or_else(|| Error::NotFound(name.into()))?;

        event_info.enable_file().write('0');
        log::debug!("Disabled tracepoint: {}", name);
        Ok(())
    }

    /// Check if a tracepoint is enabled.
    ///
    /// # Arguments
    /// * `name` - Tracepoint name in format "subsystem:event"
    pub fn is_enabled(&self, name: &str) -> bool {
        self.get(name).map(|info| info.enabled).unwrap_or(false)
    }

    /// Get the number of registered tracepoints.
    pub fn count(&self) -> usize {
        self.list_tracepoints().len()
    }

    /// Enable all tracepoints in a subsystem.
    ///
    /// # Arguments
    /// * `subsystem` - Subsystem name (e.g., "vmm")
    pub fn enable_subsystem(&self, subsystem: &str) -> Result<usize, Error> {
        let guard = MANAGER.lock();
        let manager = guard.as_ref().ok_or(Error::NotInitialized)?;

        let subsys = manager
            .get_subsystem(subsystem)
            .ok_or_else(|| Error::NotFound(subsystem.into()))?;

        let mut count = 0;
        for event_name in subsys.event_names() {
            if let Some(event_info) = subsys.get_event(&event_name) {
                event_info.enable_file().write('1');
                count += 1;
            }
        }

        log::debug!("Enabled {} tracepoints in subsystem: {}", count, subsystem);
        Ok(count)
    }

    /// Disable all tracepoints in a subsystem.
    ///
    /// # Arguments
    /// * `subsystem` - Subsystem name (e.g., "vmm")
    pub fn disable_subsystem(&self, subsystem: &str) -> Result<usize, Error> {
        let guard = MANAGER.lock();
        let manager = guard.as_ref().ok_or(Error::NotInitialized)?;

        let subsys = manager
            .get_subsystem(subsystem)
            .ok_or_else(|| Error::NotFound(subsystem.into()))?;

        let mut count = 0;
        for event_name in subsys.event_names() {
            if let Some(event_info) = subsys.get_event(&event_name) {
                event_info.enable_file().write('0');
                count += 1;
            }
        }

        log::debug!("Disabled {} tracepoints in subsystem: {}", count, subsystem);
        Ok(count)
    }
}

/// Parse a tracepoint name in format "subsystem:event".
fn parse_tracepoint_name(name: &str) -> Result<(&str, &str), Error> {
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidName(name.into()));
    }
    Ok((parts[0], parts[1]))
}

/// Initialize the tracepoint subsystem.
///
/// This must be called once during kernel boot after:
/// 1. Memory allocator is ready
/// 2. static_keys::global_init() has been called
///
/// # Panics
/// Panics if called more than once.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        log::warn!("Tracepoint subsystem already initialized");
        return;
    }

    log::info!("Initializing tracepoint subsystem...");

    // Initialize static keys first
    static_keys::global_init();

    // Initialize the tracing events manager
    match global_init_events::<Lock, AxKops>() {
        Ok(manager) => {
            let count = {
                let map = manager.tracepoint_map();
                map.len()
            };

            *MANAGER.lock() = Some(manager);
            log::info!(
                "Tracepoint subsystem initialized with {} tracepoints",
                count
            );
        }
        Err(e) => {
            INITIALIZED.store(false, Ordering::SeqCst);
            log::error!("Failed to initialize tracepoint subsystem: {}", e);
        }
    }
}

/// Check if the tracepoint subsystem has been initialized.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}
