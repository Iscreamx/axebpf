//! eBPF program attachment management.
//!
//! Maps tracepoints to loaded eBPF programs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Global verbose mode switch for real-time eBPF output
static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);

/// Enable or disable verbose mode
pub fn set_verbose(enabled: bool) {
    VERBOSE_MODE.store(enabled, Ordering::SeqCst);
    log::info!(
        "eBPF verbose mode: {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

/// Check if verbose mode is enabled
pub fn is_verbose() -> bool {
    VERBOSE_MODE.load(Ordering::SeqCst)
}

/// Error types for attachment operations.
#[derive(Debug, Clone)]
pub enum Error {
    /// Tracepoint not found.
    TracepointNotFound(String),
    /// Program not found in registry.
    ProgramNotFound(u32),
    /// Tracepoint already has an attached program.
    AlreadyAttached(String),
    /// Tracepoint has no attached program.
    NotAttached(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TracepointNotFound(name) => write!(f, "Tracepoint not found: {}", name),
            Self::ProgramNotFound(id) => write!(f, "Program not found: {}", id),
            Self::AlreadyAttached(name) => {
                write!(f, "Tracepoint already has attached program: {}", name)
            }
            Self::NotAttached(name) => write!(f, "No program attached to tracepoint: {}", name),
        }
    }
}

impl core::error::Error for Error {}

/// Information about an attached program
#[derive(Debug, Clone)]
pub struct AttachmentInfo {
    /// Program ID from runtime registry
    pub prog_id: u32,
    /// Program name (e.g., "printk", "stats")
    pub prog_name: String,
}

/// Global attachment registry: tracepoint name -> attachment info
static ATTACHMENTS: Mutex<BTreeMap<String, AttachmentInfo>> = Mutex::new(BTreeMap::new());

/// Attach a program to a tracepoint.
///
/// # Arguments
/// * `tracepoint` - Tracepoint name in format "subsystem:event"
/// * `prog_id` - Program ID from runtime::load_program()
/// * `prog_name` - Program name for display purposes
///
/// # Returns
/// Ok(()) on success, Error if tracepoint already has attachment or program not found.
pub fn attach(tracepoint: &str, prog_id: u32, prog_name: &str) -> Result<(), Error> {
    // Verify program exists
    if crate::runtime::get_program(prog_id).is_none() {
        return Err(Error::ProgramNotFound(prog_id));
    }

    let mut attachments = ATTACHMENTS.lock();

    if attachments.contains_key(tracepoint) {
        return Err(Error::AlreadyAttached(tracepoint.to_string()));
    }

    attachments.insert(
        tracepoint.to_string(),
        AttachmentInfo {
            prog_id,
            prog_name: prog_name.to_string(),
        },
    );
    log::debug!(
        "Attached program {} ({}) to {}",
        prog_name,
        prog_id,
        tracepoint
    );
    Ok(())
}

/// Detach a program from a tracepoint.
///
/// # Returns
/// The detached attachment info on success.
pub fn detach(tracepoint: &str) -> Result<AttachmentInfo, Error> {
    let mut attachments = ATTACHMENTS.lock();

    match attachments.remove(tracepoint) {
        Some(info) => {
            log::debug!(
                "Detached program {} ({}) from {}",
                info.prog_name,
                info.prog_id,
                tracepoint
            );
            Ok(info)
        }
        None => Err(Error::NotAttached(tracepoint.to_string())),
    }
}

/// Get the program attached to a tracepoint.
///
/// # Returns
/// Some(AttachmentInfo) if attached, None otherwise.
pub fn get_attached(tracepoint: &str) -> Option<AttachmentInfo> {
    let attachments = ATTACHMENTS.lock();
    attachments.get(tracepoint).cloned()
}

/// List all attachments.
///
/// # Returns
/// Vector of (tracepoint_name, AttachmentInfo) pairs.
pub fn list_attachments() -> Vec<(String, AttachmentInfo)> {
    let attachments = ATTACHMENTS.lock();
    attachments
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Get count of attachments.
pub fn attachment_count() -> usize {
    let attachments = ATTACHMENTS.lock();
    attachments.len()
}
