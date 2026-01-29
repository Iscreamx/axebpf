//! eBPF program attachment management.
//!
//! Maps tracepoints to loaded eBPF programs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

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

/// Global attachment registry: tracepoint name -> program ID
static ATTACHMENTS: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

/// Attach a program to a tracepoint.
///
/// # Arguments
/// * `tracepoint` - Tracepoint name in format "subsystem:event"
/// * `prog_id` - Program ID from runtime::load_program()
///
/// # Returns
/// Ok(()) on success, Error if tracepoint already has attachment or program not found.
pub fn attach(tracepoint: &str, prog_id: u32) -> Result<(), Error> {
    // Verify program exists
    if crate::runtime::get_program(prog_id).is_none() {
        return Err(Error::ProgramNotFound(prog_id));
    }

    let mut attachments = ATTACHMENTS.lock();

    if attachments.contains_key(tracepoint) {
        return Err(Error::AlreadyAttached(tracepoint.to_string()));
    }

    attachments.insert(tracepoint.to_string(), prog_id);
    log::debug!("Attached program {} to {}", prog_id, tracepoint);
    Ok(())
}

/// Detach a program from a tracepoint.
///
/// # Arguments
/// * `tracepoint` - Tracepoint name in format "subsystem:event"
///
/// # Returns
/// The detached program ID on success.
pub fn detach(tracepoint: &str) -> Result<u32, Error> {
    let mut attachments = ATTACHMENTS.lock();

    match attachments.remove(tracepoint) {
        Some(prog_id) => {
            log::debug!("Detached program {} from {}", prog_id, tracepoint);
            Ok(prog_id)
        }
        None => Err(Error::NotAttached(tracepoint.to_string())),
    }
}

/// Get the program attached to a tracepoint.
///
/// # Arguments
/// * `tracepoint` - Tracepoint name in format "subsystem:event"
///
/// # Returns
/// Some(prog_id) if attached, None otherwise.
pub fn get_attached(tracepoint: &str) -> Option<u32> {
    let attachments = ATTACHMENTS.lock();
    attachments.get(tracepoint).copied()
}

/// List all attachments.
///
/// # Returns
/// Vector of (tracepoint_name, program_id) pairs.
pub fn list_attachments() -> Vec<(String, u32)> {
    let attachments = ATTACHMENTS.lock();
    attachments.iter().map(|(k, v)| (k.clone(), *v)).collect()
}

/// Get count of attachments.
pub fn attachment_count() -> usize {
    let attachments = ATTACHMENTS.lock();
    attachments.len()
}
