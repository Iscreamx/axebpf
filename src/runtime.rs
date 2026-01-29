//! eBPF bytecode execution engine.
//!
//! Provides VM for running eBPF programs with registered helpers.

use alloc::vec::Vec;
use spin::Mutex;

use crate::helpers;

/// Error types for eBPF runtime operations.
#[derive(Debug)]
pub enum Error {
    /// The eBPF program is invalid or malformed.
    InvalidProgram,
    /// Program execution failed.
    ExecutionFailed,
    /// Verification of the program failed.
    VerificationFailed,
    /// Program not found in registry.
    NotFound,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProgram => write!(f, "Invalid eBPF program"),
            Self::ExecutionFailed => write!(f, "eBPF execution failed"),
            Self::VerificationFailed => write!(f, "eBPF verification failed"),
            Self::NotFound => write!(f, "Program not found"),
        }
    }
}

impl core::error::Error for Error {}

// =============================================================================
// EbpfProgram
// =============================================================================

/// eBPF program wrapper with helper support.
///
/// Stores bytecode and provides execution methods with automatic helper registration.
#[derive(Clone)]
pub struct EbpfProgram {
    bytecode: Vec<u8>,
}

impl EbpfProgram {
    /// Load eBPF bytecode into a program.
    ///
    /// # Arguments
    /// * `bytecode` - Raw eBPF bytecode.
    ///
    /// # Returns
    /// EbpfProgram on success, Error if bytecode is invalid.
    pub fn new(bytecode: &[u8]) -> Result<Self, Error> {
        if bytecode.is_empty() || !bytecode.len().is_multiple_of(8) {
            return Err(Error::InvalidProgram);
        }
        Ok(Self {
            bytecode: bytecode.to_vec(),
        })
    }

    /// Get the bytecode.
    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    /// Execute the program without input data.
    ///
    /// # Returns
    /// The return value of the eBPF program (r0 register).
    pub fn execute(&self) -> Result<u64, Error> {
        use rbpf::EbpfVmNoData;

        let mut vm = EbpfVmNoData::new(Some(&self.bytecode)).map_err(|_| Error::InvalidProgram)?;

        helpers::register_all_nodata(&mut vm);

        vm.execute_program().map_err(|_| Error::ExecutionFailed)
    }

    /// Execute the program with memory context.
    ///
    /// # Arguments
    /// * `ctx` - Memory buffer accessible to the program (e.g., tracepoint data).
    ///
    /// # Returns
    /// The return value of the eBPF program (r0 register).
    pub fn execute_with_context(&self, ctx: &mut [u8]) -> Result<u64, Error> {
        use rbpf::EbpfVmRaw;

        let mut vm = EbpfVmRaw::new(Some(&self.bytecode)).map_err(|_| Error::InvalidProgram)?;

        helpers::register_all_raw(&mut vm);

        vm.execute_program(ctx).map_err(|_| Error::ExecutionFailed)
    }
}

// =============================================================================
// Program Registry
// =============================================================================

/// Global program registry.
static PROGRAM_REGISTRY: Mutex<Vec<Option<EbpfProgram>>> = Mutex::new(Vec::new());

/// Load a program into the registry.
///
/// # Arguments
/// * `bytecode` - Raw eBPF bytecode.
///
/// # Returns
/// Program ID on success.
pub fn load_program(bytecode: &[u8]) -> Result<u32, Error> {
    let program = EbpfProgram::new(bytecode)?;
    let mut registry = PROGRAM_REGISTRY.lock();

    // Find empty slot or append
    for (i, slot) in registry.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(program);
            log::debug!("Loaded program {} ({} bytes)", i, bytecode.len());
            return Ok(i as u32);
        }
    }

    let id = registry.len() as u32;
    registry.push(Some(program));
    log::debug!("Loaded program {} ({} bytes)", id, bytecode.len());
    Ok(id)
}

/// Get a loaded program by ID.
pub fn get_program(prog_id: u32) -> Option<EbpfProgram> {
    let registry = PROGRAM_REGISTRY.lock();
    registry.get(prog_id as usize)?.clone()
}

/// Unload a program from the registry.
pub fn unload_program(prog_id: u32) -> Result<(), Error> {
    let mut registry = PROGRAM_REGISTRY.lock();
    let slot = registry.get_mut(prog_id as usize).ok_or(Error::NotFound)?;
    if slot.is_none() {
        return Err(Error::NotFound);
    }
    *slot = None;
    log::debug!("Unloaded program {}", prog_id);
    Ok(())
}

/// Run a loaded program by ID.
///
/// # Arguments
/// * `prog_id` - Program ID returned by load_program().
/// * `ctx` - Optional memory context for the program.
///
/// # Returns
/// The return value of the eBPF program.
pub fn run_program(prog_id: u32, ctx: Option<&mut [u8]>) -> Result<u64, Error> {
    let program = get_program(prog_id).ok_or(Error::NotFound)?;

    match ctx {
        Some(mem) => program.execute_with_context(mem),
        None => program.execute(),
    }
}

/// Get the number of loaded programs.
pub fn program_count() -> usize {
    let registry = PROGRAM_REGISTRY.lock();
    registry.iter().filter(|p| p.is_some()).count()
}

/// Information about a loaded program.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// Program ID.
    pub id: u32,
    /// Bytecode size in bytes.
    pub size: usize,
}

/// List all loaded programs.
///
/// # Returns
/// Vector of ProgramInfo for all loaded programs.
pub fn list_programs() -> Vec<ProgramInfo> {
    let registry = PROGRAM_REGISTRY.lock();
    registry
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| {
            slot.as_ref().map(|prog| ProgramInfo {
                id: i as u32,
                size: prog.bytecode().len(),
            })
        })
        .collect()
}

// =============================================================================
// Legacy API (backward compatible)
// =============================================================================

/// Execute an eBPF program without input data.
///
/// # Arguments
/// * `prog` - The eBPF bytecode
///
/// # Returns
/// The return value of the eBPF program (r0 register).
pub fn execute(prog: &[u8]) -> Result<u64, Error> {
    let program = EbpfProgram::new(prog)?;
    program.execute()
}

/// Execute an eBPF program with memory context.
///
/// # Arguments
/// * `prog` - The eBPF bytecode
/// * `mem` - Memory buffer accessible to the program
///
/// # Returns
/// The return value of the eBPF program (r0 register).
pub fn execute_with_mem(prog: &[u8], mem: &mut [u8]) -> Result<u64, Error> {
    let program = EbpfProgram::new(prog)?;
    program.execute_with_context(mem)
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the eBPF runtime.
pub fn init() {
    log::info!("Initializing eBPF runtime...");
    log::info!("  - {} helpers available", helpers::SUPPORTED_HELPERS.len());
}
