//! eBPF bytecode execution engine.
//!
//! Provides VM for running eBPF programs with registered helpers.

use alloc::string::String;
use alloc::sync::Arc;
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
    /// ELF parsing failed.
    ElfParseError,
    /// Map creation failed.
    MapCreationFailed,
    /// Relocation failed.
    RelocationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProgram => write!(f, "Invalid eBPF program"),
            Self::ExecutionFailed => write!(f, "eBPF execution failed"),
            Self::VerificationFailed => write!(f, "eBPF verification failed"),
            Self::NotFound => write!(f, "Program not found"),
            Self::ElfParseError => write!(f, "ELF parse error"),
            Self::MapCreationFailed => write!(f, "Map creation failed"),
            Self::RelocationFailed => write!(f, "Relocation failed"),
        }
    }
}

impl core::error::Error for Error {}

/// Result of parsing ELF with Maps.
#[derive(Debug)]
struct ElfParseResult {
    /// Extracted bytecode (already patched if Maps present)
    bytecode: Vec<u8>,
    /// Created Map FDs: (symbol_name, map_fd)
    map_fds: Vec<(String, u32)>,
}

// =============================================================================
// ELF Parsing (aya-obj based)
// =============================================================================

/// ELF magic number
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Check if data is an ELF file
fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == ELF_MAGIC
}

/// Parse ELF file using aya-obj with full relocation support.
///
/// Handles:
/// - `.text` section merging (memcpy/memmove/memset)
/// - `R_BPF_64_64` map fd relocations
/// - `R_BPF_64_32` function call relocations (BPF-to-BPF)
/// - BTF-defined and legacy map sections
fn parse_elf_with_aya(
    elf_data: &[u8],
    prog_name: Option<&str>,
) -> Result<ElfParseResult, Error> {
    use aya_obj::Object;
    use hashbrown::HashSet;

    log::debug!(
        "Parsing ELF with aya-obj, size={} bytes, prog_name={:?}",
        elf_data.len(),
        prog_name
    );

    // Phase 1: Parse ELF
    //
    // The `object` crate's ELF parser requires the input buffer to be aligned
    // to `align_of::<FileHeader64>()` (8 bytes on aarch64). Data from
    // `include_bytes!()` is placed in .rodata with no alignment guarantee,
    // so we must copy to an aligned buffer when the pointer is misaligned.
    let aligned_buf;
    let parse_data = if (elf_data.as_ptr() as usize) % 8 != 0 {
        log::debug!("ELF data not 8-byte aligned (ptr={:#x}), copying to aligned buffer", elf_data.as_ptr() as usize);
        aligned_buf = elf_data.to_vec();
        aligned_buf.as_slice()
    } else {
        elf_data
    };

    let mut obj = Object::parse(parse_data).map_err(|e| {
        log::warn!("aya-obj ELF parse error: {e:?}");
        Error::ElfParseError
    })?;

    log::debug!(
        "Parsed ELF: {} programs, {} maps, {} functions",
        obj.programs.len(),
        obj.maps.len(),
        obj.functions.len()
    );

    // Phase 2: Create maps from aya-obj descriptors
    let mut map_fds: Vec<(String, u32)> = Vec::new();

    for (name, map) in &obj.maps {
        let map_type = match map.map_type() {
            1 => crate::maps::MapType::HashMap,   // BPF_MAP_TYPE_HASH
            2 => crate::maps::MapType::Array,      // BPF_MAP_TYPE_ARRAY
            9 => crate::maps::MapType::LruHash,    // BPF_MAP_TYPE_LRU_HASH
            22 => crate::maps::MapType::Queue,     // BPF_MAP_TYPE_QUEUE
            unsupported => {
                log::warn!(
                    "map '{}': unsupported BPF map type {} (only Hash=1, Array=2, LRU=9, Queue=22 are supported)",
                    name, unsupported
                );
                // Cleanup already created maps
                for (_, fd) in &map_fds {
                    let _ = crate::maps::destroy(*fd);
                }
                return Err(Error::MapCreationFailed);
            }
        };

        let def = crate::maps::MapDef {
            map_type,
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
        };

        match crate::maps::create(&def) {
            Ok(fd) => {
                log::info!("Created map '{}' with fd {}", name, fd);
                map_fds.push((name.clone(), fd));
            }
            Err(e) => {
                log::warn!("Failed to create map '{}': {:?}", name, e);
                for (_, fd) in &map_fds {
                    let _ = crate::maps::destroy(*fd);
                }
                return Err(Error::MapCreationFailed);
            }
        }
    }

    // Phase 3: Relocate — maps AND function calls (.text linking)
    //
    // text_sections tells relocate_maps which section indices contain code
    // (so it can resolve BPF-to-BPF call relocations via FunctionLinker
    // instead of treating them as map relocations).
    let text_sections: HashSet<usize> = obj
        .functions
        .keys()
        .map(|(section_index, _)| *section_index)
        .collect();

    if !map_fds.is_empty() || !text_sections.is_empty() {
        // Take maps out of obj to avoid borrow conflict:
        // relocate_maps needs &mut self, but also needs &Map references.
        // By taking maps out, we can pass &Map refs without borrowing obj immutably.
        let taken_maps = core::mem::take(&mut obj.maps);

        let maps_for_reloc: Vec<(&str, core::ffi::c_int, &aya_obj::maps::Map)> = map_fds
            .iter()
            .filter_map(|(name, fd)| {
                taken_maps.get(name.as_str()).map(|map| {
                    (name.as_str(), *fd as core::ffi::c_int, map)
                })
            })
            .collect();

        let reloc_result = obj.relocate_maps(maps_for_reloc.into_iter(), &text_sections);

        // Put maps back regardless of result
        obj.maps = taken_maps;

        reloc_result.map_err(|e| {
            log::warn!("aya-obj map relocation error: {e:?}");
            for (_, fd) in &map_fds {
                let _ = crate::maps::destroy(*fd);
            }
            Error::RelocationFailed
        })?;
    }

    // Phase 3b: Relocate function calls (.text section linking)
    //
    // This merges .text section sub-functions (memcpy, memmove, memset)
    // into the program's instruction stream and patches BPF_PSEUDO_CALL
    // imm fields with correct relative offsets.
    obj.relocate_calls(&text_sections).map_err(|e| {
        log::warn!("aya-obj call relocation error: {e:?}");
        for (_, fd) in &map_fds {
            let _ = crate::maps::destroy(*fd);
        }
        Error::RelocationFailed
    })?;

    // Phase 4: Select program and extract bytecode
    let program = match prog_name {
        Some(name) => obj.programs.get(name).ok_or_else(|| {
            log::warn!("Program '{}' not found in ELF (available: {:?})",
                name, obj.programs.keys().collect::<Vec<_>>());
            Error::NotFound
        })?,
        None => obj.programs.values().next().ok_or_else(|| {
            log::warn!("No programs found in ELF");
            Error::ElfParseError
        })?,
    };

    let func_key = (program.section_index, program.address);

    let function = obj.functions.get(&func_key).ok_or_else(|| {
        log::warn!("Function for program not found (key: {:?})", func_key);
        Error::ElfParseError
    })?;

    // Convert Vec<bpf_insn> to Vec<u8>
    // bpf_insn is #[repr(C)], 8 bytes each, safe to reinterpret as bytes.
    let insn_count = function.instructions.len();
    let bytecode: Vec<u8> = unsafe {
        core::slice::from_raw_parts(
            function.instructions.as_ptr() as *const u8,
            insn_count * 8,
        )
    }
    .to_vec();

    log::debug!(
        "Extracted program bytecode: {} instructions ({} bytes), {} maps",
        insn_count,
        bytecode.len(),
        map_fds.len()
    );

    Ok(ElfParseResult { bytecode, map_fds })
}

// =============================================================================
// EbpfProgram
// =============================================================================

/// Shared Map ownership for cloned programs.
/// Maps are only destroyed when the last reference is dropped.
struct SharedMapFds {
    map_fds: Vec<(String, u32)>,
}

impl Drop for SharedMapFds {
    fn drop(&mut self) {
        // Auto-cleanup associated Maps when last reference is dropped
        for (name, fd) in &self.map_fds {
            if let Err(e) = crate::maps::destroy(*fd) {
                log::warn!("Failed to destroy map '{}' (fd={}): {:?}", name, fd, e);
            } else {
                log::debug!("Destroyed map '{}' (fd={})", name, fd);
            }
        }
    }
}

/// eBPF program wrapper with helper support.
///
/// Stores bytecode and provides execution methods with automatic helper registration.
/// Maps are reference-counted and only destroyed when the last clone is dropped.
#[derive(Clone)]
pub struct EbpfProgram {
    bytecode: Vec<u8>,
    /// Shared Map FDs (reference counted, destroyed when last reference drops)
    shared_maps: Arc<SharedMapFds>,
}

impl EbpfProgram {
    /// Load eBPF bytecode into a program.
    ///
    /// Supports both raw bytecode and ELF format.
    /// If ELF contains Maps, they are automatically created and bytecode is patched.
    ///
    /// # Arguments
    /// * `data` - Raw eBPF bytecode or ELF file containing eBPF program.
    ///
    /// # Returns
    /// EbpfProgram on success, Error if bytecode is invalid.
    pub fn new(data: &[u8], prog_name: Option<&str>) -> Result<Self, Error> {
        let (bytecode, map_fds) = if is_elf(data) {
            log::debug!("Detected ELF format, parsing with aya-obj...");
            let result = parse_elf_with_aya(data, prog_name)?;
            (result.bytecode, result.map_fds)
        } else {
            (data.to_vec(), Vec::new())
        };

        if bytecode.is_empty() || bytecode.len() % 8 != 0 {
            return Err(Error::InvalidProgram);
        }

        log::debug!(
            "Loaded eBPF program: {} bytes ({} instructions), {} maps",
            bytecode.len(),
            bytecode.len() / 8,
            map_fds.len()
        );

        Ok(Self {
            bytecode,
            shared_maps: Arc::new(SharedMapFds { map_fds }),
        })
    }

    /// Get the bytecode.
    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    /// Get associated Map FDs.
    pub fn map_fds(&self) -> &[(String, u32)] {
        &self.shared_maps.map_fds
    }

    /// Execute the program without input data.
    ///
    /// # Returns
    /// The return value of the eBPF program (r0 register).
    pub fn execute(&self) -> Result<u64, Error> {
        use rbpf::EbpfVmNoData;

        let mut vm = EbpfVmNoData::new(Some(&self.bytecode)).map_err(|_| Error::InvalidProgram)?;

        helpers::register_all_nodata(&mut vm);

        // Register LOOKUP_BUFFER so eBPF can access bpf_map_lookup_elem results
        vm.register_allowed_memory(helpers::get_lookup_buffer_range());
        // Register NAME_BUFFER so eBPF can access bpf_get_tracepoint_name results
        vm.register_allowed_memory(helpers::get_name_buffer_range());

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

        let mut vm = EbpfVmRaw::new(Some(&self.bytecode)).map_err(|e| {
            log::error!("Failed to create VM: {:?}", e);
            Error::InvalidProgram
        })?;

        helpers::register_all_raw(&mut vm);

        // Register LOOKUP_BUFFER so eBPF can access bpf_map_lookup_elem results
        vm.register_allowed_memory(helpers::get_lookup_buffer_range());
        // Register NAME_BUFFER so eBPF can access bpf_get_tracepoint_name results
        vm.register_allowed_memory(helpers::get_name_buffer_range());

        vm.execute_program(ctx).map_err(|e| {
            log::error!("eBPF execution error: {:?}", e);
            Error::ExecutionFailed
        })
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
pub fn load_program(bytecode: &[u8], prog_name: Option<&str>) -> Result<u32, Error> {
    let program = EbpfProgram::new(bytecode, prog_name)?;
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

/// Get Map FDs associated with a loaded program.
///
/// # Arguments
/// * `prog_id` - Program ID returned by load_program().
///
/// # Returns
/// Vector of (map_name, map_fd) pairs, or None if program not found.
pub fn get_program_map_fds(prog_id: u32) -> Option<Vec<(String, u32)>> {
    let program = get_program(prog_id)?;
    Some(program.map_fds().to_vec())
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
// Initialization
// =============================================================================

/// Initialize the eBPF runtime.
pub fn init() {
    log::info!("Initializing eBPF runtime...");
    log::info!("  - {} helpers available", helpers::SUPPORTED_HELPERS.len());
}
