//! eBPF bytecode execution engine.
//!
//! Provides VM for running eBPF programs with registered helpers.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
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

// =============================================================================
// ELF Map Relocation Structures
// =============================================================================

/// Map definition extracted from ELF `maps` section.
#[derive(Debug, Clone)]
struct ElfMapDef {
    /// Symbol name (e.g., "COUNTER_MAP")
    name: String,
    /// BPF_MAP_TYPE_* value
    map_type: u32,
    /// Size of key in bytes
    key_size: u32,
    /// Size of value in bytes
    value_size: u32,
    /// Maximum number of entries
    max_entries: u32,
}

/// Relocation entry from ELF `.relXXX` section.
#[derive(Debug, Clone)]
struct ElfReloc {
    /// Offset in code section where patch is needed
    offset: usize,
    /// Symbol index in symbol table
    symbol_idx: usize,
}

/// Result of parsing ELF with Maps.
#[derive(Debug)]
struct ElfParseResult {
    /// Extracted bytecode (already patched if Maps present)
    bytecode: Vec<u8>,
    /// Created Map FDs: (symbol_name, map_fd)
    map_fds: Vec<(String, u32)>,
}

// =============================================================================
// ELF Parsing (minimal implementation for eBPF)
// =============================================================================

/// ELF magic number
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Check if data is an ELF file
fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == ELF_MAGIC
}

/// Parse the `maps` section to extract Map definitions.
///
/// Each Map definition is 28 bytes:
/// - offset 0x00: map_type (u32)
/// - offset 0x04: key_size (u32)
/// - offset 0x08: value_size (u32)
/// - offset 0x0c: max_entries (u32)
/// - offset 0x10: map_flags (u32) - ignored
/// - offset 0x14-0x1b: padding
fn parse_maps_section(
    maps_data: &[u8],
    symbols: &[(String, usize, usize)], // (name, section_idx, offset)
    maps_section_idx: usize,
) -> Vec<ElfMapDef> {
    const MAP_DEF_SIZE: usize = 28;
    let mut map_defs = Vec::new();

    // Find symbols that point to maps section
    for (name, sec_idx, offset) in symbols {
        if *sec_idx != maps_section_idx {
            continue;
        }

        // Ensure offset is valid
        if *offset + MAP_DEF_SIZE > maps_data.len() {
            log::warn!("Map '{}' offset {} exceeds maps section size", name, offset);
            continue;
        }

        let base = *offset;
        let map_type = u32::from_le_bytes(maps_data[base..base + 4].try_into().unwrap());
        let key_size = u32::from_le_bytes(maps_data[base + 4..base + 8].try_into().unwrap());
        let value_size = u32::from_le_bytes(maps_data[base + 8..base + 12].try_into().unwrap());
        let max_entries = u32::from_le_bytes(maps_data[base + 12..base + 16].try_into().unwrap());

        log::debug!(
            "Found map '{}': type={}, key_size={}, value_size={}, max_entries={}",
            name,
            map_type,
            key_size,
            value_size,
            max_entries
        );

        map_defs.push(ElfMapDef {
            name: name.clone(),
            map_type,
            key_size,
            value_size,
            max_entries,
        });
    }

    map_defs
}

/// Parse a relocation section (.relXXX).
///
/// Each relocation entry is 16 bytes (REL format for BPF):
/// - offset 0x00: r_offset (u64) - offset in target section
/// - offset 0x08: r_info (u64) - symbol index in upper 32 bits
fn parse_relocation_section(rel_data: &[u8]) -> Vec<ElfReloc> {
    const REL_ENTRY_SIZE: usize = 16;
    let mut relocs = Vec::new();

    let num_entries = rel_data.len() / REL_ENTRY_SIZE;
    for i in 0..num_entries {
        let base = i * REL_ENTRY_SIZE;
        if base + REL_ENTRY_SIZE > rel_data.len() {
            break;
        }

        let r_offset = u64::from_le_bytes(rel_data[base..base + 8].try_into().unwrap()) as usize;
        let r_info = u64::from_le_bytes(rel_data[base + 8..base + 16].try_into().unwrap());

        // Symbol index is in upper 32 bits of r_info
        let symbol_idx = (r_info >> 32) as usize;

        log::debug!(
            "Relocation: offset={:#x}, symbol_idx={}",
            r_offset,
            symbol_idx
        );

        relocs.push(ElfReloc {
            offset: r_offset,
            symbol_idx,
        });
    }

    relocs
}

/// Patch a `ld_map_fd` instruction with actual Map FD.
///
/// The `ld_map_fd` is a 16-byte double instruction (ld_imm64):
/// - Instruction 1: opcode=0x18, imm=fd_lo (bytes 4-7)
/// - Instruction 2: pseudo, imm=fd_hi (bytes 12-15)
fn patch_map_fd(bytecode: &mut [u8], offset: usize, map_fd: u32) -> Result<(), Error> {
    // Verify bounds
    if offset + 16 > bytecode.len() {
        log::warn!(
            "Relocation offset {:#x} exceeds bytecode length {}",
            offset,
            bytecode.len()
        );
        return Err(Error::RelocationFailed);
    }

    // Verify this is a ld_imm64 instruction (opcode 0x18)
    if bytecode[offset] != 0x18 {
        log::warn!(
            "Expected ld_imm64 (0x18) at offset {:#x}, found {:#x}",
            offset,
            bytecode[offset]
        );
        return Err(Error::InvalidProgram);
    }

    // Patch imm_lo (bytes 4-7 of first instruction)
    bytecode[offset + 4..offset + 8].copy_from_slice(&map_fd.to_le_bytes());

    // Patch imm_hi (bytes 12-15 of second instruction) - always 0 for 32-bit FDs
    bytecode[offset + 12..offset + 16].copy_from_slice(&0u32.to_le_bytes());

    log::debug!("Patched Map FD {} at offset {:#x}", map_fd, offset);
    Ok(())
}

/// Parse ELF file with full Map relocation support.
///
/// This function:
/// 1. Parses section headers to find maps, code, and relocation sections
/// 2. Parses symbol table to get Map names
/// 3. Creates Maps and gets FDs
/// 4. Patches bytecode with Map FDs
fn parse_elf_with_maps(elf_data: &[u8]) -> Result<ElfParseResult, Error> {
    if elf_data.len() < 64 {
        return Err(Error::ElfParseError);
    }

    log::debug!(
        "Parsing ELF with Map support, size={} bytes",
        elf_data.len()
    );

    // ELF64 header parsing
    let e_shoff = u64::from_le_bytes(elf_data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(elf_data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(elf_data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(elf_data[62..64].try_into().unwrap()) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        return Err(Error::ElfParseError);
    }

    // Get section name string table offset
    let shstrtab_off = e_shoff + e_shstrndx * e_shentsize;
    if shstrtab_off + e_shentsize > elf_data.len() {
        return Err(Error::ElfParseError);
    }
    let strtab_sh_offset = u64::from_le_bytes(
        elf_data[shstrtab_off + 24..shstrtab_off + 32]
            .try_into()
            .unwrap(),
    ) as usize;

    // First pass: collect section info
    let mut code_section: Option<(usize, usize, usize)> = None; // (idx, offset, size)
    let mut maps_section: Option<(usize, usize, usize)> = None;
    let mut rel_section: Option<(usize, usize)> = None; // (offset, size)
    let mut symtab_section: Option<(usize, usize, usize)> = None; // (offset, size, link)
    let mut _strtab_offset: usize = 0;

    for i in 0..e_shnum {
        let sh_off = e_shoff + i * e_shentsize;
        if sh_off + e_shentsize > elf_data.len() {
            continue;
        }

        let sh_name_off =
            u32::from_le_bytes(elf_data[sh_off..sh_off + 4].try_into().unwrap()) as usize;
        let sh_type = u32::from_le_bytes(elf_data[sh_off + 4..sh_off + 8].try_into().unwrap());
        let sh_offset =
            u64::from_le_bytes(elf_data[sh_off + 24..sh_off + 32].try_into().unwrap()) as usize;
        let sh_size =
            u64::from_le_bytes(elf_data[sh_off + 32..sh_off + 40].try_into().unwrap()) as usize;
        let sh_link =
            u32::from_le_bytes(elf_data[sh_off + 40..sh_off + 44].try_into().unwrap()) as usize;

        // Get section name
        let name_start = strtab_sh_offset + sh_name_off;
        let mut name_end = name_start;
        while name_end < elf_data.len() && elf_data[name_end] != 0 {
            name_end += 1;
        }
        let section_name = core::str::from_utf8(&elf_data[name_start..name_end]).unwrap_or("");

        log::debug!(
            "Section [{}] '{}': type={}, offset={:#x}, size={}",
            i,
            section_name,
            sh_type,
            sh_offset,
            sh_size
        );

        // Identify sections
        if section_name == "tracepoint" || section_name.starts_with("tracepoint/")
            || section_name == "kprobe" || section_name.starts_with("kprobe/")
            || section_name == "kretprobe" || section_name.starts_with("kretprobe/")
        {
            code_section = Some((i, sh_offset, sh_size));
        } else if section_name == "maps" {
            maps_section = Some((i, sh_offset, sh_size));
        } else if section_name == ".reltracepoint" || section_name.starts_with(".reltracepoint")
            || section_name == ".relkprobe" || section_name.starts_with(".relkprobe")
            || section_name == ".relkretprobe" || section_name.starts_with(".relkretprobe")
        {
            rel_section = Some((sh_offset, sh_size));
        } else if sh_type == 2 {
            // SHT_SYMTAB
            symtab_section = Some((sh_offset, sh_size, sh_link));
        } else if sh_type == 3 && section_name == ".strtab" {
            // SHT_STRTAB
            _strtab_offset = sh_offset;
        }
    }

    // Must have code section
    let (_code_idx, code_offset, code_size) = code_section.ok_or_else(|| {
        log::warn!("No tracepoint code section found");
        Error::ElfParseError
    })?;

    // Extract bytecode
    if code_offset + code_size > elf_data.len() {
        return Err(Error::ElfParseError);
    }
    let mut bytecode = elf_data[code_offset..code_offset + code_size].to_vec();

    // If no maps section, return bytecode as-is (backward compatible)
    let (maps_idx, maps_offset, maps_size) = match maps_section {
        Some(m) => m,
        None => {
            log::debug!("No maps section, returning raw bytecode");
            return Ok(ElfParseResult {
                bytecode,
                map_fds: Vec::new(),
            });
        }
    };

    // Parse symbol table to get Map names
    let (sym_offset, sym_size, sym_strtab_link) = symtab_section.ok_or_else(|| {
        log::warn!("No symbol table found");
        Error::ElfParseError
    })?;

    // Get symbol string table offset (from link field)
    let sym_strtab_off = {
        let link_sh_off = e_shoff + sym_strtab_link * e_shentsize;
        if link_sh_off + e_shentsize > elf_data.len() {
            _strtab_offset
        } else {
            u64::from_le_bytes(
                elf_data[link_sh_off + 24..link_sh_off + 32]
                    .try_into()
                    .unwrap(),
            ) as usize
        }
    };

    // Parse symbols: (name, section_idx, value/offset)
    let mut symbols: Vec<(String, usize, usize)> = Vec::new();
    const SYM_ENTRY_SIZE: usize = 24; // ELF64 symbol entry size
    let num_symbols = sym_size / SYM_ENTRY_SIZE;

    for i in 0..num_symbols {
        let base = sym_offset + i * SYM_ENTRY_SIZE;
        if base + SYM_ENTRY_SIZE > elf_data.len() {
            break;
        }

        let st_name = u32::from_le_bytes(elf_data[base..base + 4].try_into().unwrap()) as usize;
        let st_shndx =
            u16::from_le_bytes(elf_data[base + 6..base + 8].try_into().unwrap()) as usize;
        let st_value =
            u64::from_le_bytes(elf_data[base + 8..base + 16].try_into().unwrap()) as usize;

        // Get symbol name
        let name_start = sym_strtab_off + st_name;
        let mut name_end = name_start;
        while name_end < elf_data.len() && elf_data[name_end] != 0 {
            name_end += 1;
        }
        let sym_name = core::str::from_utf8(&elf_data[name_start..name_end])
            .unwrap_or("")
            .to_string();

        if !sym_name.is_empty() {
            symbols.push((sym_name, st_shndx, st_value));
        }
    }

    // Parse maps section
    let maps_data = &elf_data[maps_offset..maps_offset + maps_size];
    let map_defs = parse_maps_section(maps_data, &symbols, maps_idx);

    if map_defs.is_empty() {
        log::debug!("No Map definitions found");
        return Ok(ElfParseResult {
            bytecode,
            map_fds: Vec::new(),
        });
    }

    // Create Maps and build name->fd mapping
    let mut map_name_to_fd: BTreeMap<String, u32> = BTreeMap::new();
    let mut map_fds: Vec<(String, u32)> = Vec::new();

    for map_def in &map_defs {
        // Convert BPF map type to our MapType
        let map_type = match map_def.map_type {
            1 => crate::maps::MapType::HashMap, // BPF_MAP_TYPE_HASH
            2 => crate::maps::MapType::Array,   // BPF_MAP_TYPE_ARRAY
            9 => crate::maps::MapType::LruHash, // BPF_MAP_TYPE_LRU_HASH
            22 => crate::maps::MapType::Queue,  // BPF_MAP_TYPE_QUEUE
            _ => {
                log::warn!(
                    "Unsupported map type {} for '{}'",
                    map_def.map_type,
                    map_def.name
                );
                return Err(Error::MapCreationFailed);
            }
        };

        let def = crate::maps::MapDef {
            map_type,
            key_size: map_def.key_size,
            value_size: map_def.value_size,
            max_entries: map_def.max_entries,
        };

        match crate::maps::create(&def) {
            Ok(fd) => {
                log::info!("Created Map '{}' with FD {}", map_def.name, fd);
                map_name_to_fd.insert(map_def.name.clone(), fd);
                map_fds.push((map_def.name.clone(), fd));
            }
            Err(e) => {
                log::warn!("Failed to create map '{}': {:?}", map_def.name, e);
                // Cleanup already created maps
                for (_, fd) in &map_fds {
                    let _ = crate::maps::destroy(*fd);
                }
                return Err(Error::MapCreationFailed);
            }
        }
    }

    // Parse and apply relocations
    if let Some((rel_offset, rel_size)) = rel_section {
        let rel_data = &elf_data[rel_offset..rel_offset + rel_size];
        let relocs = parse_relocation_section(rel_data);

        for reloc in relocs {
            // Find symbol name
            let sym_name = symbols
                .get(reloc.symbol_idx)
                .map(|(name, _, _)| name.as_str())
                .unwrap_or("");

            if sym_name.is_empty() {
                log::warn!(
                    "Empty symbol name for relocation at offset {:#x}",
                    reloc.offset
                );
                continue;
            }

            // Find Map FD for this symbol
            // Skip non-Map symbols (like memcpy, memset, etc.)
            if let Some(&fd) = map_name_to_fd.get(sym_name) {
                patch_map_fd(&mut bytecode, reloc.offset, fd)?;
            }
            // Note: Non-Map relocations (memcpy, etc.) are silently skipped
            // as they are handled by the eBPF VM's built-in functions
        }
    }

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
    pub fn new(data: &[u8]) -> Result<Self, Error> {
        let (bytecode, map_fds) = if is_elf(data) {
            log::debug!("Detected ELF format, parsing with Map support...");
            let result = parse_elf_with_maps(data)?;
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
