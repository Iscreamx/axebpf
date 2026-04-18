//! Guest user object metadata registry.
//!
//! The first stage stores host-side loaded symbol metadata keyed by
//! `(vm_id, guest_path)` so uprobe attachment can resolve symbols into
//! file offsets without depending on guest filesystem parsing.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

const PF_X: u32 = 0x1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub file_offset: u64,
    pub flags: u32,
}

impl LoadSegment {
    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    pub fn contains(&self, object_addr: u64) -> bool {
        object_addr
            .checked_sub(self.vaddr)
            .is_some_and(|delta| delta < self.memsz)
    }
}

struct GuestObject {
    symbol_to_offset: BTreeMap<String, u64>,
    offset_to_symbol: BTreeMap<u64, String>,
    main_text_start: Option<u64>,
    load_segments: Vec<LoadSegment>,
}

static GUEST_OBJECTS: Mutex<BTreeMap<u32, BTreeMap<String, GuestObject>>> =
    Mutex::new(BTreeMap::new());

fn parse_u64_token(token: &str) -> Option<u64> {
    let token = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .unwrap_or(token);
    if token.is_empty() {
        return None;
    }
    u64::from_str_radix(token, 16)
        .ok()
        .or_else(|| token.parse::<u64>().ok())
}

fn parse_segment_flags(token: &str) -> Option<u32> {
    if let Some(value) = parse_u64_token(token) {
        return u32::try_from(value).ok();
    }

    let mut flags = 0u32;
    for ch in token.chars() {
        match ch {
            'x' | 'X' => flags |= 0x1,
            'w' | 'W' => flags |= 0x2,
            'r' | 'R' => flags |= 0x4,
            _ => return None,
        }
    }
    Some(flags)
}

fn parse_load_segment_directive(line: &str) -> Option<LoadSegment> {
    let rest = line.strip_prefix("# axvisor-load-segment")?.trim();
    let mut parts = rest.split_whitespace();
    let vaddr = parse_u64_token(parts.next()?)?;
    let memsz = parse_u64_token(parts.next()?)?;
    let file_offset = parse_u64_token(parts.next()?)?;
    let flags = parse_segment_flags(parts.next()?)?;
    if memsz == 0 {
        return None;
    }
    Some(LoadSegment {
        vaddr,
        memsz,
        file_offset,
        flags,
    })
}

fn parse_offset_token(symbol_or_offset: &str) -> Option<u64> {
    parse_u64_token(symbol_or_offset)
}

/// Load symbols for one guest object from `nm -n` style text.
///
/// Each valid line is `<hex_offset> <type_char> <name>`. Invalid lines are
/// skipped and duplicate names keep the last offset.
pub fn load_text_symbols(
    vm_id: u32,
    guest_path: &str,
    content: &str,
) -> Result<usize, &'static str> {
    let mut symbol_to_offset = BTreeMap::new();
    let mut offset_to_symbol = BTreeMap::new();
    let mut main_text_start = None;
    let mut load_segments = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# axvisor-main-text-start") {
            let token = rest.trim();
            let token = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .unwrap_or(token);
            if let Ok(value) = u64::from_str_radix(token, 16) {
                main_text_start = Some(value);
            }
            continue;
        }
        if let Some(segment) = parse_load_segment_directive(line) {
            load_segments.push(segment);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(offset_str) = parts.next() else {
            continue;
        };
        let Some(type_str) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };

        if name.is_empty() || type_str.len() != 1 {
            continue;
        }

        let offset_token = offset_str
            .strip_prefix("0x")
            .or_else(|| offset_str.strip_prefix("0X"))
            .unwrap_or(offset_str);
        let Ok(offset) = u64::from_str_radix(offset_token, 16) else {
            continue;
        };

        let name = String::from(name);
        if let Some(old_offset) = symbol_to_offset.insert(name.clone(), offset) {
            offset_to_symbol.remove(&old_offset);
        }
        offset_to_symbol.insert(offset, name);
    }

    let count = symbol_to_offset.len();
    if count == 0 {
        return Err("no valid symbols found in input");
    }

    let object = GuestObject {
        symbol_to_offset,
        offset_to_symbol,
        main_text_start,
        load_segments,
    };

    let mut tables = GUEST_OBJECTS.lock();
    tables
        .entry(vm_id)
        .or_default()
        .insert(String::from(guest_path), object);
    log::info!(
        "guest_uprobe: loaded {} symbols for vm{}:{}",
        count,
        vm_id,
        guest_path
    );
    Ok(count)
}

/// Look up file offset by symbol name.
pub fn lookup_offset(vm_id: u32, guest_path: &str, symbol: &str) -> Option<u64> {
    let tables = GUEST_OBJECTS.lock();
    let vm_objects = tables.get(&vm_id)?;
    let object = vm_objects.get(guest_path)?;
    object.symbol_to_offset.get(symbol).copied()
}

/// Look up the nearest symbol name for one file offset.
pub fn lookup_symbol(vm_id: u32, guest_path: &str, offset: u64) -> Option<(String, u64)> {
    let tables = GUEST_OBJECTS.lock();
    let vm_objects = tables.get(&vm_id)?;
    let object = vm_objects.get(guest_path)?;
    let (&sym_offset, name) = object.offset_to_symbol.range(..=offset).next_back()?;
    Some((name.clone(), offset - sym_offset))
}

/// List all load segments captured from metadata directives.
pub fn list_load_segments(vm_id: u32, guest_path: &str) -> Option<Vec<LoadSegment>> {
    let tables = GUEST_OBJECTS.lock();
    let vm_objects = tables.get(&vm_id)?;
    let object = vm_objects.get(guest_path)?;
    Some(object.load_segments.clone())
}

/// List executable load segments.
pub fn list_executable_load_segments(vm_id: u32, guest_path: &str) -> Option<Vec<LoadSegment>> {
    let segments = list_load_segments(vm_id, guest_path)?;
    Some(
        segments
            .into_iter()
            .filter(LoadSegment::is_executable)
            .collect(),
    )
}

/// Resolve symbol name or raw offset token to an object-relative address.
pub fn resolve_object_addr(
    vm_id: u32,
    guest_path: &str,
    symbol_or_offset: &str,
) -> Result<u64, &'static str> {
    if let Some(offset) = lookup_offset(vm_id, guest_path, symbol_or_offset) {
        return Ok(offset);
    }
    parse_offset_token(symbol_or_offset).ok_or("symbol not found and offset parse failed")
}

/// Resolve and validate that the address is in an executable load segment.
///
/// If no load segment metadata exists for the object, this function accepts the
/// resolved address to stay backward compatible with symbol-only metadata.
pub fn resolve_executable_object_addr(
    vm_id: u32,
    guest_path: &str,
    symbol_or_offset: &str,
) -> Result<u64, &'static str> {
    let offset = resolve_object_addr(vm_id, guest_path, symbol_or_offset)?;
    let Some(segments) = list_load_segments(vm_id, guest_path) else {
        return Err("guest object metadata not loaded");
    };
    if segments.is_empty() {
        return Ok(offset);
    }
    if segments
        .iter()
        .any(|segment| segment.is_executable() && segment.contains(offset))
    {
        return Ok(offset);
    }
    Err("offset not in executable load segment")
}

/// Look up the containing load segment for an object-relative address.
pub fn lookup_load_segment(vm_id: u32, guest_path: &str, object_addr: u64) -> Option<LoadSegment> {
    let segments = list_load_segments(vm_id, guest_path)?;
    segments
        .into_iter()
        .find(|segment| segment.contains(object_addr))
}

fn resolve_runtime_pc_with_legacy_formula(
    object_addr: u64,
    mapping_start: u64,
    mapping_end: Option<u64>,
    mapping_file_offset: u64,
) -> Result<u64, &'static str> {
    let runtime_pc = if mapping_file_offset == 0 && object_addr >= mapping_start {
        object_addr
    } else {
        let offset_delta = object_addr
            .checked_sub(mapping_file_offset)
            .ok_or("object addr before mapping file offset")?;
        mapping_start
            .checked_add(offset_delta)
            .ok_or("runtime pc overflow")?
    };
    if runtime_pc < mapping_start {
        return Err("runtime pc before mapping start");
    }
    if mapping_end.is_some_and(|end| runtime_pc >= end) {
        return Err("runtime pc outside mapping");
    }
    Ok(runtime_pc)
}

fn resolve_runtime_pc_with_segment(
    object_addr: u64,
    mapping_start: u64,
    mapping_end: Option<u64>,
    mapping_file_offset: u64,
    segment: &LoadSegment,
) -> Result<u64, &'static str> {
    const PAGE_OFFSET_MASK: u64 = 0xfff;

    if (segment.vaddr & PAGE_OFFSET_MASK) != (segment.file_offset & PAGE_OFFSET_MASK) {
        return Err("segment vaddr/file offset page mismatch");
    }

    let segment_delta = object_addr
        .checked_sub(segment.vaddr)
        .ok_or("object addr before segment start")?;
    let object_file_offset = segment
        .file_offset
        .checked_add(segment_delta)
        .ok_or("object file offset overflow")?;
    let object_delta = object_file_offset
        .checked_sub(mapping_file_offset)
        .ok_or("object file offset before mapping file offset")?;
    let runtime_pc = mapping_start
        .checked_add(object_delta)
        .ok_or("runtime pc overflow")?;
    if mapping_end.is_some_and(|end| runtime_pc >= end) {
        return Err("runtime pc outside mapping");
    }
    Ok(runtime_pc)
}

/// Resolve one object-relative address to runtime PC using mapping information.
///
/// When load segment metadata is available, this uses segment-relative load bias:
/// `runtime_pc = load_bias + object_addr`.
/// If no load segment metadata exists, it falls back to legacy
/// `start/file_offset` conversion for compatibility.
pub fn resolve_runtime_pc_for_mapping(
    vm_id: u32,
    guest_path: &str,
    object_addr: u64,
    mapping_start: u64,
    mapping_end: Option<u64>,
    mapping_file_offset: u64,
) -> Result<u64, &'static str> {
    let Some(segments) = list_load_segments(vm_id, guest_path) else {
        return Err("guest object metadata not loaded");
    };
    if segments.is_empty() {
        return resolve_runtime_pc_with_legacy_formula(
            object_addr,
            mapping_start,
            mapping_end,
            mapping_file_offset,
        );
    }

    let segment = segments
        .iter()
        .find(|segment| segment.is_executable() && segment.contains(object_addr))
        .or_else(|| {
            segments
                .iter()
                .find(|segment| segment.contains(object_addr))
        })
        .ok_or("object addr not in any load segment")?;

    resolve_runtime_pc_with_segment(
        object_addr,
        mapping_start,
        mapping_end,
        mapping_file_offset,
        segment,
    )
}

/// Look up the expected main executable mapping start recorded in metadata.
pub fn lookup_main_text_start(vm_id: u32, guest_path: &str) -> Option<u64> {
    let tables = GUEST_OBJECTS.lock();
    let vm_objects = tables.get(&vm_id)?;
    let object = vm_objects.get(guest_path)?;
    object.main_text_start
}

/// Check whether metadata has been loaded for one guest object.
pub fn is_loaded(vm_id: u32, guest_path: &str) -> bool {
    let tables = GUEST_OBJECTS.lock();
    tables
        .get(&vm_id)
        .is_some_and(|vm_objects| vm_objects.contains_key(guest_path))
}

/// Remove metadata for one guest object.
pub fn unload_object(vm_id: u32, guest_path: &str) {
    let mut tables = GUEST_OBJECTS.lock();
    if let Some(vm_objects) = tables.get_mut(&vm_id) {
        vm_objects.remove(guest_path);
        if vm_objects.is_empty() {
            tables.remove(&vm_id);
        }
    }
}

/// Remove all object metadata for one VM.
pub fn unload_vm(vm_id: u32) {
    GUEST_OBJECTS.lock().remove(&vm_id);
}
