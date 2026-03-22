//! Guest user object metadata registry.
//!
//! The first stage stores host-side loaded symbol metadata keyed by
//! `(vm_id, guest_path)` so uprobe attachment can resolve symbols into
//! file offsets without depending on guest filesystem parsing.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;

struct GuestObject {
    symbol_to_offset: BTreeMap<String, u64>,
    offset_to_symbol: BTreeMap<u64, String>,
    main_text_start: Option<u64>,
}

static GUEST_OBJECTS: Mutex<BTreeMap<u32, BTreeMap<String, GuestObject>>> =
    Mutex::new(BTreeMap::new());

/// Load symbols for one guest object from `nm -n` style text.
///
/// Each valid line is `<hex_offset> <type_char> <name>`. Invalid lines are
/// skipped and duplicate names keep the last offset.
pub fn load_text_symbols(vm_id: u32, guest_path: &str, content: &str) -> Result<usize, &'static str> {
    let mut symbol_to_offset = BTreeMap::new();
    let mut offset_to_symbol = BTreeMap::new();
    let mut main_text_start = None;

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
