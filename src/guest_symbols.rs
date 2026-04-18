//! Per-VM guest symbol table management.
//!
//! Parses `nm -n` / Linux `System.map` text and provides
//! symbol-to-address and address-to-symbol lookup for guest kprobe.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

struct GuestSymbolTable {
    name_to_addr: BTreeMap<String, u64>,
    addr_to_name: BTreeMap<u64, (String, char)>,
}

static GUEST_SYMBOL_TABLES: Mutex<BTreeMap<u32, GuestSymbolTable>> = Mutex::new(BTreeMap::new());

/// Load symbols from `nm -n` / `System.map` style text.
///
/// Each valid line is `<hex_addr> <type_char> <name>`.
/// Malformed lines are skipped. Duplicate names keep the last address.
pub fn load_from_text(vm_id: u32, content: &str) -> Result<usize, &'static str> {
    let mut name_to_addr = BTreeMap::new();
    let mut addr_to_name = BTreeMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(addr_str) = parts.next() else {
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

        let addr_token = addr_str
            .strip_prefix("0x")
            .or_else(|| addr_str.strip_prefix("0X"))
            .unwrap_or(addr_str);
        let Ok(addr) = u64::from_str_radix(addr_token, 16) else {
            continue;
        };

        let sym_type = type_str.as_bytes()[0] as char;
        let name = String::from(name);

        if let Some(old_addr) = name_to_addr.insert(name.clone(), addr) {
            addr_to_name.remove(&old_addr);
        }
        addr_to_name.insert(addr, (name, sym_type));
    }

    let count = name_to_addr.len();
    if count == 0 {
        return Err("no valid symbols found in input");
    }

    let table = GuestSymbolTable {
        name_to_addr,
        addr_to_name,
    };

    GUEST_SYMBOL_TABLES.lock().insert(vm_id, table);
    log::info!("guest_symbols: loaded {} symbols for vm{}", count, vm_id);
    Ok(count)
}

/// Look up a guest symbol address by name.
pub fn lookup_addr(vm_id: u32, name: &str) -> Option<u64> {
    let tables = GUEST_SYMBOL_TABLES.lock();
    let table = tables.get(&vm_id)?;
    table.name_to_addr.get(name).copied()
}

/// Look up the nearest symbol name for a guest address.
///
/// Returns `(name, type_char, offset)` where `offset = addr - symbol_addr`.
pub fn lookup_name(vm_id: u32, addr: u64) -> Option<(String, char, u64)> {
    let tables = GUEST_SYMBOL_TABLES.lock();
    let table = tables.get(&vm_id)?;

    let (&sym_addr, (name, sym_type)) = table.addr_to_name.range(..=addr).next_back()?;
    Some((name.clone(), *sym_type, addr - sym_addr))
}

/// Search symbols containing `pattern`, capped by `max_results`.
pub fn search(vm_id: u32, pattern: &str, max_results: usize) -> Vec<(u64, String, char)> {
    if max_results == 0 {
        return Vec::new();
    }

    let tables = GUEST_SYMBOL_TABLES.lock();
    let Some(table) = tables.get(&vm_id) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for (name, &addr) in &table.name_to_addr {
        if results.len() >= max_results {
            break;
        }
        if name.contains(pattern) {
            let sym_type = table
                .addr_to_name
                .get(&addr)
                .map(|(_, ty)| *ty)
                .unwrap_or('?');
            results.push((addr, name.clone(), sym_type));
        }
    }

    results
}

/// Check whether symbols are loaded for the VM.
pub fn is_loaded(vm_id: u32) -> bool {
    GUEST_SYMBOL_TABLES.lock().contains_key(&vm_id)
}

/// Unload guest symbols for one VM.
pub fn unload(vm_id: u32) {
    GUEST_SYMBOL_TABLES.lock().remove(&vm_id);
    log::info!("guest_symbols: unloaded symbols for vm{}", vm_id);
}

/// Get loaded symbol count for one VM.
pub fn symbol_count(vm_id: u32) -> usize {
    let tables = GUEST_SYMBOL_TABLES.lock();
    tables
        .get(&vm_id)
        .map(|t| t.name_to_addr.len())
        .unwrap_or(0)
}
