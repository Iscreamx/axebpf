//! Uretprobe return-instance bookkeeping.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnEntry {
    pub vm_id: u32,
    pub vcpu_id: u32,
    pub mm: u64,
    pub entry_pc: u64,
    pub return_gva: u64,
    pub return_hva: usize,
    pub saved_insn: u32,
    pub prog_id: u32,
    pub guest_path: String,
    pub symbol: String,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
}

type ReturnKey = (u32, u32, u64);

static RETURN_STACKS: Mutex<BTreeMap<ReturnKey, Vec<ReturnEntry>>> = Mutex::new(BTreeMap::new());

pub fn push(entry: ReturnEntry) -> Result<(), &'static str> {
    RETURN_STACKS
        .lock()
        .entry((entry.vm_id, entry.vcpu_id, entry.mm))
        .or_default()
        .push(entry);
    Ok(())
}

pub fn pop(vm_id: u32, vcpu_id: u32, mm: u64, return_gva: u64) -> Option<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let entries = stacks.get_mut(&(vm_id, vcpu_id, mm))?;
    let idx = entries.iter().rposition(|entry| entry.return_gva == return_gva)?;
    let entry = entries.remove(idx);
    if entries.is_empty() {
        stacks.remove(&(vm_id, vcpu_id, mm));
    }
    Some(entry)
}

pub fn pop_for_vcpu(vm_id: u32, vcpu_id: u32, return_gva: u64) -> Option<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let keys: Vec<_> = stacks
        .keys()
        .filter(|&&(entry_vm_id, entry_vcpu_id, _)| entry_vm_id == vm_id && entry_vcpu_id == vcpu_id)
        .copied()
        .collect();

    for key in keys {
        let Some(entries) = stacks.get_mut(&key) else {
            continue;
        };
        let Some(idx) = entries.iter().rposition(|entry| entry.return_gva == return_gva) else {
            continue;
        };
        let entry = entries.remove(idx);
        if entries.is_empty() {
            stacks.remove(&key);
        }
        return Some(entry);
    }

    None
}

pub fn clear_for_entry(vm_id: u32, entry_pc: u64) -> Vec<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let keys: Vec<_> = stacks.keys().copied().collect();
    let mut removed = Vec::new();

    for key in keys {
        let Some(entries) = stacks.get_mut(&key) else {
            continue;
        };
        let mut retained = Vec::with_capacity(entries.len());
        for entry in entries.drain(..) {
            if entry.vm_id == vm_id && entry.entry_pc == entry_pc {
                removed.push(entry);
            } else {
                retained.push(entry);
            }
        }
        if retained.is_empty() {
            stacks.remove(&key);
        } else {
            *entries = retained;
        }
    }

    removed
}

pub fn clear_for_vm(vm_id: u32) -> Vec<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let keys: Vec<_> = stacks.keys().copied().collect();
    let mut removed = Vec::new();

    for key in keys {
        let Some(entries) = stacks.get_mut(&key) else {
            continue;
        };
        let mut retained = Vec::with_capacity(entries.len());
        for entry in entries.drain(..) {
            if entry.vm_id == vm_id {
                removed.push(entry);
            } else {
                retained.push(entry);
            }
        }
        if retained.is_empty() {
            stacks.remove(&key);
        } else {
            *entries = retained;
        }
    }

    removed
}

#[cfg(any(test, feature = "test-utils"))]
pub fn list_for_test(vm_id: u32, vcpu_id: u32, mm: u64) -> Vec<ReturnEntry> {
    RETURN_STACKS
        .lock()
        .get(&(vm_id, vcpu_id, mm))
        .cloned()
        .unwrap_or_default()
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_all_for_test() {
    RETURN_STACKS.lock().clear();
}
