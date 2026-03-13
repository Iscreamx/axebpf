//! Per-vCPU return address stack for guest kretprobe.
//!
//! Tracks pending return probes per CPU as a LIFO stack.
//! Entry hits on `is_ret=true` probes push a return address record.
//! Return hits pop the matching record to recover the logical probe site.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

const MAX_RETURN_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct ReturnEntry {
    pub vm_id: u32,
    pub return_gva: u64,
    pub return_hva: usize,
    pub saved_insn: u32,
    pub entry_gva: u64,
    pub prog_id: u32,
}

#[derive(Clone, Copy, Debug)]
struct ReturnStack {
    entries: [Option<ReturnEntry>; MAX_RETURN_DEPTH],
    top: usize,
}

impl ReturnStack {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_RETURN_DEPTH],
            top: 0,
        }
    }

    fn push(&mut self, entry: ReturnEntry) -> Result<(), &'static str> {
        if self.top >= MAX_RETURN_DEPTH {
            return Err("return stack is full");
        }
        self.entries[self.top] = Some(entry);
        self.top += 1;
        Ok(())
    }

    fn pop_matching(&mut self, vm_id: u32, return_gva: u64) -> Option<ReturnEntry> {
        let mut idx = self.top;
        while idx > 0 {
            idx -= 1;
            let Some(entry) = self.entries[idx] else {
                continue;
            };
            if entry.vm_id != vm_id || entry.return_gva != return_gva {
                continue;
            }

            let removed = self.entries[idx].take();
            let mut shift = idx;
            while shift + 1 < self.top {
                self.entries[shift] = self.entries[shift + 1];
                shift += 1;
            }
            if self.top > 0 {
                self.top -= 1;
                self.entries[self.top] = None;
            }
            return removed;
        }
        None
    }

    fn retain<F>(&mut self, mut keep: F, removed: &mut Vec<ReturnEntry>)
    where
        F: FnMut(ReturnEntry) -> bool,
    {
        let mut write = 0usize;
        for idx in 0..self.top {
            let Some(entry) = self.entries[idx].take() else {
                continue;
            };
            if keep(entry) {
                self.entries[write] = Some(entry);
                write += 1;
            } else {
                removed.push(entry);
            }
        }
        for idx in write..self.top {
            self.entries[idx] = None;
        }
        self.top = write;
    }

    fn has_pending(&self, vm_id: u32, return_gva: u64) -> bool {
        self.entries[..self.top]
            .iter()
            .flatten()
            .any(|entry| entry.vm_id == vm_id && entry.return_gva == return_gva)
    }

    fn is_empty(&self) -> bool {
        self.top == 0
    }
}

static RETURN_STACKS: Mutex<BTreeMap<usize, ReturnStack>> = Mutex::new(BTreeMap::new());

pub fn push(cpu: usize, entry: ReturnEntry) -> Result<(), &'static str> {
    let mut stacks = RETURN_STACKS.lock();
    let stack = stacks.entry(cpu).or_insert_with(ReturnStack::new);
    stack.push(entry)
}

pub fn pop_matching(cpu: usize, vm_id: u32, return_gva: u64) -> Option<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let stack = stacks.get_mut(&cpu)?;
    let removed = stack.pop_matching(vm_id, return_gva);
    if stack.is_empty() {
        stacks.remove(&cpu);
    }
    removed
}

pub fn has_pending(cpu: usize, vm_id: u32, return_gva: u64) -> bool {
    RETURN_STACKS
        .lock()
        .get(&cpu)
        .map(|stack| stack.has_pending(vm_id, return_gva))
        .unwrap_or(false)
}

pub fn clear_for_vm(vm_id: u32) {
    let mut stacks = RETURN_STACKS.lock();
    let cpus: Vec<usize> = stacks.keys().copied().collect();
    for cpu in cpus {
        let mut removed = Vec::new();
        if let Some(stack) = stacks.get_mut(&cpu) {
            stack.retain(|entry| entry.vm_id != vm_id, &mut removed);
            if stack.is_empty() {
                stacks.remove(&cpu);
            }
        }
    }
}

pub fn clear_for_vm_probe(vm_id: u32, entry_gva: u64) -> Vec<ReturnEntry> {
    let mut stacks = RETURN_STACKS.lock();
    let cpus: Vec<usize> = stacks.keys().copied().collect();
    let mut removed = Vec::new();
    for cpu in cpus {
        if let Some(stack) = stacks.get_mut(&cpu) {
            stack.retain(
                |entry| !(entry.vm_id == vm_id && entry.entry_gva == entry_gva),
                &mut removed,
            );
            if stack.is_empty() {
                stacks.remove(&cpu);
            }
        }
    }
    removed
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_all_for_test() {
    RETURN_STACKS.lock().clear();
}
