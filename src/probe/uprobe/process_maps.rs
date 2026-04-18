//! Guest Linux userspace process-map state for uprobe matching.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMapMatch {
    pub vm_id: u32,
    pub pid: u32,
    pub tgid: u32,
    pub mm: u64,
    pub comm: String,
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub guest_path: String,
}

impl ProcessMapMatch {
    pub fn runtime_offset(&self, pc: u64) -> u64 {
        self.file_offset + (pc - self.start)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverEvent {
    Exec {
        vm_id: u32,
        pid: u32,
        tgid: u32,
        mm: u64,
        comm: String,
    },
    Mmap {
        vm_id: u32,
        mm: u64,
        start: u64,
        end: u64,
        file_offset: u64,
        guest_path: String,
    },
    Munmap {
        vm_id: u32,
        mm: u64,
        start: u64,
        end: u64,
    },
    ExitMm {
        vm_id: u32,
        mm: u64,
    },
    Exit {
        vm_id: u32,
        pid: u32,
    },
}

#[derive(Debug, Clone)]
struct ProcessState {
    pid: u32,
    tgid: u32,
    comm: String,
    main_text: Option<ProcessMapMatch>,
    mappings: Vec<ProcessMapMatch>,
}

#[derive(Default)]
pub struct ProcessMaps {
    inner: Mutex<BTreeMap<(u32, u64), ProcessState>>,
}

impl ProcessMaps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&self, event: ObserverEvent) {
        let mut inner = self.inner.lock();
        match event {
            ObserverEvent::Exec {
                vm_id,
                pid,
                tgid,
                mm,
                comm,
            } => {
                inner.insert(
                    (vm_id, mm),
                    ProcessState {
                        pid,
                        tgid,
                        comm,
                        main_text: None,
                        mappings: Vec::new(),
                    },
                );
            }
            ObserverEvent::Mmap {
                vm_id,
                mm,
                start,
                end,
                file_offset,
                guest_path,
            } => {
                let Some(state) = inner.get_mut(&(vm_id, mm)) else {
                    return;
                };
                state.mappings.retain(|mapping| {
                    !(mapping.start == start
                        && mapping.end == end
                        && mapping.file_offset == file_offset
                        && mapping.guest_path == guest_path)
                });
                state.mappings.push(ProcessMapMatch {
                    vm_id,
                    pid: state.pid,
                    tgid: state.tgid,
                    mm,
                    comm: state.comm.clone(),
                    start,
                    end,
                    file_offset,
                    guest_path: guest_path.clone(),
                });
                if !guest_path_matches_comm(&guest_path, &state.comm) {
                    return;
                }
                state.main_text = Some(ProcessMapMatch {
                    vm_id,
                    pid: state.pid,
                    tgid: state.tgid,
                    mm,
                    comm: state.comm.clone(),
                    start,
                    end,
                    file_offset,
                    guest_path,
                });
            }
            ObserverEvent::Munmap {
                vm_id,
                mm,
                start,
                end,
            } => {
                let Some(state) = inner.get_mut(&(vm_id, mm)) else {
                    return;
                };
                if state
                    .main_text
                    .as_ref()
                    .is_some_and(|mapping| ranges_overlap(mapping.start, mapping.end, start, end))
                {
                    state.main_text = None;
                }
                state
                    .mappings
                    .retain(|mapping| !ranges_overlap(mapping.start, mapping.end, start, end));
            }
            ObserverEvent::ExitMm { vm_id, mm } => {
                inner.remove(&(vm_id, mm));
            }
            ObserverEvent::Exit { vm_id, pid } => {
                inner
                    .retain(|(event_vm_id, _), state| !(*event_vm_id == vm_id && state.pid == pid));
            }
        }
    }

    pub fn lookup_pc(&self, vm_id: u32, mm: u64, pc: u64) -> Option<ProcessMapMatch> {
        let inner = self.inner.lock();
        let state = inner.get(&(vm_id, mm))?;
        state
            .main_text
            .as_ref()
            .filter(|mapping| mapping.start <= pc && pc < mapping.end)
            .cloned()
    }

    pub fn lookup_main_text(&self, vm_id: u32, mm: u64) -> Option<ProcessMapMatch> {
        let inner = self.inner.lock();
        inner.get(&(vm_id, mm))?.main_text.clone()
    }

    pub fn lookup_mappings_for_path(
        &self,
        vm_id: u32,
        mm: u64,
        guest_path: &str,
    ) -> Vec<ProcessMapMatch> {
        let inner = self.inner.lock();
        let Some(state) = inner.get(&(vm_id, mm)) else {
            return Vec::new();
        };
        state
            .mappings
            .iter()
            .filter(|mapping| mapping.guest_path == guest_path)
            .cloned()
            .collect()
    }
}

fn guest_path_matches_comm(guest_path: &str, comm: &str) -> bool {
    guest_path
        .rsplit('/')
        .next()
        .is_some_and(|basename| basename == comm)
}

fn ranges_overlap(lhs_start: u64, lhs_end: u64, rhs_start: u64, rhs_end: u64) -> bool {
    lhs_start < rhs_end && rhs_start < lhs_end
}
