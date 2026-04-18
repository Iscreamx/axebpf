//! Uprobe registry and shell-facing management helpers.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use super::object;
use super::process_maps::ProcessMaps;
use super::return_stack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UprobeState {
    Pending,
    Active,
}

impl UprobeState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UprobeListEntry {
    pub vm_id: u32,
    pub guest_path: String,
    pub symbol: String,
    pub offset: u64,
    pub pending_reason: Option<String>,
    pub instance_id: u64,
    pub runtime_pc: u64,
    pub load_bias: u64,
    pub mm: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub hits: u64,
    pub prog_id: u32,
    pub is_ret: bool,
    pub state: UprobeState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveUprobeEntry {
    pub binding_id: u64,
    pub instance_id: u64,
    pub vm_id: u32,
    pub guest_path: String,
    pub symbol: String,
    pub offset: u64,
    pub hits: u64,
    pub prog_id: u32,
    pub is_ret: bool,
    pub mm: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub pc: u64,
    pub hva: usize,
    pub saved_insn: u32,
}

#[derive(Debug, Clone)]
struct PendingUprobeEntry {
    vm_id: u32,
    guest_path: String,
    symbol: String,
    offset: u64,
    prog_id: u32,
    is_ret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PendingKey {
    vm_id: u32,
    guest_path: String,
    offset: u64,
    is_ret: bool,
}

#[derive(Debug, Clone)]
struct UprobeBinding {
    id: u64,
    vm_id: u32,
    guest_path: String,
    symbol: String,
    offset: u64,
    prog_id: u32,
    is_ret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InstanceKey {
    vm_id: u32,
    mm: u64,
    guest_path: String,
    start: u64,
    file_offset: u64,
}

#[derive(Debug, Clone)]
struct UprobeInstance {
    id: u64,
    vm_id: u32,
    mm: u64,
    guest_path: String,
    start: u64,
    file_offset: u64,
    pid: u32,
    tgid: u32,
    comm: String,
}

#[derive(Default)]
struct UprobeRegistry {
    next_binding_id: u64,
    next_instance_id: u64,
    bindings: BTreeMap<u64, UprobeBinding>,
    binding_index: BTreeMap<PendingKey, u64>,
    instances: BTreeMap<u64, UprobeInstance>,
    instance_index: BTreeMap<InstanceKey, u64>,
    pending: BTreeMap<PendingKey, PendingUprobeEntry>,
    active: BTreeMap<(u32, u64, u64), ActiveUprobeEntry>,
    armed_exec_barriers: BTreeMap<(u32, u64), ArmedExecBarrier>,
    return_brks: BTreeMap<ReturnBrkKey, ReturnBrkState>,
}

#[derive(Clone, Copy)]
struct PatchResult {
    hva: usize,
    saved_insn: u32,
    gpa: u64,
}

#[derive(Clone, Copy)]
struct ArmedExecBarrier {
    size: u64,
    target_gpa: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReturnBrkKey {
    vm_id: u32,
    return_hva: usize,
}

#[derive(Debug, Clone)]
struct ReturnBrkState {
    return_gva: u64,
    return_hva: usize,
    saved_insn: u32,
    refcount: u32,
    mm_refcounts: BTreeMap<u64, u32>,
}

impl ReturnBrkState {
    fn add_mm_ref(&mut self, mm: u64) {
        let entry = self.mm_refcounts.entry(mm).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    fn remove_mm_ref(&mut self, mm: u64) -> Result<(), &'static str> {
        let Some(count) = self.mm_refcounts.get_mut(&mm) else {
            return Err("return BRK mm refcount not found");
        };
        if *count <= 1 {
            self.mm_refcounts.remove(&mm);
        } else {
            *count -= 1;
        }
        Ok(())
    }

    fn mm_refcount_for(&self, mm: u64) -> Option<u32> {
        self.mm_refcounts.get(&mm).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SharedPatchKey {
    vm_id: u32,
    guest_path: String,
    pc: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecBarrierFaultAction {
    ProbeHitSingleStep { barrier_gpa: u64, barrier_size: u64 },
    RetryInstruction,
    Unhandled,
}

type PatchBackendFn = fn(vm_id: u32, pc: u64) -> Result<PatchResult, &'static str>;
type RestoreBackendFn = fn(hva: usize, saved_insn: u32) -> Result<(), &'static str>;
type ReinjectBackendFn = fn(hva: usize) -> Result<(), &'static str>;

static UPROBES: Mutex<UprobeRegistry> = Mutex::new(UprobeRegistry {
    next_binding_id: 1,
    next_instance_id: 1,
    bindings: BTreeMap::new(),
    binding_index: BTreeMap::new(),
    instances: BTreeMap::new(),
    instance_index: BTreeMap::new(),
    pending: BTreeMap::new(),
    active: BTreeMap::new(),
    armed_exec_barriers: BTreeMap::new(),
    return_brks: BTreeMap::new(),
});
static PATCH_BACKEND: RwLock<Option<PatchBackendFn>> = RwLock::new(None);
static RESTORE_BACKEND: RwLock<Option<RestoreBackendFn>> = RwLock::new(None);
static REINJECT_BACKEND: RwLock<Option<ReinjectBackendFn>> = RwLock::new(None);

#[cfg(any(test, feature = "test-utils"))]
static MOCK_PATCH_RESULT: Mutex<PatchResult> = Mutex::new(PatchResult {
    hva: 0x8000,
    saved_insn: 0x1234_5678,
    gpa: 0,
});

#[cfg(target_arch = "aarch64")]
const GUEST_BRK_INSN: u32 = 0xd4200000;

#[cfg(target_arch = "x86_64")]
const GUEST_BRK_INSN: u32 = 0x000000cc;

pub fn init() {
    #[cfg(feature = "guest-kprobe")]
    crate::probe::kprobe::manager::init();
}

fn parse_offset(symbol_or_offset: &str) -> Option<u64> {
    let token = symbol_or_offset
        .strip_prefix("0x")
        .or_else(|| symbol_or_offset.strip_prefix("0X"))
        .unwrap_or(symbol_or_offset);
    u64::from_str_radix(token, 16).ok()
}

fn resolve_offset(
    vm_id: u32,
    guest_path: &str,
    symbol_or_offset: &str,
) -> Result<u64, &'static str> {
    if let Some(offset) = object::lookup_offset(vm_id, guest_path, symbol_or_offset) {
        return Ok(offset);
    }
    parse_offset(symbol_or_offset).ok_or("guest object metadata not loaded or symbol not found")
}

fn patch_runtime_pc(vm_id: u32, pc: u64) -> Result<PatchResult, &'static str> {
    if let Some(f) = *PATCH_BACKEND.read() {
        return f(vm_id, pc);
    }
    default_patch_runtime_pc(vm_id, pc)
}

fn restore_instruction(hva: usize, saved_insn: u32) -> Result<(), &'static str> {
    if let Some(f) = *RESTORE_BACKEND.read() {
        return f(hva, saved_insn);
    }
    default_restore_instruction(hva, saved_insn)
}

pub fn reinject_breakpoint(hva: usize) -> Result<(), &'static str> {
    if let Some(f) = *REINJECT_BACKEND.read() {
        return f(hva);
    }
    default_reinject_breakpoint(hva)
}

fn default_patch_runtime_pc(vm_id: u32, pc: u64) -> Result<PatchResult, &'static str> {
    #[cfg(all(feature = "guest-kprobe", feature = "axhal"))]
    {
        let gpa = super::addr_translate::gva_to_gpa_user_with_vm(pc, vm_id)
            .map_err(|_| "failed to translate user VA->GPA")?;
        let hpa = crate::probe::kprobe::addr_translate::gpa_to_hpa(gpa, vm_id)
            .map_err(|_| "failed to translate GPA->HPA")?;
        let hpa = usize::try_from(hpa).map_err(|_| "HPA out of range")?;
        let hva = axhal::mem::phys_to_virt(hpa.into()).as_usize();
        let saved_insn = inject_guest_breakpoint(hva)?;
        Ok(PatchResult {
            hva,
            saved_insn,
            gpa,
        })
    }
    #[cfg(not(all(feature = "guest-kprobe", feature = "axhal")))]
    {
        let _ = (vm_id, pc);
        Err("runtime patch backend requires guest-kprobe + axhal")
    }
}

fn default_restore_instruction(hva: usize, saved_insn: u32) -> Result<(), &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { core::ptr::write_volatile(hva as *mut u32, saved_insn) };
        crate::cache::flush_icache_range(hva, hva + core::mem::size_of::<u32>());
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::ptr::write_volatile(hva as *mut u8, saved_insn as u8) };
        Ok(())
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (hva, saved_insn);
        Err("instruction restore is not supported on this architecture")
    }
}

fn default_reinject_breakpoint(hva: usize) -> Result<(), &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { core::ptr::write_volatile(hva as *mut u32, GUEST_BRK_INSN) };
        crate::cache::flush_icache_range(hva, hva + core::mem::size_of::<u32>());
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::ptr::write_volatile(hva as *mut u8, GUEST_BRK_INSN as u8) };
        Ok(())
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = hva;
        Err("instruction reinject is not supported on this architecture")
    }
}

fn find_shared_patch_for_runtime_pc(
    probes: &UprobeRegistry,
    vm_id: u32,
    guest_path: &str,
    pc: u64,
) -> Option<(usize, u32)> {
    probes
        .active
        .values()
        .find(|entry| entry.vm_id == vm_id && entry.guest_path == guest_path && entry.pc == pc)
        .map(|entry| (entry.hva, entry.saved_insn))
}

fn shared_patch_key(entry: &ActiveUprobeEntry) -> SharedPatchKey {
    SharedPatchKey {
        vm_id: entry.vm_id,
        guest_path: entry.guest_path.clone(),
        pc: entry.pc,
    }
}

fn collect_restore_sites_for_active_keys(
    probes: &UprobeRegistry,
    active_keys: &[(u32, u64, u64)],
) -> Vec<(usize, u32)> {
    let removal_keys: BTreeSet<_> = active_keys.iter().copied().collect();
    let mut restore_sites = BTreeMap::<SharedPatchKey, (usize, u32)>::new();

    for key in active_keys {
        let Some(entry) = probes.active.get(key) else {
            continue;
        };
        let has_remaining_shared_patch = probes.active.iter().any(|(other_key, other_entry)| {
            !removal_keys.contains(other_key)
                && other_entry.vm_id == entry.vm_id
                && other_entry.guest_path == entry.guest_path
                && other_entry.pc == entry.pc
        });
        if has_remaining_shared_patch {
            continue;
        }
        restore_sites
            .entry(shared_patch_key(entry))
            .or_insert((entry.hva, entry.saved_insn));
    }

    restore_sites.into_values().collect()
}

fn ensure_instance(
    probes: &mut UprobeRegistry,
    vm_id: u32,
    mm: u64,
    guest_path: &str,
    start: u64,
    file_offset: u64,
    pid: u32,
    tgid: u32,
    comm: &str,
) -> u64 {
    let key = InstanceKey {
        vm_id,
        mm,
        guest_path: guest_path.to_string(),
        start,
        file_offset,
    };
    if let Some(id) = probes.instance_index.get(&key).copied() {
        if let Some(instance) = probes.instances.get_mut(&id) {
            instance.pid = pid;
            instance.tgid = tgid;
            instance.comm = comm.to_string();
        }
        return id;
    }
    let id = probes.next_instance_id;
    probes.next_instance_id = probes.next_instance_id.saturating_add(1);
    probes.instances.insert(
        id,
        UprobeInstance {
            id,
            vm_id,
            mm,
            guest_path: guest_path.to_string(),
            start,
            file_offset,
            pid,
            tgid,
            comm: comm.to_string(),
        },
    );
    probes.instance_index.insert(key, id);
    id
}

fn prune_instances_without_active(probes: &mut UprobeRegistry) {
    let active_instance_ids: BTreeSet<u64> = probes
        .active
        .values()
        .map(|entry| entry.instance_id)
        .collect();
    probes
        .instances
        .retain(|instance_id, _| active_instance_ids.contains(instance_id));
    probes
        .instance_index
        .retain(|_, instance_id| active_instance_ids.contains(instance_id));
}

#[cfg(all(feature = "guest-kprobe", feature = "axhal"))]
fn inject_guest_breakpoint(hva: usize) -> Result<u32, &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        let saved = unsafe { core::ptr::read_volatile(hva as *const u32) };
        unsafe { core::ptr::write_volatile(hva as *mut u32, GUEST_BRK_INSN) };
        crate::cache::flush_icache_range(hva, hva + core::mem::size_of::<u32>());
        Ok(saved)
    }
    #[cfg(target_arch = "x86_64")]
    {
        let saved = unsafe { core::ptr::read_volatile(hva as *const u8) };
        unsafe { core::ptr::write_volatile(hva as *mut u8, GUEST_BRK_INSN as u8) };
        Ok(saved as u32)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = hva;
        Err("BRK injection is not supported on this architecture")
    }
}

pub fn attach_symbol(
    vm_id: u32,
    guest_path: &str,
    symbol_or_offset: &str,
    prog_id: u32,
    is_ret: bool,
) -> Result<(), &'static str> {
    let offset = resolve_offset(vm_id, guest_path, symbol_or_offset)?;
    let key = PendingKey {
        vm_id,
        guest_path: guest_path.to_string(),
        offset,
        is_ret,
    };

    let mut probes = UPROBES.lock();
    if probes.bindings.values().any(|entry| {
        entry.vm_id == vm_id && entry.guest_path == guest_path && entry.offset == offset
    }) {
        return Err("duplicate uprobe registration");
    }

    let binding_id = probes.next_binding_id;
    probes.next_binding_id = probes.next_binding_id.saturating_add(1);
    probes.bindings.insert(
        binding_id,
        UprobeBinding {
            id: binding_id,
            vm_id,
            guest_path: guest_path.to_string(),
            symbol: symbol_or_offset.to_string(),
            offset,
            prog_id,
            is_ret,
        },
    );
    probes.binding_index.insert(key.clone(), binding_id);
    probes.pending.insert(
        key,
        PendingUprobeEntry {
            vm_id,
            guest_path: guest_path.to_string(),
            symbol: symbol_or_offset.to_string(),
            offset,
            prog_id,
            is_ret,
        },
    );
    Ok(())
}

pub fn detach(vm_id: u32, guest_path: &str, symbol_or_offset: &str) -> Result<(), &'static str> {
    let offset = resolve_offset(vm_id, guest_path, symbol_or_offset)?;
    let mut probes = UPROBES.lock();
    let mut removed_any = false;
    let mut cleared_return_entries = Vec::new();

    let pending_keys: Vec<_> = probes
        .pending
        .keys()
        .filter(|key| key.vm_id == vm_id && key.guest_path == guest_path && key.offset == offset)
        .cloned()
        .collect();
    for key in pending_keys {
        if let Some(binding_id) = probes.binding_index.remove(&key) {
            probes.bindings.remove(&binding_id);
        }
        removed_any |= probes.pending.remove(&key).is_some();
    }

    let binding_ids_to_remove: Vec<_> = probes
        .bindings
        .iter()
        .filter_map(|(binding_id, binding)| {
            (binding.vm_id == vm_id && binding.guest_path == guest_path && binding.offset == offset)
                .then_some(*binding_id)
        })
        .collect();
    for binding_id in binding_ids_to_remove {
        if let Some(binding) = probes.bindings.remove(&binding_id) {
            probes.binding_index.remove(&PendingKey {
                vm_id: binding.vm_id,
                guest_path: binding.guest_path,
                offset: binding.offset,
                is_ret: binding.is_ret,
            });
            removed_any = true;
        }
    }

    let active_keys: Vec<_> = probes
        .active
        .iter()
        .filter_map(|(key, entry)| {
            (entry.vm_id == vm_id && entry.guest_path == guest_path && entry.offset == offset)
                .then_some(*key)
        })
        .collect();
    let restore_sites = collect_restore_sites_for_active_keys(&probes, &active_keys);

    for key in &active_keys {
        if let Some(entry) = probes.active.get(key) {
            if entry.is_ret {
                cleared_return_entries.extend(return_stack::clear_for_instance(
                    entry.vm_id,
                    entry.instance_id,
                ));
            }
        }
    }
    for (hva, saved_insn) in &restore_sites {
        restore_instruction(*hva, *saved_insn)?;
    }
    for key in active_keys {
        removed_any |= probes.active.remove(&key).is_some();
    }
    prune_instances_without_active(&mut probes);
    drop(probes);

    release_cleared_return_entries(cleared_return_entries);

    if removed_any {
        return Ok(());
    }

    Err("uprobe not found")
}

pub fn list_all() -> Vec<UprobeListEntry> {
    let probes = UPROBES.lock();
    let mut entries: Vec<_> = probes
        .pending
        .values()
        .map(|entry| UprobeListEntry {
            vm_id: entry.vm_id,
            guest_path: entry.guest_path.clone(),
            symbol: entry.symbol.clone(),
            offset: entry.offset,
            pending_reason: Some("waiting-for-instance".into()),
            instance_id: 0,
            runtime_pc: 0,
            load_bias: 0,
            mm: 0,
            pid: 0,
            tgid: 0,
            comm: String::new(),
            hits: 0,
            prog_id: entry.prog_id,
            is_ret: entry.is_ret,
            state: UprobeState::Pending,
        })
        .collect();

    entries.extend(probes.active.values().map(|entry| UprobeListEntry {
        vm_id: entry.vm_id,
        guest_path: entry.guest_path.clone(),
        symbol: entry.symbol.clone(),
        offset: entry.offset,
        pending_reason: None,
        instance_id: entry.instance_id,
        runtime_pc: entry.pc,
        load_bias: entry.pc.checked_sub(entry.offset).unwrap_or(0),
        mm: entry.mm,
        pid: entry.pid,
        tgid: entry.tgid,
        comm: entry.comm.clone(),
        hits: entry.hits,
        prog_id: entry.prog_id,
        is_ret: entry.is_ret,
        state: UprobeState::Active,
    }));

    entries.sort_by(|lhs, rhs| {
        (
            lhs.vm_id,
            lhs.guest_path.as_str(),
            lhs.offset,
            lhs.mm,
            lhs.is_ret,
            lhs.state.label(),
        )
            .cmp(&(
                rhs.vm_id,
                rhs.guest_path.as_str(),
                rhs.offset,
                rhs.mm,
                rhs.is_ret,
                rhs.state.label(),
            ))
    });
    entries
}

pub fn has_pending_path(vm_id: u32, guest_path: &str) -> bool {
    UPROBES
        .lock()
        .bindings
        .values()
        .any(|entry| entry.vm_id == vm_id && entry.guest_path == guest_path)
}

pub fn lookup_active(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    UPROBES
        .lock()
        .active
        .values()
        .find(|entry| entry.vm_id == vm_id && entry.pc == pc)
        .cloned()
}

pub fn lookup_active_for_mm(vm_id: u32, mm: u64, pc: u64) -> Option<ActiveUprobeEntry> {
    UPROBES.lock().active.get(&(vm_id, mm, pc)).cloned()
}

pub fn increment_active_hits(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    let mut probes = UPROBES.lock();
    let key = probes
        .active
        .iter()
        .find_map(|(key, entry)| (entry.vm_id == vm_id && entry.pc == pc).then_some(*key))?;
    let entry = probes.active.get_mut(&key)?;
    entry.hits = entry.hits.saturating_add(1);
    Some(entry.clone())
}

pub fn increment_active_hits_for_mm(vm_id: u32, mm: u64, pc: u64) -> Option<ActiveUprobeEntry> {
    let mut probes = UPROBES.lock();
    let entry = probes.active.get_mut(&(vm_id, mm, pc))?;
    entry.hits = entry.hits.saturating_add(1);
    Some(entry.clone())
}

pub fn remove_active(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    let mut probes = UPROBES.lock();
    let key = probes
        .active
        .iter()
        .find_map(|(key, entry)| (entry.vm_id == vm_id && entry.pc == pc).then_some(*key))?;
    let removed = probes.active.remove(&key);
    prune_instances_without_active(&mut probes);
    removed
}

pub fn remove_active_for_mm(vm_id: u32, mm: u64, pc: u64) -> Option<ActiveUprobeEntry> {
    let mut probes = UPROBES.lock();
    let removed = probes.active.remove(&(vm_id, mm, pc));
    prune_instances_without_active(&mut probes);
    removed
}

pub fn disable_active(vm_id: u32, pc: u64) -> Result<(), &'static str> {
    let mut probes = UPROBES.lock();
    let Some(key) = probes
        .active
        .iter()
        .find_map(|(key, entry)| (entry.vm_id == vm_id && entry.pc == pc).then_some(*key))
    else {
        return Err("active uprobe not found");
    };
    let Some(entry) = probes.active.remove(&key) else {
        return Err("active uprobe not found");
    };
    let has_remaining_shared_patch = probes.active.values().any(|other| {
        other.vm_id == entry.vm_id && other.guest_path == entry.guest_path && other.pc == entry.pc
    });
    if !has_remaining_shared_patch {
        restore_instruction(entry.hva, entry.saved_insn)?;
    }
    let cleared_return_entries = if entry.is_ret {
        return_stack::clear_for_instance(entry.vm_id, entry.instance_id)
    } else {
        Vec::new()
    };
    prune_instances_without_active(&mut probes);
    drop(probes);
    release_cleared_return_entries(cleared_return_entries);
    Ok(())
}

fn release_cleared_return_entries(entries: Vec<return_stack::ReturnEntry>) {
    for entry in entries {
        match release_return_brk(entry.vm_id, entry.mm, entry.return_gva) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(err) = restore_instruction(entry.return_hva, entry.saved_insn) {
                    log::warn!(
                        "guest_uretprobe: cleanup return BRK vm{} mm={:#x} pc={:#x} failed: {}",
                        entry.vm_id,
                        entry.mm,
                        entry.return_gva,
                        err
                    );
                }
            }
            Err(err) => {
                log::warn!(
                    "guest_uretprobe: release return BRK vm{} mm={:#x} pc={:#x} failed: {}",
                    entry.vm_id,
                    entry.mm,
                    entry.return_gva,
                    err
                );
            }
        }
    }
}

fn cleanup_remaining_return_brks_for_mm(vm_id: u32, mm: u64) {
    let states: Vec<_> = {
        let probes = UPROBES.lock();
        probes
            .return_brks
            .iter()
            .filter_map(|(key, state)| {
                (key.vm_id == vm_id)
                    .then(|| {
                        state.mm_refcount_for(mm).map(|count| {
                            (state.return_gva, state.return_hva, state.saved_insn, count)
                        })
                    })
                    .flatten()
            })
            .collect()
    };

    for (return_gva, return_hva, saved_insn, count) in states {
        for _ in 0..count {
            match release_return_brk(vm_id, mm, return_gva) {
                Ok(true) => {}
                Ok(false) => {
                    if let Err(err) = restore_instruction(return_hva, saved_insn) {
                        log::warn!(
                            "guest_uretprobe: cleanup return BRK vm{} mm={:#x} pc={:#x} failed: {}",
                            vm_id,
                            mm,
                            return_gva,
                            err
                        );
                    }
                    break;
                }
                Err(err) => {
                    log::warn!(
                        "guest_uretprobe: cleanup return BRK vm{} mm={:#x} pc={:#x} failed: {}",
                        vm_id,
                        mm,
                        return_gva,
                        err
                    );
                    break;
                }
            }
        }
    }
}

pub fn cleanup_mm(vm_id: u32, mm: u64) -> Result<(), &'static str> {
    let mut probes = UPROBES.lock();
    let active_keys: Vec<_> = probes
        .active
        .iter()
        .filter_map(|(key, entry)| (entry.vm_id == vm_id && entry.mm == mm).then_some(*key))
        .collect();
    let restore_sites = collect_restore_sites_for_active_keys(&probes, &active_keys);

    for key in &active_keys {
        if let Some(entry) = probes.active.get(key) {
            log::info!(
                "guest_uprobe_deactivate_mm: vm{} mm={:#x} path={} symbol={} pc={:#x}",
                entry.vm_id,
                entry.mm,
                entry.guest_path,
                entry.symbol,
                entry.pc
            );
        }
    }
    for (hva, saved_insn) in &restore_sites {
        restore_instruction(*hva, *saved_insn)?;
    }

    for key in active_keys {
        probes.active.remove(&key);
    }
    prune_instances_without_active(&mut probes);
    drop(probes);

    release_cleared_return_entries(return_stack::clear_for_mm(vm_id, mm));
    cleanup_remaining_return_brks_for_mm(vm_id, mm);
    Ok(())
}

pub fn cleanup_range(vm_id: u32, mm: u64, start: u64, end: u64) -> Result<(), &'static str> {
    let mut probes = UPROBES.lock();
    let active_keys: Vec<_> = probes
        .active
        .iter()
        .filter_map(|(key, entry)| {
            (entry.vm_id == vm_id && entry.mm == mm && start <= entry.pc && entry.pc < end)
                .then_some(*key)
        })
        .collect();
    let restore_sites = collect_restore_sites_for_active_keys(&probes, &active_keys);
    let mut cleared_return_entries = Vec::new();

    for key in &active_keys {
        if let Some(entry) = probes.active.get(key) {
            if entry.is_ret {
                cleared_return_entries.extend(return_stack::clear_for_instance(
                    entry.vm_id,
                    entry.instance_id,
                ));
            }
        }
    }

    for (hva, saved_insn) in &restore_sites {
        restore_instruction(*hva, *saved_insn)?;
    }

    for key in active_keys {
        probes.active.remove(&key);
    }
    prune_instances_without_active(&mut probes);
    drop(probes);

    release_cleared_return_entries(cleared_return_entries);
    Ok(())
}

pub fn cleanup_pid(vm_id: u32, pid: u32) -> Result<(), &'static str> {
    let mut probes = UPROBES.lock();
    let active_keys: Vec<_> = probes
        .active
        .iter()
        .filter_map(|(key, entry)| (entry.vm_id == vm_id && entry.pid == pid).then_some(*key))
        .collect();
    let restore_sites = collect_restore_sites_for_active_keys(&probes, &active_keys);

    for (hva, saved_insn) in &restore_sites {
        restore_instruction(*hva, *saved_insn)?;
    }

    for key in active_keys {
        probes.active.remove(&key);
    }
    prune_instances_without_active(&mut probes);
    drop(probes);

    release_cleared_return_entries(return_stack::clear_for_pid(vm_id, pid));
    Ok(())
}

pub fn acquire_return_brk(
    vm_id: u32,
    mm: u64,
    return_gva: u64,
) -> Result<(usize, u32, u32), &'static str> {
    let patch = patch_runtime_pc(vm_id, return_gva)?;
    let key = ReturnBrkKey {
        vm_id,
        return_hva: patch.hva,
    };

    let mut probes = UPROBES.lock();
    if let Some(state) = probes.return_brks.get_mut(&key) {
        state.add_mm_ref(mm);
        state.refcount = state.refcount.saturating_add(1);
        return Ok((state.return_hva, state.saved_insn, state.refcount));
    }
    probes.return_brks.insert(
        key,
        ReturnBrkState {
            return_gva,
            return_hva: patch.hva,
            saved_insn: patch.saved_insn,
            refcount: 1,
            mm_refcounts: BTreeMap::new(),
        },
    );
    if let Some(state) = probes.return_brks.get_mut(&key) {
        state.add_mm_ref(mm);
    }
    Ok((patch.hva, patch.saved_insn, 1))
}

pub fn release_return_brk(vm_id: u32, mm: u64, return_gva: u64) -> Result<bool, &'static str> {
    let mut probes = UPROBES.lock();
    let key = probes
        .return_brks
        .iter()
        .find_map(|(key, state)| {
            (key.vm_id == vm_id
                && state.return_gva == return_gva
                && state.mm_refcount_for(mm).is_some())
            .then_some(*key)
        })
        .ok_or("return BRK not found")?;
    let state = probes
        .return_brks
        .get_mut(&key)
        .ok_or("return BRK not found")?;
    state.remove_mm_ref(mm)?;
    if state.refcount <= 1 {
        probes.return_brks.remove(&key);
        return Ok(false);
    }
    state.refcount -= 1;
    Ok(true)
}

pub fn cleanup_return_brk(vm_id: u32, mm: u64, return_gva: u64) -> Result<(), &'static str> {
    let state = {
        let probes = UPROBES.lock();
        probes.return_brks.iter().find_map(|(key, state)| {
            (key.vm_id == vm_id
                && state.return_gva == return_gva
                && state.mm_refcount_for(mm).is_some())
            .then_some((
                state.return_hva,
                state.saved_insn,
                state.mm_refcount_for(mm).unwrap_or(0),
            ))
        })
    };
    let Some((return_hva, saved_insn, count)) = state else {
        return Ok(());
    };
    for _ in 0..count {
        if !release_return_brk(vm_id, mm, return_gva)? {
            restore_instruction(return_hva, saved_insn)?;
            break;
        }
    }
    Ok(())
}

fn activate_for_mapping(
    vm_id: u32,
    guest_path: &str,
    mm: u64,
    start: u64,
    end: Option<u64>,
    file_offset: u64,
    pid: u32,
    tgid: u32,
    comm: &str,
) -> Result<usize, &'static str> {
    let candidates: Vec<_> = {
        let probes = UPROBES.lock();
        probes
            .pending
            .iter()
            .filter(|(key, _)| key.vm_id == vm_id && key.guest_path == guest_path)
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect()
    };

    let mut activated = 0usize;
    for (key, pending) in candidates {
        let runtime_pc = match object::resolve_runtime_pc_for_mapping(
            vm_id,
            guest_path,
            pending.offset,
            start,
            end,
            file_offset,
        ) {
            Ok(runtime_pc) => runtime_pc,
            Err(err) => {
                log::debug!(
                    "guest_uprobe: skip activation vm{}:{}+{:#x} for mapping [{:#x}, {:?}) off={:#x}: {}",
                    vm_id,
                    guest_path,
                    pending.offset,
                    start,
                    end,
                    file_offset,
                    err
                );
                continue;
            }
        };

        {
            let probes = UPROBES.lock();
            if probes.active.contains_key(&(vm_id, mm, runtime_pc)) {
                continue;
            }
        }

        let shared_patch = {
            let probes = UPROBES.lock();
            find_shared_patch_for_runtime_pc(&probes, vm_id, guest_path, runtime_pc)
        };
        let (hva, saved_insn, patched_gpa) = if let Some((hva, saved_insn)) = shared_patch {
            (hva, saved_insn, None)
        } else {
            let patch = match patch_runtime_pc(vm_id, runtime_pc) {
                Ok(patch) => patch,
                Err(err) => {
                    log::warn!(
                        "guest_uprobe: activate pending vm{}:{}+{:#x} failed: {}",
                        vm_id,
                        guest_path,
                        pending.offset,
                        err
                    );
                    continue;
                }
            };
            (patch.hva, patch.saved_insn, Some(patch.gpa))
        };

        {
            let mut probes = UPROBES.lock();
            if !probes.pending.contains_key(&key)
                || probes.active.contains_key(&(vm_id, mm, runtime_pc))
            {
                continue;
            }
            let Some(binding_id) = probes.binding_index.get(&key).copied() else {
                continue;
            };
            let instance_id = ensure_instance(
                &mut probes,
                vm_id,
                mm,
                guest_path,
                start,
                file_offset,
                pid,
                tgid,
                comm,
            );
            probes.active.insert(
                (vm_id, mm, runtime_pc),
                ActiveUprobeEntry {
                    binding_id,
                    instance_id,
                    vm_id,
                    guest_path: pending.guest_path,
                    symbol: pending.symbol,
                    offset: pending.offset,
                    hits: 0,
                    prog_id: pending.prog_id,
                    is_ret: pending.is_ret,
                    mm,
                    pid,
                    tgid,
                    comm: comm.to_string(),
                    pc: runtime_pc,
                    hva,
                    saved_insn,
                },
            );
        }
        if let Some(gpa) = patched_gpa {
            arm_exec_barrier(vm_id, gpa);
            #[cfg(all(target_arch = "aarch64", not(any(test, feature = "test-utils"))))]
            let patched_insn = unsafe { core::ptr::read_volatile(hva as *const u32) };
            #[cfg(all(target_arch = "x86_64", not(any(test, feature = "test-utils"))))]
            let patched_insn = unsafe { core::ptr::read_volatile(hva as *const u8) as u32 };
            #[cfg(any(test, feature = "test-utils"))]
            let patched_insn = GUEST_BRK_INSN;
            log::info!(
                "guest_uprobe: BRK patch vm{}:{} runtime_pc={:#x} hva={:#x} saved_insn={:#010x} patched_insn={:#010x}",
                vm_id,
                guest_path,
                runtime_pc,
                hva,
                saved_insn,
                patched_insn
            );
        } else {
            log::info!(
                "guest_uprobe: BRK reuse vm{}:{} runtime_pc={:#x} hva={:#x} saved_insn={:#010x}",
                vm_id,
                guest_path,
                runtime_pc,
                hva,
                saved_insn
            );
        }
        activated += 1;
    }

    Ok(activated)
}

fn arm_exec_barrier(vm_id: u32, gpa: u64) {
    if gpa == 0 {
        return;
    }

    #[cfg(feature = "guest-kprobe")]
    {
        let (barrier_gpa, barrier_size) =
            crate::probe::kprobe::manager::query_step_barrier(vm_id, gpa);
        if UPROBES
            .lock()
            .armed_exec_barriers
            .contains_key(&(vm_id, barrier_gpa))
        {
            return;
        }
        if let Err(err) =
            crate::probe::kprobe::manager::set_stage2_executable(vm_id, barrier_gpa, false)
        {
            log::warn!(
                "guest_uprobe: failed to arm Stage-2 exec barrier vm{} gpa={:#x} size={:#x}: {}",
                vm_id,
                barrier_gpa,
                barrier_size,
                err
            );
            return;
        }
        UPROBES.lock().armed_exec_barriers.insert(
            (vm_id, barrier_gpa),
            ArmedExecBarrier {
                size: barrier_size,
                target_gpa: gpa,
            },
        );
        log::info!(
            "guest_uprobe: Stage-2 exec barrier armed vm{} gpa={:#x} size={:#x}",
            vm_id,
            barrier_gpa,
            barrier_size
        );
    }
}

pub(crate) fn handle_exec_barrier_fault(
    vm_id: u32,
    fault_gpa: u64,
) -> Result<ExecBarrierFaultAction, &'static str> {
    #[cfg(feature = "guest-kprobe")]
    {
        let barrier = {
            let probes = UPROBES.lock();
            probes
                .armed_exec_barriers
                .iter()
                .find_map(|(&(entry_vm_id, barrier_gpa), barrier)| {
                    (entry_vm_id == vm_id
                        && (barrier_gpa..barrier_gpa.saturating_add(barrier.size))
                            .contains(&fault_gpa))
                    .then_some((barrier_gpa, *barrier))
                })
        };

        let Some((barrier_gpa, barrier)) = barrier else {
            return Ok(ExecBarrierFaultAction::Unhandled);
        };

        if fault_gpa == barrier.target_gpa {
            UPROBES
                .lock()
                .armed_exec_barriers
                .remove(&(vm_id, barrier_gpa));
            if let Err(err) =
                crate::probe::kprobe::manager::set_stage2_executable(vm_id, barrier_gpa, true)
            {
                UPROBES
                    .lock()
                    .armed_exec_barriers
                    .insert((vm_id, barrier_gpa), barrier);
                return Err(err);
            }

            log::info!(
                "guest_uprobe: Stage-2 exec barrier released vm{} gpa={:#x} size={:#x} fault_gpa={:#x}",
                vm_id,
                barrier_gpa,
                barrier.size,
                fault_gpa
            );
            return Ok(ExecBarrierFaultAction::RetryInstruction);
        }

        crate::probe::kprobe::manager::set_stage2_executable(vm_id, barrier_gpa, true)?;
        log::debug!(
            "guest_uprobe: Stage-2 exec barrier single-step vm{} gpa={:#x} size={:#x} target_gpa={:#x} fault_gpa={:#x}",
            vm_id,
            barrier_gpa,
            barrier.size,
            barrier.target_gpa,
            fault_gpa
        );
        Ok(ExecBarrierFaultAction::ProbeHitSingleStep {
            barrier_gpa,
            barrier_size: barrier.size,
        })
    }

    #[cfg(not(feature = "guest-kprobe"))]
    {
        let _ = (vm_id, fault_gpa);
        Ok(ExecBarrierFaultAction::Unhandled)
    }
}

pub(crate) fn rearm_exec_barrier_after_step(
    vm_id: u32,
    barrier_gpa: u64,
) -> Result<bool, &'static str> {
    #[cfg(feature = "guest-kprobe")]
    {
        let barrier_size = UPROBES
            .lock()
            .armed_exec_barriers
            .get(&(vm_id, barrier_gpa))
            .map(|barrier| barrier.size);
        let Some(barrier_size) = barrier_size else {
            return Ok(false);
        };

        crate::probe::kprobe::manager::set_stage2_executable(vm_id, barrier_gpa, false)?;
        log::debug!(
            "guest_uprobe: Stage-2 exec barrier rearmed vm{} gpa={:#x} size={:#x}",
            vm_id,
            barrier_gpa,
            barrier_size
        );
        Ok(true)
    }

    #[cfg(not(feature = "guest-kprobe"))]
    {
        let _ = (vm_id, barrier_gpa);
        Ok(false)
    }
}

pub fn try_activate_for_mm(maps: &ProcessMaps, vm_id: u32, mm: u64) -> Result<usize, &'static str> {
    let paths: BTreeSet<String> = {
        let probes = UPROBES.lock();
        probes
            .bindings
            .values()
            .filter(|binding| binding.vm_id == vm_id)
            .map(|binding| binding.guest_path.clone())
            .collect()
    };
    if paths.is_empty() {
        return Ok(0);
    }

    let mut activated = 0usize;
    for path in paths {
        let mappings = maps.lookup_mappings_for_path(vm_id, mm, &path);
        for mapping in mappings {
            activated = activated.saturating_add(activate_for_mapping(
                vm_id,
                &mapping.guest_path,
                mapping.mm,
                mapping.start,
                Some(mapping.end),
                mapping.file_offset,
                mapping.pid,
                mapping.tgid,
                &mapping.comm,
            )?);
        }
    }
    Ok(activated)
}

pub fn restore_instruction_for_step(hva: usize, saved_insn: u32) -> Result<(), &'static str> {
    restore_instruction(hva, saved_insn)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn install_mock_patch_backend_for_test() {
    *PATCH_BACKEND.write() = Some(mock_patch_runtime_pc);
    *RESTORE_BACKEND.write() = Some(mock_restore_instruction);
    *REINJECT_BACKEND.write() = Some(mock_reinject_breakpoint);
}

#[cfg(any(test, feature = "test-utils"))]
fn mock_patch_runtime_pc(_vm_id: u32, _pc: u64) -> Result<PatchResult, &'static str> {
    Ok(*MOCK_PATCH_RESULT.lock())
}

#[cfg(any(test, feature = "test-utils"))]
fn mock_restore_instruction(_hva: usize, _saved_insn: u32) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(any(test, feature = "test-utils"))]
fn mock_reinject_breakpoint(_hva: usize) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(any(test, feature = "test-utils"))]
pub fn activate_for_mapping_for_test(
    vm_id: u32,
    guest_path: &str,
    mm: u64,
    start: u64,
    file_offset: u64,
    hva: usize,
    saved_insn: u32,
) -> Result<usize, &'static str> {
    let gpa = MOCK_PATCH_RESULT.lock().gpa;
    *MOCK_PATCH_RESULT.lock() = PatchResult {
        hva,
        saved_insn,
        gpa,
    };
    activate_for_mapping(vm_id, guest_path, mm, start, None, file_offset, 0, 0, "")
}

#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_active_for_test(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    lookup_active(vm_id, pc)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_active_for_mm_for_test(vm_id: u32, mm: u64, pc: u64) -> Option<ActiveUprobeEntry> {
    UPROBES.lock().active.get(&(vm_id, mm, pc)).cloned()
}

#[cfg(any(test, feature = "test-utils"))]
pub fn binding_count_for_test(vm_id: u32) -> usize {
    UPROBES
        .lock()
        .bindings
        .values()
        .filter(|binding| binding.vm_id == vm_id)
        .count()
}

#[cfg(any(test, feature = "test-utils"))]
pub fn instance_count_for_test(vm_id: u32) -> usize {
    UPROBES
        .lock()
        .instances
        .values()
        .filter(|instance| instance.vm_id == vm_id)
        .count()
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnBrkStateForTest {
    pub return_hva: usize,
    pub saved_insn: u32,
    pub refcount: u32,
}

#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_return_brk_for_test(
    vm_id: u32,
    mm: u64,
    return_gva: u64,
) -> Option<ReturnBrkStateForTest> {
    UPROBES.lock().return_brks.iter().find_map(|(key, state)| {
        (key.vm_id == vm_id
            && state.return_gva == return_gva
            && state.mm_refcount_for(mm).is_some())
        .then_some(ReturnBrkStateForTest {
            return_hva: state.return_hva,
            saved_insn: state.saved_insn,
            refcount: state.refcount,
        })
    })
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_return_brks_for_test() {
    UPROBES.lock().return_brks.clear();
}

#[cfg(any(test, feature = "test-utils"))]
pub fn set_mock_patch_result_for_test(hva: usize, saved_insn: u32, gpa: u64) {
    *MOCK_PATCH_RESULT.lock() = PatchResult {
        hva,
        saved_insn,
        gpa,
    };
}

#[cfg(any(test, feature = "test-utils"))]
pub fn has_armed_exec_barrier_for_test(vm_id: u32, fault_gpa: u64) -> bool {
    UPROBES
        .lock()
        .armed_exec_barriers
        .iter()
        .any(|(&(entry_vm_id, barrier_gpa), barrier)| {
            entry_vm_id == vm_id
                && (barrier_gpa..barrier_gpa.saturating_add(barrier.size)).contains(&fault_gpa)
        })
}

#[cfg(any(test, feature = "test-utils"))]
pub fn install_mock_active_probe_for_test(
    vm_id: u32,
    pc: u64,
    hva: usize,
    saved_insn: u32,
    prog_id: u32,
    is_ret: bool,
) {
    *RESTORE_BACKEND.write() = Some(mock_restore_instruction);
    *REINJECT_BACKEND.write() = Some(mock_reinject_breakpoint);
    let mut probes = UPROBES.lock();
    probes.active.insert(
        (vm_id, 0x1000, pc),
        ActiveUprobeEntry {
            binding_id: 0,
            instance_id: 0,
            vm_id,
            guest_path: "/mock".to_string(),
            symbol: "mock".to_string(),
            offset: 0,
            hits: 0,
            prog_id,
            is_ret,
            mm: 0x1000,
            pid: 0,
            tgid: 0,
            comm: String::new(),
            pc,
            hva,
            saved_insn,
        },
    );
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_all_for_test() {
    let mut probes = UPROBES.lock();
    probes.next_binding_id = 1;
    probes.next_instance_id = 1;
    probes.bindings.clear();
    probes.binding_index.clear();
    probes.instances.clear();
    probes.instance_index.clear();
    probes.pending.clear();
    probes.active.clear();
    probes.armed_exec_barriers.clear();
    probes.return_brks.clear();
    *PATCH_BACKEND.write() = None;
    *RESTORE_BACKEND.write() = None;
    *REINJECT_BACKEND.write() = None;
    #[cfg(any(test, feature = "test-utils"))]
    {
        *MOCK_PATCH_RESULT.lock() = PatchResult {
            hva: 0x8000,
            saved_insn: 0x1234_5678,
            gpa: 0,
        };
    }
}
