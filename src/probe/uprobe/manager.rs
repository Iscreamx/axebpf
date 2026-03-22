//! Uprobe registry and shell-facing management helpers.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use super::object;
use super::process_maps::ProcessMaps;

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
    pub hits: u64,
    pub prog_id: u32,
    pub is_ret: bool,
    pub state: UprobeState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveUprobeEntry {
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

#[derive(Default)]
struct UprobeRegistry {
    pending: BTreeMap<PendingKey, PendingUprobeEntry>,
    active: BTreeMap<(u32, u64), ActiveUprobeEntry>,
    armed_exec_barriers: BTreeMap<(u32, u64), ArmedExecBarrier>,
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
    pending: BTreeMap::new(),
    active: BTreeMap::new(),
    armed_exec_barriers: BTreeMap::new(),
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
    if probes.pending.contains_key(&key)
        || probes.active.values().any(|entry| {
            entry.vm_id == vm_id
                && entry.guest_path == guest_path
                && entry.offset == offset
                && entry.is_ret == is_ret
        })
    {
        return Err("duplicate uprobe registration");
    }

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

    let pending_keys: Vec<_> = probes
        .pending
        .keys()
        .filter(|key| key.vm_id == vm_id && key.guest_path == guest_path && key.offset == offset)
        .cloned()
        .collect();
    for key in pending_keys {
        removed_any |= probes.pending.remove(&key).is_some();
    }

    let active_keys: Vec<_> = probes
        .active
        .iter()
        .filter_map(|(key, entry)| {
            (entry.vm_id == vm_id && entry.guest_path == guest_path && entry.offset == offset)
                .then_some(*key)
        })
        .collect();

    for key in &active_keys {
        if let Some(entry) = probes.active.get(key) {
            restore_instruction(entry.hva, entry.saved_insn)?;
        }
    }
    for key in active_keys {
        removed_any |= probes.active.remove(&key).is_some();
    }

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
        hits: entry.hits,
        prog_id: entry.prog_id,
        is_ret: entry.is_ret,
        state: UprobeState::Active,
    }));

    entries.sort_by(|lhs, rhs| {
        (lhs.vm_id, lhs.guest_path.as_str(), lhs.offset, lhs.is_ret, lhs.state.label()).cmp(&(
            rhs.vm_id,
            rhs.guest_path.as_str(),
            rhs.offset,
            rhs.is_ret,
            rhs.state.label(),
        ))
    });
    entries
}

pub fn has_pending_path(vm_id: u32, guest_path: &str) -> bool {
    UPROBES
        .lock()
        .pending
        .values()
        .any(|entry| entry.vm_id == vm_id && entry.guest_path == guest_path)
}

pub fn lookup_active(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    UPROBES.lock().active.get(&(vm_id, pc)).cloned()
}

pub fn record_active_hit(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    let mut probes = UPROBES.lock();
    let entry = probes.active.get_mut(&(vm_id, pc))?;
    entry.hits = entry.hits.saturating_add(1);
    Some(entry.clone())
}

pub fn remove_active(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    UPROBES.lock().active.remove(&(vm_id, pc))
}

pub fn disable_active(vm_id: u32, pc: u64) -> Result<(), &'static str> {
    let mut probes = UPROBES.lock();
    let Some(entry) = probes.active.remove(&(vm_id, pc)) else {
        return Err("active uprobe not found");
    };
    restore_instruction(entry.hva, entry.saved_insn)?;
    Ok(())
}

fn activate_for_mapping(
    vm_id: u32,
    guest_path: &str,
    mm: u64,
    start: u64,
    file_offset: u64,
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
        let runtime_pc = if file_offset == 0 && pending.offset >= start {
            pending.offset
        } else {
            let Some(offset_delta) = pending.offset.checked_sub(file_offset) else {
                continue;
            };
            let Some(runtime_pc) = start.checked_add(offset_delta) else {
                continue;
            };
            runtime_pc
        };
        if runtime_pc < start {
            continue;
        }

        {
            let probes = UPROBES.lock();
            if probes.active.contains_key(&(vm_id, runtime_pc)) {
                continue;
            }
        }

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

        {
            let mut probes = UPROBES.lock();
            if probes.pending.remove(&key).is_none() || probes.active.contains_key(&(vm_id, runtime_pc)) {
                continue;
            }
            probes.active.insert(
                (vm_id, runtime_pc),
                ActiveUprobeEntry {
                    vm_id,
                    guest_path: pending.guest_path,
                    symbol: pending.symbol,
                    offset: pending.offset,
                    hits: 0,
                    prog_id: pending.prog_id,
                    is_ret: pending.is_ret,
                    mm,
                    pid: 0,
                    tgid: 0,
                    comm: String::new(),
                    pc: runtime_pc,
                    hva: patch.hva,
                    saved_insn: patch.saved_insn,
                },
            );
        }
        arm_exec_barrier(vm_id, patch.gpa);
        #[cfg(all(target_arch = "aarch64", not(any(test, feature = "test-utils"))))]
        let patched_insn = unsafe { core::ptr::read_volatile(patch.hva as *const u32) };
        #[cfg(all(target_arch = "x86_64", not(any(test, feature = "test-utils"))))]
        let patched_insn = unsafe { core::ptr::read_volatile(patch.hva as *const u8) as u32 };
        #[cfg(any(test, feature = "test-utils"))]
        let patched_insn = GUEST_BRK_INSN;
        log::info!(
            "guest_uprobe: BRK patch vm{}:{} runtime_pc={:#x} hva={:#x} saved_insn={:#010x} patched_insn={:#010x}",
            vm_id,
            guest_path,
            runtime_pc,
            patch.hva,
            patch.saved_insn,
            patched_insn
        );
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
        let (barrier_gpa, barrier_size) = crate::probe::kprobe::manager::query_step_barrier(vm_id, gpa);
        if UPROBES
            .lock()
            .armed_exec_barriers
            .contains_key(&(vm_id, barrier_gpa))
        {
            return;
        }
        if let Err(err) = crate::probe::kprobe::manager::set_stage2_executable(vm_id, barrier_gpa, false) {
            log::warn!(
                "guest_uprobe: failed to arm Stage-2 exec barrier vm{} gpa={:#x} size={:#x}: {}",
                vm_id,
                barrier_gpa,
                barrier_size,
                err
            );
            return;
        }
        UPROBES
            .lock()
            .armed_exec_barriers
            .insert(
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
            UPROBES.lock().armed_exec_barriers.remove(&(vm_id, barrier_gpa));
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
        return Ok(ExecBarrierFaultAction::ProbeHitSingleStep {
            barrier_gpa,
            barrier_size: barrier.size,
        });
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
    let Some(mapping) = maps.lookup_main_text(vm_id, mm) else {
        return Ok(0);
    };
    activate_for_mapping(
        vm_id,
        &mapping.guest_path,
        mapping.mm,
        mapping.start,
        mapping.file_offset,
    )
    .inspect(|count| {
        if *count == 0 {
            return;
        }
        let mut probes = UPROBES.lock();
        for entry in probes.active.values_mut() {
            if entry.vm_id == vm_id && entry.mm == mapping.mm && entry.guest_path == mapping.guest_path {
                entry.pid = mapping.pid;
                entry.tgid = mapping.tgid;
                entry.comm = mapping.comm.clone();
            }
        }
    })
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
    activate_for_mapping(vm_id, guest_path, mm, start, file_offset)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_active_for_test(vm_id: u32, pc: u64) -> Option<ActiveUprobeEntry> {
    lookup_active(vm_id, pc)
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
) {
    *RESTORE_BACKEND.write() = Some(mock_restore_instruction);
    *REINJECT_BACKEND.write() = Some(mock_reinject_breakpoint);
    let mut probes = UPROBES.lock();
    probes.active.insert(
        (vm_id, pc),
        ActiveUprobeEntry {
            vm_id,
            guest_path: "/mock".to_string(),
            symbol: "mock".to_string(),
            offset: 0,
            hits: 0,
            prog_id,
            is_ret: false,
            mm: 0,
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
    probes.pending.clear();
    probes.active.clear();
    probes.armed_exec_barriers.clear();
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
