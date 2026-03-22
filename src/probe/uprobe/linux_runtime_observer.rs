//! Hidden guest-kprobe based Linux runtime observer for guest uprobe activation.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once, RwLock};

use super::addr_translate;
use super::linux_observer;
use super::object;
use super::process_maps::ProcessMaps;
use crate::guest_symbols;
use crate::probe::kprobe::manager::{self as guest_kprobe, HiddenProbePhase};
use crate::probe::uprobe::manager;

const EXECVE_SYM: &str = "__arm64_sys_execve";
const EXECVEAT_SYM: &str = "__arm64_sys_execveat";
const VM_MMAP_PGOFF_SYM: &str = "vm_mmap_pgoff";
const RETRY_ACTIVATE_SYM: &str = "__arm64_sys_nanosleep";
const MAX_EXEC_PATH_LEN: usize = 256;

type VmContextidrFn = fn(vm_id: u32) -> axerrno::AxResult<u32>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecIntent {
    pub vm_id: u32,
    pub proc_token: u32,
    pub mm_token: u64,
    pub exec_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MmapIntent {
    vm_id: u32,
    proc_token: u32,
    mm_token: u64,
    len: u64,
    prot: u64,
    file_backed: bool,
    file_offset: u64,
}

#[derive(Clone, Copy, Default)]
struct VmObserverState {
    execve_gva: Option<u64>,
    execveat_gva: Option<u64>,
    vm_mmap_pgoff_gva: Option<u64>,
    retry_activate_gva: Option<u64>,
}

static VM_OBSERVERS: Mutex<BTreeMap<u32, VmObserverState>> = Mutex::new(BTreeMap::new());
static EXEC_INTENTS: Mutex<BTreeMap<(u32, u32), ExecIntent>> = Mutex::new(BTreeMap::new());
static LATEST_EXEC_INTENTS: Mutex<BTreeMap<u32, ExecIntent>> = Mutex::new(BTreeMap::new());
static LATEST_EXEC_INTENTS_BY_PATH: Mutex<BTreeMap<(u32, String), (usize, ExecIntent)>> =
    Mutex::new(BTreeMap::new());
static MMAP_INTENTS: Mutex<BTreeMap<(u32, u32, u64), MmapIntent>> = Mutex::new(BTreeMap::new());
static VM_CONTEXTIDR_HOOK: RwLock<Option<VmContextidrFn>> = RwLock::new(None);
static PROCESS_MAPS: Once<ProcessMaps> = Once::new();
static EXEC_INTENT_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

fn runtime_process_maps() -> &'static ProcessMaps {
    PROCESS_MAPS.call_once(ProcessMaps::new)
}

pub fn register_vm_contextidr_hook(f: VmContextidrFn) {
    *VM_CONTEXTIDR_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_vm_contextidr_hook_for_test() {
    *VM_CONTEXTIDR_HOOK.write() = None;
}

fn vm_contextidr_el1(vm_id: u32) -> axerrno::AxResult<u32> {
    if let Some(state) = crate::probe::guest_runtime_state::current_live_guest_runtime_state(vm_id)
        && state.contextidr_el1 != 0
    {
        return Ok(state.contextidr_el1);
    }
    let hook = *VM_CONTEXTIDR_HOOK.read();
    let Some(f) = hook else {
        return axerrno::ax_err!(Unsupported, "VM CONTEXTIDR_EL1 hook not registered");
    };
    f(vm_id)
}

fn fold_runtime_token(raw_token: u64) -> u32 {
    let folded = raw_token as u32 ^ (raw_token >> 32) as u32;
    if folded == 0 { 1 } else { folded }
}

fn proc_token_from_live_state(vm_id: u32) -> Option<u32> {
    let state = crate::probe::guest_runtime_state::current_live_guest_runtime_state(vm_id)?;
    if state.contextidr_el1 != 0 {
        return Some(state.contextidr_el1);
    }
    if state.sp_el0 != 0 {
        return Some(fold_runtime_token(state.sp_el0));
    }
    if state.tpidr_el0 != 0 {
        return Some(fold_runtime_token(state.tpidr_el0));
    }
    None
}

fn basename_of(exec_path: &str) -> Option<&str> {
    exec_path
        .rsplit('/')
        .find(|component| !component.is_empty())
}

fn execve_path_arg_index(symbol: &str) -> axerrno::AxResult<usize> {
    match symbol {
        EXECVE_SYM => Ok(0),
        EXECVEAT_SYM => Ok(1),
        _ => axerrno::ax_err!(InvalidInput, "unsupported exec observer symbol"),
    }
}

fn read_guest_kernel_u64(vm_id: u32, kernel_gva: u64) -> axerrno::AxResult<u64> {
    let hva = crate::probe::kprobe::addr_translate::gva_to_hva_for_vm(kernel_gva, vm_id)?;
    Ok(unsafe { core::ptr::read_volatile(hva as *const u64) })
}

fn execve_path_gva_from_regs(vm_id: u32, symbol: &str, regs: &[u64; 31]) -> axerrno::AxResult<u64> {
    let pt_regs_gva = regs[0];
    if pt_regs_gva == 0 {
        return axerrno::ax_err!(InvalidInput, "guest pt_regs pointer is null");
    }
    let arg_index = execve_path_arg_index(symbol)?;
    let arg_gva = pt_regs_gva
        .checked_add((arg_index * core::mem::size_of::<u64>()) as u64)
        .ok_or_else(|| axerrno::ax_err_type!(InvalidInput, "guest pt_regs argument overflow"))?;
    let path_gva = read_guest_kernel_u64(vm_id, arg_gva)?;
    if path_gva == 0 {
        return axerrno::ax_err!(InvalidInput, "guest exec pathname pointer is null");
    }
    Ok(path_gva)
}

fn read_exec_path_from_regs(
    vm_id: u32,
    symbol: &str,
    regs: &[u64; 31],
) -> axerrno::AxResult<String> {
    let path_gva = execve_path_gva_from_regs(vm_id, symbol, regs)?;
    addr_translate::read_user_cstring_with_vm(vm_id, path_gva, MAX_EXEC_PATH_LEN)
}

fn classify_exec_probe(vm_id: u32, probe_gva: u64) -> Option<&'static str> {
    let observers = VM_OBSERVERS.lock();
    let state = observers.get(&vm_id)?;
    if state.execve_gva == Some(probe_gva) {
        return Some(EXECVE_SYM);
    }
    if state.execveat_gva == Some(probe_gva) {
        return Some(EXECVEAT_SYM);
    }
    None
}

fn classify_mmap_probe(vm_id: u32, probe_gva: u64) -> bool {
    VM_OBSERVERS
        .lock()
        .get(&vm_id)
        .is_some_and(|state| state.vm_mmap_pgoff_gva == Some(probe_gva))
}

fn classify_retry_probe(vm_id: u32, probe_gva: u64) -> bool {
    VM_OBSERVERS
        .lock()
        .get(&vm_id)
        .is_some_and(|state| state.retry_activate_gva == Some(probe_gva))
}

fn current_tokens(vm_id: u32) -> Result<(u32, u64), &'static str> {
    let mm_token = addr_translate::vm_ttbr0_el1(vm_id).map_err(|_| "VM TTBR0_EL1 hook not registered")?;
    let proc_token = proc_token_from_live_state(vm_id)
        .or_else(|| vm_contextidr_el1(vm_id).ok())
        .unwrap_or_else(|| fold_runtime_token(mm_token));
    Ok((proc_token, mm_token))
}

fn lookup_exec_intent(vm_id: u32, proc_token: u32, mm_token: u64) -> Option<ExecIntent> {
    let _ = mm_token;
    if let Some(exec) = EXEC_INTENTS.lock().get(&(vm_id, proc_token)).cloned()
        && manager::has_pending_path(vm_id, &exec.exec_path)
    {
        return Some(exec);
    }

    let mut latest_matchable = None::<(usize, ExecIntent)>;
    for ((entry_vm_id, _path), (sequence, exec)) in LATEST_EXEC_INTENTS_BY_PATH.lock().iter() {
        if *entry_vm_id != vm_id || !manager::has_pending_path(vm_id, &exec.exec_path) {
            continue;
        }
        if latest_matchable
            .as_ref()
            .is_none_or(|(best_sequence, _)| *sequence > *best_sequence)
        {
            latest_matchable = Some((*sequence, exec.clone()));
        }
    }

    latest_matchable
        .map(|(_, exec)| exec)
        .or_else(|| LATEST_EXEC_INTENTS.lock().get(&vm_id).cloned())
}

fn record_execve(
    _maps: &ProcessMaps,
    vm_id: u32,
    symbol: &str,
    proc_token: u32,
    mm_token: u64,
    exec_path: &str,
) -> Result<(), &'static str> {
    if symbol != EXECVE_SYM && symbol != EXECVEAT_SYM {
        return Err("unsupported exec observer symbol");
    }
    if !exec_path.starts_with('/') {
        log::debug!(
            "guest_uprobe_observer: ignore relative exec path vm{} symbol={} path={}",
            vm_id,
            symbol,
            exec_path
        );
        return Ok(());
    }

    let Some(_comm) = basename_of(exec_path) else {
        return Err("exec path missing basename");
    };

    let exec_intent = ExecIntent {
        vm_id,
        proc_token,
        mm_token,
        exec_path: exec_path.to_string(),
    };
    let sequence = EXEC_INTENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    EXEC_INTENTS.lock().insert(
        (vm_id, proc_token),
        exec_intent.clone(),
    );
    LATEST_EXEC_INTENTS.lock().insert(vm_id, exec_intent);
    LATEST_EXEC_INTENTS_BY_PATH.lock().insert(
        (vm_id, exec_path.to_string()),
        (sequence, ExecIntent {
            vm_id,
            proc_token,
            mm_token,
            exec_path: exec_path.to_string(),
        }),
    );
    log::debug!(
        "guest_uprobe_observer: recorded exec intent vm{} proc={:#x} mm={:#x} path={}",
        vm_id,
        proc_token,
        mm_token,
        exec_path
    );
    Ok(())
}

fn handle_exec_entry(vm_id: u32, probe_gva: u64, regs: &[u64; 31]) {
    let Some(symbol) = classify_exec_probe(vm_id, probe_gva) else {
        return;
    };

    let (proc_token, mm_token) = match current_tokens(vm_id) {
        Ok(tokens) => tokens,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: missing exec observer tokens vm{} symbol={}: {}",
                vm_id,
                symbol,
                err
            );
            return;
        }
    };
    let path_gva = match execve_path_gva_from_regs(vm_id, symbol, regs) {
        Ok(path_gva) => path_gva,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: failed to resolve exec path pointer vm{} symbol={}: {}",
                vm_id,
                symbol,
                err
            );
            return;
        }
    };
    let exec_path = match read_exec_path_from_regs(vm_id, symbol, regs) {
        Ok(path) => path,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: failed to read exec path vm{} symbol={} gva={:#x}: {}",
                vm_id,
                symbol,
                path_gva,
                err
            );
            return;
        }
    };
    log::info!(
        "guest_uprobe_observer_exec: vm{} symbol={} proc={:#x} mm={:#x} path={}",
        vm_id,
        symbol,
        proc_token,
        mm_token,
        exec_path
    );
    if let Err(err) = record_execve(runtime_process_maps(), vm_id, symbol, proc_token, mm_token, &exec_path)
    {
        log::warn!(
            "guest_uprobe_observer: failed to record exec intent vm{} symbol={}: {}",
            vm_id,
            symbol,
            err
        );
    }
}

fn record_vm_mmap_entry(
    vm_id: u32,
    proc_token: u32,
    mm_token: u64,
    file_backed: bool,
    len: u64,
    prot: u64,
    pgoff: u64,
) -> Result<(), &'static str> {
    let file_offset = pgoff.checked_shl(12).ok_or("mmap file offset overflow")?;
    MMAP_INTENTS.lock().insert(
        (vm_id, proc_token, mm_token),
        MmapIntent {
            vm_id,
            proc_token,
            mm_token,
            len,
            prot,
            file_backed,
            file_offset,
        },
    );
    Ok(())
}

fn record_vm_mmap_return(
    maps: &ProcessMaps,
    vm_id: u32,
    proc_token: u32,
    mm_token: u64,
    start: u64,
) -> Result<usize, &'static str> {
    let Some(intent) = MMAP_INTENTS.lock().remove(&(vm_id, proc_token, mm_token)) else {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=no_mmap_intent",
            vm_id,
            proc_token,
            mm_token
        );
        return Ok(0);
    };
    if (start as i64) <= 0 || !intent.file_backed || (intent.prot & 0x4) == 0 {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=non_exec_or_anon start={:#x} file_backed={} prot={:#x}",
            vm_id,
            proc_token,
            mm_token,
            start,
            intent.file_backed,
            intent.prot
        );
        return Ok(0);
    }

    let Some(exec) = lookup_exec_intent(vm_id, proc_token, mm_token) else {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=no_exec_intent",
            vm_id,
            proc_token,
            mm_token
        );
        return Ok(0);
    };
    if !manager::has_pending_path(vm_id, &exec.exec_path) {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=no_pending_path path={}",
            vm_id,
            proc_token,
            mm_token,
            exec.exec_path
        );
        return Ok(0);
    }
    if let Some(expected_start) = object::lookup_main_text_start(vm_id, &exec.exec_path)
        && expected_start != start
    {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=main_text_start_mismatch expected_start={:#x} actual_start={:#x} path={}",
            vm_id,
            proc_token,
            mm_token,
            expected_start,
            start,
            exec.exec_path
        );
        return Ok(0);
    }
    if maps.lookup_main_text(vm_id, mm_token).is_some() {
        log::info!(
            "guest_uprobe_observer_mmap_return_skip: vm{} proc={:#x} mm={:#x} reason=main_text_exists path={}",
            vm_id,
            proc_token,
            mm_token,
            exec.exec_path
        );
        return Ok(0);
    }

    let Some(comm) = basename_of(&exec.exec_path) else {
        return Err("exec path missing basename");
    };
    linux_observer::on_exec(maps, vm_id, proc_token, proc_token, mm_token, comm);

    let end = start.checked_add(intent.len).ok_or("mmap end overflow")?;
    let activated = linux_observer::on_mmap(
        maps,
        vm_id,
        mm_token,
        start,
        end,
        intent.file_offset,
        &exec.exec_path,
    );
    if activated > 0 {
        log::info!(
            "guest_uprobe_activate: vm{} proc={:#x} mm={:#x} path={} start={:#x} count={}",
            vm_id,
            proc_token,
            mm_token,
            exec.exec_path,
            start,
            activated
        );
    }
    Ok(activated)
}

fn retry_pending_activation(
    maps: &ProcessMaps,
    vm_id: u32,
    mm_token: u64,
) -> Result<Option<(String, u64, usize)>, &'static str> {
    let Some(mapping) = maps.lookup_main_text(vm_id, mm_token) else {
        return Ok(None);
    };
    if !manager::has_pending_path(vm_id, &mapping.guest_path) {
        return Ok(None);
    }
    let activated = manager::try_activate_for_mm(maps, vm_id, mm_token)?;
    if activated == 0 {
        return Ok(None);
    }
    Ok(Some((mapping.guest_path, mapping.start, activated)))
}

fn handle_mmap_entry(vm_id: u32, regs: &[u64; 31]) {
    let (proc_token, mm_token) = match current_tokens(vm_id) {
        Ok(tokens) => tokens,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: missing mmap observer tokens vm{}: {}",
                vm_id,
                err
            );
            return;
        }
    };
    let file_backed = regs[0] != 0;
    let len = regs[2];
    let prot = regs[3];
    let pgoff = regs[5];
    log::info!(
        "guest_uprobe_observer_mmap_entry: vm{} proc={:#x} mm={:#x} file_backed={} len={:#x} prot={:#x} pgoff={:#x}",
        vm_id,
        proc_token,
        mm_token,
        file_backed,
        len,
        prot,
        pgoff
    );
    if let Err(err) = record_vm_mmap_entry(vm_id, proc_token, mm_token, file_backed, len, prot, pgoff)
    {
        log::warn!(
            "guest_uprobe_observer: failed to record mmap entry vm{} proc={:#x} mm={:#x}: {}",
            vm_id,
            proc_token,
            mm_token,
            err
        );
    }
}

fn handle_mmap_return(vm_id: u32, regs: &[u64; 31]) {
    let (proc_token, mm_token) = match current_tokens(vm_id) {
        Ok(tokens) => tokens,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: missing mmap observer return tokens vm{}: {}",
                vm_id,
                err
            );
            return;
        }
    };
    let start = regs[0];
    log::info!(
        "guest_uprobe_observer_mmap_return: vm{} proc={:#x} mm={:#x} start={:#x}",
        vm_id,
        proc_token,
        mm_token,
        start
    );
    if let Err(err) = record_vm_mmap_return(runtime_process_maps(), vm_id, proc_token, mm_token, start) {
        log::warn!(
            "guest_uprobe_observer: failed to record mmap return vm{} proc={:#x} mm={:#x}: {}",
            vm_id,
            proc_token,
            mm_token,
            err
        );
    }
}

fn handle_retry_activation_entry(vm_id: u32) {
    let (proc_token, mm_token) = match current_tokens(vm_id) {
        Ok(tokens) => tokens,
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: missing retry observer tokens vm{}: {}",
                vm_id,
                err
            );
            return;
        }
    };
    match retry_pending_activation(runtime_process_maps(), vm_id, mm_token) {
        Ok(Some((guest_path, start, activated))) => {
            log::info!(
                "guest_uprobe_activate: vm{} proc={:#x} mm={:#x} path={} start={:#x} count={} reason=runtime_retry",
                vm_id,
                proc_token,
                mm_token,
                guest_path,
                start,
                activated
            );
        }
        Ok(None) => {}
        Err(err) => {
            log::warn!(
                "guest_uprobe_observer: retry activation failed vm{} proc={:#x} mm={:#x}: {}",
                vm_id,
                proc_token,
                mm_token,
                err
            );
        }
    }
}

fn runtime_observer_callback(
    vm_id: u32,
    probe_gva: u64,
    _current_pc: u64,
    regs: &[u64; 31],
    phase: HiddenProbePhase,
) {
    match phase {
        HiddenProbePhase::Entry => {
            if classify_exec_probe(vm_id, probe_gva).is_some() {
                handle_exec_entry(vm_id, probe_gva, regs);
                return;
            }
            if classify_mmap_probe(vm_id, probe_gva) {
                handle_mmap_entry(vm_id, regs);
                return;
            }
            if classify_retry_probe(vm_id, probe_gva) {
                handle_retry_activation_entry(vm_id);
            }
        }
        HiddenProbePhase::Return => {
            if classify_mmap_probe(vm_id, probe_gva) {
                handle_mmap_return(vm_id, regs);
            }
        }
    }
}

pub fn ensure_registered_for_vm(vm_id: u32) -> Result<usize, &'static str> {
    guest_kprobe::init();

    if !guest_symbols::is_loaded(vm_id) {
        return Ok(0);
    }

    let mut registered = 0usize;
    let mut state = *VM_OBSERVERS.lock().entry(vm_id).or_default();

    if state.execve_gva.is_none() && let Some(gva) = guest_symbols::lookup_addr(vm_id, EXECVE_SYM) {
        guest_kprobe::attach_hidden_brk(vm_id, gva, false, runtime_observer_callback)?;
        state.execve_gva = Some(gva);
        registered += 1;
    }

    if state.execveat_gva.is_none()
        && let Some(gva) = guest_symbols::lookup_addr(vm_id, EXECVEAT_SYM)
    {
        guest_kprobe::attach_hidden_brk(vm_id, gva, false, runtime_observer_callback)?;
        state.execveat_gva = Some(gva);
        registered += 1;
    }

    if state.vm_mmap_pgoff_gva.is_none()
        && let Some(gva) = guest_symbols::lookup_addr(vm_id, VM_MMAP_PGOFF_SYM)
    {
        guest_kprobe::attach_hidden_brk(vm_id, gva, true, runtime_observer_callback)?;
        state.vm_mmap_pgoff_gva = Some(gva);
        registered += 1;
    }

    if state.retry_activate_gva.is_none()
        && let Some(gva) = guest_symbols::lookup_addr(vm_id, RETRY_ACTIVATE_SYM)
    {
        guest_kprobe::attach_hidden_brk(vm_id, gva, false, runtime_observer_callback)?;
        state.retry_activate_gva = Some(gva);
        registered += 1;
    }

    VM_OBSERVERS.lock().insert(vm_id, state);
    Ok(registered)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn record_execve_for_test(
    maps: &ProcessMaps,
    vm_id: u32,
    symbol: &str,
    proc_token: u32,
    mm_token: u64,
    exec_path: &str,
) -> Result<(), &'static str> {
    record_execve(maps, vm_id, symbol, proc_token, mm_token, exec_path)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_exec_intent_for_test(vm_id: u32, proc_token: u32, mm_token: u64) -> Option<ExecIntent> {
    let exec = EXEC_INTENTS.lock().get(&(vm_id, proc_token)).cloned()?;
    (exec.mm_token == mm_token).then_some(exec)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn record_vm_mmap_entry_for_test(
    vm_id: u32,
    proc_token: u32,
    mm_token: u64,
    file_backed: bool,
    len: u64,
    prot: u64,
    pgoff: u64,
) -> Result<(), &'static str> {
    record_vm_mmap_entry(vm_id, proc_token, mm_token, file_backed, len, prot, pgoff)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn record_vm_mmap_return_for_test(
    maps: &ProcessMaps,
    vm_id: u32,
    proc_token: u32,
    mm_token: u64,
    start: u64,
) -> Result<usize, &'static str> {
    record_vm_mmap_return(maps, vm_id, proc_token, mm_token, start)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn retry_pending_activation_for_test(
    maps: &ProcessMaps,
    vm_id: u32,
    mm_token: u64,
) -> Result<usize, &'static str> {
    Ok(retry_pending_activation(maps, vm_id, mm_token)?.map_or(0, |(_, _, count)| count))
}

#[cfg(any(test, feature = "test-utils"))]
pub fn current_tokens_for_test(vm_id: u32) -> Result<(u32, u64), &'static str> {
    current_tokens(vm_id)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn read_exec_path_from_regs_for_test(
    vm_id: u32,
    symbol: &str,
    regs: &[u64; 31],
) -> axerrno::AxResult<String> {
    read_exec_path_from_regs(vm_id, symbol, regs)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn fallback_proc_token_for_test(raw_token: u64) -> u32 {
    fold_runtime_token(raw_token)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_all_for_test() {
    let states = VM_OBSERVERS.lock().clone();
    VM_OBSERVERS.lock().clear();
    EXEC_INTENTS.lock().clear();
    LATEST_EXEC_INTENTS.lock().clear();
    LATEST_EXEC_INTENTS_BY_PATH.lock().clear();
    MMAP_INTENTS.lock().clear();
    *VM_CONTEXTIDR_HOOK.write() = None;
    EXEC_INTENT_SEQUENCE.store(1, Ordering::Relaxed);
    for (vm_id, state) in states {
        for gva in [
            state.execve_gva,
            state.execveat_gva,
            state.vm_mmap_pgoff_gva,
            state.retry_activate_gva,
        ]
            .into_iter()
            .flatten()
        {
            let _ = guest_kprobe::detach(vm_id, gva);
        }
    }
}
