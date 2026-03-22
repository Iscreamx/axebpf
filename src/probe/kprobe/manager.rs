//! Guest kprobe manager.
//!
//! Manages registration, enabling, and lifecycle of probes targeting
//! guest VM kernel code. Each probe is associated with a VM ID and
//! a guest virtual address.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use spin::RwLock;

type Stage2ExecHook = fn(vm_id: u32, gpa: u64, executable: bool) -> axerrno::AxResult<()>;
type Stage2ExecRegionHook = fn(vm_id: u32, gpa: u64) -> axerrno::AxResult<(u64, u64)>;
pub type HiddenProbeCallback =
    fn(vm_id: u32, probe_gva: u64, current_pc: u64, regs: &[u64; 31], phase: HiddenProbePhase);

/// Guest kprobe injection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KprobeMode {
    /// Stage-2 fault: mark page as non-executable (XN=1)
    Stage2Fault,
    /// BRK injection: write BRK instruction into guest memory
    BrkInject,
}

/// State of a guest kprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestKprobeState {
    Registered,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenProbePhase {
    Entry,
    Return,
}

#[inline]
fn is_ttbr1_not_ready(err: &str) -> bool {
    err == "VM TTBR1_EL1 is not ready"
}

/// A registered guest kprobe entry.
pub struct GuestKprobeEntry {
    /// VM ID this probe targets (0 = all VMs)
    pub vm_id: u32,
    /// Guest virtual address
    pub gva: u64,
    /// Symbol name (if resolved via guest symbol table)
    pub symbol: Option<String>,
    /// Injection mode
    pub mode: KprobeMode,
    /// Associated eBPF program ID
    pub prog_id: u32,
    /// Hit count
    pub hits: u64,
    /// Whether this is a return probe
    pub is_ret: bool,
    /// Probe state
    pub state: GuestKprobeState,
    /// Saved original instruction (for BRK inject mode)
    pub saved_insn: Option<u32>,
    /// Resolved guest physical address for Stage-2 mode.
    pub resolved_gpa: Option<u64>,
    /// Resolved Stage-2 execute barrier size.
    pub resolved_gpa_size: Option<u64>,
    /// Resolved host virtual address for BRK mode.
    pub resolved_hva: Option<usize>,
    /// Internal observer probe; not shown in shell output.
    pub hidden: bool,
    /// Optional internal callback for hidden probes.
    pub hidden_callback: Option<HiddenProbeCallback>,
}

/// Key for identifying a guest kprobe: (vm_id, gva).
type ProbeKey = (u32, u64);

/// Detached BRK probe state kept for short-lived stale trap recovery.
#[derive(Clone, Copy)]
struct StaleBrkEntry {
    hva: usize,
    saved_insn: u32,
    retries_left: u32,
}

#[derive(Clone, Copy, Debug)]
struct ReturnBrkState {
    refcount: u32,
    hva: usize,
    saved_insn: u32,
}

#[derive(Clone, Copy, Default)]
struct RegisterOptions {
    hidden: bool,
    hidden_callback: Option<HiddenProbeCallback>,
}

const STALE_BRK_MAX_ENTRIES: usize = 64;
const STALE_BRK_RETRY_BUDGET: u32 = 4096;

/// Global guest kprobe registry.
static GUEST_KPROBE_REGISTRY: Mutex<Option<GuestKprobeRegistry>> = Mutex::new(None);
static STAGE2_EXEC_HOOK: RwLock<Option<Stage2ExecHook>> = RwLock::new(None);
static STAGE2_EXEC_REGION_HOOK: RwLock<Option<Stage2ExecRegionHook>> = RwLock::new(None);
static STALE_BRK_REGISTRY: Mutex<BTreeMap<ProbeKey, StaleBrkEntry>> = Mutex::new(BTreeMap::new());
static RETURN_BRK_REFCOUNT: Mutex<BTreeMap<ProbeKey, ReturnBrkState>> = Mutex::new(BTreeMap::new());
#[cfg(any(test, feature = "test-utils"))]
static MOCK_FAIL_ENABLE_TARGET: Mutex<Option<ProbeKey>> = Mutex::new(None);

#[cfg(target_arch = "aarch64")]
const GUEST_BRK_INSN: u32 = 0xd4200000;

#[cfg(target_arch = "x86_64")]
const GUEST_BRK_INSN: u32 = 0x000000cc;

/// Registry managing all guest kprobes.
pub struct GuestKprobeRegistry {
    probes: BTreeMap<ProbeKey, GuestKprobeEntry>,
}

/// Atomic BRK probe hit context for single-step flow.
#[derive(Clone, Copy, Debug)]
pub struct BrkProbeHitInfo {
    pub prog_id: u32,
    pub is_ret: bool,
    pub hidden: bool,
    pub hva: usize,
    pub saved_insn: u32,
    pub gpa: Option<u64>,
    pub gpa_size: u64,
}

pub type GuestKprobeListEntry = (u32, u64, Option<String>, u64, bool, bool, u32, KprobeMode);

impl Default for GuestKprobeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestKprobeRegistry {
    pub fn new() -> Self {
        Self {
            probes: BTreeMap::new(),
        }
    }

    /// Register a guest kprobe.
    fn register_inner(
        &mut self,
        vm_id: u32,
        gva: u64,
        prog_id: u32,
        is_ret: bool,
        mode: KprobeMode,
        options: RegisterOptions,
    ) -> Result<(), &'static str> {
        let key = (vm_id, gva);
        if self.probes.contains_key(&key) {
            return Err("guest kprobe already registered at this address");
        }
        clear_stale_brk(key);

        let entry = GuestKprobeEntry {
            vm_id,
            gva,
            symbol: None,
            mode,
            prog_id,
            hits: 0,
            is_ret,
            state: GuestKprobeState::Registered,
            saved_insn: None,
            resolved_gpa: None,
            resolved_gpa_size: None,
            resolved_hva: None,
            hidden: options.hidden,
            hidden_callback: options.hidden_callback,
        };

        self.probes.insert(key, entry);
        log::info!(
            "guest_kprobe: registered vm{}:{:#x} (mode={:?}, prog={})",
            vm_id,
            gva,
            mode,
            prog_id
        );
        Ok(())
    }

    /// Register a guest kprobe.
    pub fn register(
        &mut self,
        vm_id: u32,
        gva: u64,
        prog_id: u32,
        is_ret: bool,
        mode: KprobeMode,
    ) -> Result<(), &'static str> {
        self.register_inner(vm_id, gva, prog_id, is_ret, mode, RegisterOptions::default())
    }

    pub fn register_hidden(
        &mut self,
        vm_id: u32,
        gva: u64,
        is_ret: bool,
        mode: KprobeMode,
        callback: HiddenProbeCallback,
    ) -> Result<(), &'static str> {
        self.register_inner(
            vm_id,
            gva,
            0,
            is_ret,
            mode,
            RegisterOptions {
                hidden: true,
                hidden_callback: Some(callback),
            },
        )
    }

    /// Enable a guest kprobe (activate the probe mechanism).
    pub fn enable(&mut self, vm_id: u32, gva: u64) -> Result<(), &'static str> {
        let key = (vm_id, gva);
        let entry = self.probes.get_mut(&key).ok_or("guest kprobe not found")?;

        if entry.state == GuestKprobeState::Enabled {
            return Ok(());
        }

        #[cfg(any(test, feature = "test-utils"))]
        {
            let mut fail_target = MOCK_FAIL_ENABLE_TARGET.lock();
            if *fail_target == Some(key) {
                *fail_target = None;
                return Err("mock backend enable failed");
            }
        }

        match entry.mode {
            KprobeMode::Stage2Fault => {
                if super::addr_translate::vm_ttbr1_el1(vm_id).is_err() {
                    return Err("VM TTBR1_EL1 is not ready");
                }
                let gpa = super::addr_translate::gva_to_gpa_with_vm(gva, vm_id)
                    .map_err(|_| "failed to translate GVA->GPA")?;
                let (barrier_gpa, barrier_size) = query_stage2_exec_region(vm_id, gpa)?;
                set_stage2_executable(vm_id, barrier_gpa, false)?;
                entry.resolved_gpa = Some(barrier_gpa);
                entry.resolved_gpa_size = Some(barrier_size);
                log::info!(
                    "guest_kprobe: enabling Stage-2 fault mode for vm{}:{:#x}",
                    vm_id,
                    gva
                );
            }
            KprobeMode::BrkInject => {
                if super::addr_translate::vm_ttbr1_el1(vm_id).is_err() {
                    return Err("VM TTBR1_EL1 is not ready");
                }
                clear_stale_brk(key);
                let hva = super::addr_translate::gva_to_hva_for_vm(gva, vm_id)
                    .map_err(|_| "failed to translate GVA->HVA")?;
                let gpa = super::addr_translate::gva_to_gpa_with_vm(gva, vm_id)
                    .map_err(|_| "failed to translate GVA->GPA")?;
                let (barrier_gpa, barrier_size) = query_stage2_exec_region(vm_id, gpa)?;
                let saved = inject_guest_breakpoint(hva)?;
                entry.saved_insn = Some(saved);
                entry.resolved_hva = Some(hva);
                entry.resolved_gpa = Some(barrier_gpa);
                entry.resolved_gpa_size = Some(barrier_size);
                log::info!(
                    "guest_kprobe: BRK patch vm{}:{:#x} hva={:#x} gpa={:#x} barrier_size={:#x} saved_insn={:#010x}",
                    vm_id,
                    gva,
                    hva,
                    barrier_gpa,
                    barrier_size,
                    saved
                );
                log::info!(
                    "guest_kprobe: enabling BRK inject mode for vm{}:{:#x}",
                    vm_id,
                    gva
                );
            }
        }

        entry.state = GuestKprobeState::Enabled;
        Ok(())
    }

    /// Disable a guest kprobe.
    pub fn disable(&mut self, vm_id: u32, gva: u64) -> Result<(), &'static str> {
        let key = (vm_id, gva);
        let Some(entry) = self.probes.get_mut(&key) else {
            return Ok(());
        };

        if entry.state == GuestKprobeState::Disabled || entry.state == GuestKprobeState::Registered
        {
            return Ok(());
        }

        match entry.mode {
            KprobeMode::Stage2Fault => {
                if let Some(gpa) = entry.resolved_gpa {
                    set_stage2_executable(vm_id, gpa, true)?;
                }
                entry.resolved_gpa = None;
                entry.resolved_gpa_size = None;
            }
            KprobeMode::BrkInject => {
                if let (Some(hva), Some(saved)) = (entry.resolved_hva, entry.saved_insn) {
                    remember_stale_brk(key, hva, saved);
                    log::info!(
                        "guest_kprobe: BRK restore vm{}:{:#x} hva={:#x} saved_insn={:#010x}",
                        vm_id,
                        gva,
                        hva,
                        saved
                    );
                    restore_guest_breakpoint(hva, saved)?;
                }
                entry.saved_insn = None;
                entry.resolved_hva = None;
                entry.resolved_gpa = None;
                entry.resolved_gpa_size = None;
            }
        }

        entry.state = GuestKprobeState::Disabled;
        log::info!("guest_kprobe: disabled vm{}:{:#x}", vm_id, gva);
        Ok(())
    }

    /// Unregister a guest kprobe.
    pub fn unregister(&mut self, vm_id: u32, gva: u64) -> Result<(), &'static str> {
        self.disable(vm_id, gva)?;
        let key = (vm_id, gva);
        let Some(_removed) = self.probes.remove(&key) else {
            return Ok(());
        };
        log::info!("guest_kprobe: unregistered vm{}:{:#x}", vm_id, gva);
        Ok(())
    }

    /// Look up a guest kprobe by GVA, checking all VMs and the global (vm_id=0) entry.
    pub fn lookup(&self, vm_id: u32, gva: u64) -> Option<&GuestKprobeEntry> {
        // Check VM-specific first, then global
        self.probes
            .get(&(vm_id, gva))
            .or_else(|| self.probes.get(&(0, gva)))
    }

    /// Mutable lookup with VM-specific entry preferred over global entry.
    pub fn lookup_mut(&mut self, vm_id: u32, gva: u64) -> Option<&mut GuestKprobeEntry> {
        if self.probes.contains_key(&(vm_id, gva)) {
            return self.probes.get_mut(&(vm_id, gva));
        }
        self.probes.get_mut(&(0, gva))
    }

    /// Record a hit.
    pub fn record_hit(&mut self, vm_id: u32, gva: u64) {
        if let Some(entry) = self.probes.get_mut(&(vm_id, gva)) {
            entry.hits += 1;
            log_hit_progress(entry);
        } else if let Some(entry) = self.probes.get_mut(&(0, gva)) {
            entry.hits += 1;
            log_hit_progress(entry);
        }
    }

    /// List all guest kprobes.
    pub fn list(&self) -> Vec<&GuestKprobeEntry> {
        self.probes.values().filter(|entry| !entry.hidden).collect()
    }

    /// Retry enabling probes that were registered before TTBR1_EL1 became ready.
    pub fn try_enable_registered_for_vm(&mut self, vm_id: u32) -> usize {
        let keys: Vec<ProbeKey> = self
            .probes
            .iter()
            .filter_map(|(&(vid, gva), entry)| {
                (vid == vm_id && entry.state == GuestKprobeState::Registered).then_some((vid, gva))
            })
            .collect();

        let mut enabled = 0usize;
        for (vid, gva) in keys {
            match self.enable(vid, gva) {
                Ok(()) => {
                    enabled += 1;
                    log::info!(
                        "guest_kprobe: auto-enabled deferred probe vm{}:{:#x}",
                        vid,
                        gva
                    );
                }
                Err(e) if is_ttbr1_not_ready(e) => {}
                Err(e) => {
                    log::warn!(
                        "guest_kprobe: deferred enable vm{}:{:#x} failed: {}",
                        vid,
                        gva,
                        e
                    );
                }
            }
        }

        enabled
    }
}

fn log_hit_progress(entry: &GuestKprobeEntry) {
    if entry.hidden {
        return;
    }
    if !entry.hits.is_power_of_two() {
        return;
    }

    let kind = if entry.is_ret { "kretprobe" } else { "kprobe" };
    if let Some(symbol) = entry.symbol.as_deref() {
        log::info!(
            "guest_kprobe_hits: {} vm{}:{} hits={}",
            kind,
            entry.vm_id,
            symbol,
            entry.hits
        );
    } else {
        log::info!(
            "guest_kprobe_hits: {} vm{}:{:#x} hits={}",
            kind,
            entry.vm_id,
            entry.gva,
            entry.hits
        );
    }
}

#[inline]
pub(crate) fn set_stage2_executable(
    vm_id: u32,
    gpa: u64,
    executable: bool,
) -> Result<(), &'static str> {
    let hook = *STAGE2_EXEC_HOOK.read();
    let Some(f) = hook else {
        return Err("Stage-2 execute hook not registered");
    };
    f(vm_id, gpa, executable).map_err(|_| "failed to update Stage-2 execute permission")
}

fn query_stage2_exec_region(vm_id: u32, gpa: u64) -> Result<(u64, u64), &'static str> {
    let hook = *STAGE2_EXEC_REGION_HOOK.read();
    if let Some(f) = hook {
        return f(vm_id, gpa).map_err(|_| "failed to query Stage-2 execute region");
    }
    Ok((gpa & !0xfff, 0x1000))
}

pub fn query_step_barrier(vm_id: u32, gpa: u64) -> (u64, u64) {
    query_stage2_exec_region(vm_id, gpa).unwrap_or((gpa & !0xfff, 0x1000))
}

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

fn restore_guest_breakpoint(hva: usize, saved_insn: u32) -> Result<(), &'static str> {
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
        Err("BRK restore is not supported on this architecture")
    }
}

fn evict_one_stale_brk() {
    let mut stale = STALE_BRK_REGISTRY.lock();
    if stale.len() < STALE_BRK_MAX_ENTRIES {
        return;
    }
    if let Some(key) = stale.keys().next().copied() {
        stale.remove(&key);
    }
}

fn remember_stale_brk(key: ProbeKey, hva: usize, saved_insn: u32) {
    evict_one_stale_brk();
    let mut stale = STALE_BRK_REGISTRY.lock();
    stale.insert(
        key,
        StaleBrkEntry {
            hva,
            saved_insn,
            retries_left: STALE_BRK_RETRY_BUDGET,
        },
    );
}

fn clear_stale_brk(key: ProbeKey) {
    STALE_BRK_REGISTRY.lock().remove(&key);
}

pub fn acquire_return_brk(vm_id: u32, gva: u64, hva: usize) -> Result<(u32, u32), &'static str> {
    let key = (vm_id, gva);
    let mut registry = RETURN_BRK_REFCOUNT.lock();
    if let Some(state) = registry.get_mut(&key) {
        if state.hva != hva {
            return Err("return BRK HVA mismatch");
        }
        state.refcount = state.refcount.saturating_add(1);
        return Ok((state.refcount, state.saved_insn));
    }

    let saved_insn = inject_guest_breakpoint(hva)?;
    registry.insert(
        key,
        ReturnBrkState {
            refcount: 1,
            hva,
            saved_insn,
        },
    );
    Ok((1, saved_insn))
}

pub fn release_return_brk(vm_id: u32, gva: u64) -> Result<bool, &'static str> {
    let key = (vm_id, gva);
    let mut registry = RETURN_BRK_REFCOUNT.lock();
    let state = registry.get_mut(&key).ok_or("return BRK not found")?;
    if state.refcount <= 1 {
        registry.remove(&key);
        return Ok(false);
    }
    state.refcount -= 1;
    Ok(true)
}

pub fn cleanup_return_brk(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let key = (vm_id, gva);
    let state = RETURN_BRK_REFCOUNT.lock().remove(&key);
    let Some(state) = state else {
        return Ok(());
    };
    restore_guest_breakpoint(state.hva, state.saved_insn)
}

pub fn cleanup_return_brks_for_vm(vm_id: u32) {
    let keys: Vec<ProbeKey> = RETURN_BRK_REFCOUNT
        .lock()
        .keys()
        .filter(|&&(vid, _)| vid == vm_id)
        .copied()
        .collect();
    for (_, gva) in keys {
        if let Err(e) = cleanup_return_brk(vm_id, gva) {
            log::warn!(
                "guest_kprobe: cleanup return BRK vm{}:{:#x} failed: {}",
                vm_id,
                gva,
                e
            );
        }
    }
}

// === Module-level convenience functions ===

pub fn init() {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    ensure_registry_initialized(&mut registry);
}

fn ensure_registry_initialized(
    registry: &mut Option<GuestKprobeRegistry>,
) -> &mut GuestKprobeRegistry {
    if registry.is_none() {
        *registry = Some(GuestKprobeRegistry::new());
        log::info!("guest_kprobe: subsystem initialized");
    }
    registry.as_mut().expect("guest kprobe registry must exist")
}

pub fn register_stage2_exec_hook(f: Stage2ExecHook) {
    *STAGE2_EXEC_HOOK.write() = Some(f);
}

pub fn register_stage2_exec_region_hook(f: Stage2ExecRegionHook) {
    *STAGE2_EXEC_REGION_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_stage2_exec_hook_for_test() {
    *STAGE2_EXEC_HOOK.write() = None;
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_stage2_exec_region_hook_for_test() {
    *STAGE2_EXEC_REGION_HOOK.write() = None;
}

pub fn register(
    vm_id: u32,
    gva: u64,
    prog_id: u32,
    is_ret: bool,
    mode: KprobeMode,
) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    registry.register(vm_id, gva, prog_id, is_ret, mode)
}

pub fn attach_hidden_brk(
    vm_id: u32,
    gva: u64,
    is_ret: bool,
    callback: HiddenProbeCallback,
) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    registry.register_hidden(vm_id, gva, is_ret, KprobeMode::BrkInject, callback)?;
    if let Err(e) = registry.enable(vm_id, gva) {
        if is_ttbr1_not_ready(e) {
            log::info!(
                "guest_kprobe: deferred hidden enable vm{}:{:#x} until TTBR1_EL1 is ready",
                vm_id,
                gva
            );
            return Ok(());
        }
        let _ = registry.unregister(vm_id, gva);
        return Err(e);
    }
    Ok(())
}

pub fn enable(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    registry.enable(vm_id, gva)
}

pub fn disable(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    registry.disable(vm_id, gva)
}

pub fn unregister(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    registry.unregister(vm_id, gva)
}

pub fn attach(
    vm_id: u32,
    gva: u64,
    prog_id: u32,
    is_ret: bool,
    mode: KprobeMode,
) -> Result<(), &'static str> {
    register(vm_id, gva, prog_id, is_ret, mode)?;
    if let Err(e) = enable(vm_id, gva) {
        if is_ttbr1_not_ready(e) {
            log::info!(
                "guest_kprobe: deferred enable vm{}:{:#x} until TTBR1_EL1 is ready",
                vm_id,
                gva
            );
            return Ok(());
        }
        let _ = unregister(vm_id, gva);
        return Err(e);
    }
    Ok(())
}

pub fn try_enable_registered_for_vm(vm_id: u32) -> usize {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let Some(registry) = registry.as_mut() else {
        return 0;
    };
    registry.try_enable_registered_for_vm(vm_id)
}

pub fn detach(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let is_ret = {
        let registry = GUEST_KPROBE_REGISTRY.lock();
        registry
            .as_ref()
            .and_then(|r| r.lookup(vm_id, gva))
            .map(|entry| entry.is_ret)
            .unwrap_or(false)
    };

    unregister(vm_id, gva)?;

    if is_ret {
        let cleared = super::return_stack::clear_for_vm_probe(vm_id, gva);
        for entry in cleared {
            if let Err(e) = cleanup_return_brk(vm_id, entry.return_gva) {
                log::warn!(
                    "guest_kprobe: cleanup return BRK vm{}:{:#x} failed: {}",
                    vm_id,
                    entry.return_gva,
                    e
                );
            }
        }
    }

    Ok(())
}

/// Detach and unregister all guest kprobes for one VM.
///
/// Individual cleanup failures are logged and skipped so that
/// the rest of the VM probes can still be processed.
pub fn detach_all_for_vm(vm_id: u32) -> usize {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let Some(registry) = registry.as_mut() else {
        return 0;
    };

    let keys: Vec<ProbeKey> = registry
        .probes
        .keys()
        .filter(|&&(vid, _)| vid == vm_id)
        .copied()
        .collect();

    let removed = keys.len();
    for (vid, gva) in keys {
        if let Err(e) = registry.disable(vid, gva) {
            log::warn!(
                "guest_kprobe: cleanup disable vm{}:{:#x} failed: {}",
                vid,
                gva,
                e
            );
        }
        if let Err(e) = registry.unregister(vid, gva) {
            log::warn!(
                "guest_kprobe: cleanup unregister vm{}:{:#x} failed: {}",
                vid,
                gva,
                e
            );
        }
    }

    if removed > 0 {
        log::info!("guest_kprobe: detached {} probes for vm{}", removed, vm_id);
    }
    super::return_stack::clear_for_vm(vm_id);
    cleanup_return_brks_for_vm(vm_id);
    removed
}

/// Set or clear symbol name for an existing guest kprobe entry.
pub fn set_symbol(vm_id: u32, gva: u64, symbol: Option<&str>) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = ensure_registry_initialized(&mut registry);
    let entry = registry
        .probes
        .get_mut(&(vm_id, gva))
        .ok_or("guest kprobe not found")?;
    entry.symbol = symbol.map(String::from);
    Ok(())
}

/// Recover from stale BRK traps after probe detach.
///
/// Returns `true` when a stale BRK trap was matched and recovered, and
/// the guest should retry execution at the same PC.
pub fn consume_stale_brk(vm_id: u32, gva: u64) -> bool {
    let key = (vm_id, gva);
    let stale = {
        let mut stale_registry = STALE_BRK_REGISTRY.lock();
        let Some(entry) = stale_registry.get_mut(&key) else {
            return false;
        };
        let stale = *entry;
        if entry.retries_left <= 1 {
            stale_registry.remove(&key);
        } else {
            entry.retries_left -= 1;
        }
        stale
    };

    if let Err(e) = restore_guest_breakpoint(stale.hva, stale.saved_insn) {
        log::warn!(
            "guest_kprobe: stale BRK recover failed vm{}:{:#x}: {}",
            vm_id,
            gva,
            e
        );
        return false;
    }

    log::debug!(
        "guest_kprobe: stale BRK consumed vm{}:{:#x}, retries_left={}",
        vm_id,
        gva,
        stale.retries_left.saturating_sub(1)
    );
    true
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_stale_brk_for_test() {
    STALE_BRK_REGISTRY.lock().clear();
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_return_brk_for_test() {
    RETURN_BRK_REFCOUNT.lock().clear();
}

#[cfg(any(test, feature = "test-utils"))]
pub fn install_mock_backend_fail_on_enable(vm_id: u32, gva: u64) {
    *MOCK_FAIL_ENABLE_TARGET.lock() = Some((vm_id, gva));
}

pub fn list_all() -> Vec<GuestKprobeListEntry> {
    let registry = GUEST_KPROBE_REGISTRY.lock();
    match registry.as_ref() {
        Some(r) => r
            .list()
            .iter()
            .map(|e| {
                (
                    e.vm_id,
                    e.gva,
                    e.symbol.clone(),
                    e.hits,
                    e.state == GuestKprobeState::Enabled,
                    e.is_ret,
                    e.prog_id,
                    e.mode,
                )
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Look up an enabled probe and return `(prog_id, is_ret)`.
pub fn lookup_enabled(vm_id: u32, gva: u64) -> Option<(u32, bool)> {
    let registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_ref()?;
    let entry = registry.lookup(vm_id, gva)?;
    if entry.state != GuestKprobeState::Enabled {
        return None;
    }
    Some((entry.prog_id, entry.is_ret))
}

/// Look up the execute barrier tracked for an enabled probe.
pub fn lookup_stage2_barrier(vm_id: u32, gva: u64) -> Option<(u64, u64)> {
    let registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_ref()?;
    let entry = registry.lookup(vm_id, gva)?;
    if entry.state != GuestKprobeState::Enabled {
        return None;
    }
    let barrier_gpa = entry.resolved_gpa?;
    let barrier_size = entry.resolved_gpa_size.unwrap_or(0x1000);
    Some((barrier_gpa, barrier_size))
}

/// Look up an enabled Stage-2 probe whose execute barrier covers the given GPA.
pub fn lookup_enabled_stage2_probe_by_gpa(vm_id: u32, gpa: u64) -> Option<(u64, u64, u64)> {
    let registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_ref()?;

    for entry in registry.list() {
        if entry.vm_id != vm_id && entry.vm_id != 0 {
            continue;
        }
        if entry.state != GuestKprobeState::Enabled || entry.mode != KprobeMode::Stage2Fault {
            continue;
        }

        let barrier_gpa = entry.resolved_gpa?;
        let barrier_size = entry.resolved_gpa_size.unwrap_or(0x1000);
        if (barrier_gpa..barrier_gpa.saturating_add(barrier_size)).contains(&gpa) {
            return Some((entry.gva, barrier_gpa, barrier_size));
        }
    }

    None
}

/// Look up an enabled BRK probe and record one hit in the same lock scope.
pub fn lookup_enabled_brk_hit(vm_id: u32, gva: u64) -> Option<BrkProbeHitInfo> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_mut()?;
    let entry = registry.lookup_mut(vm_id, gva)?;
    if entry.state != GuestKprobeState::Enabled || entry.mode != KprobeMode::BrkInject {
        return None;
    }
    let (hva, saved_insn) = match (entry.resolved_hva, entry.saved_insn) {
        (Some(hva), Some(insn)) => (hva, insn),
        _ => return None,
    };
    entry.hits = entry.hits.saturating_add(1);
    log_hit_progress(entry);
    Some(BrkProbeHitInfo {
        prog_id: entry.prog_id,
        is_ret: entry.is_ret,
        hidden: entry.hidden,
        hva,
        saved_insn,
        gpa: entry.resolved_gpa,
        gpa_size: entry.resolved_gpa_size.unwrap_or(0x1000),
    })
}

pub fn dispatch_hidden_callback(
    vm_id: u32,
    probe_gva: u64,
    current_pc: u64,
    regs: &[u64; 31],
    phase: HiddenProbePhase,
) -> bool {
    let callback = {
        let registry = GUEST_KPROBE_REGISTRY.lock();
        let Some(registry) = registry.as_ref() else {
            return false;
        };
        let Some(entry) = registry.lookup(vm_id, probe_gva) else {
            return false;
        };
        if entry.state != GuestKprobeState::Enabled || !entry.hidden {
            return false;
        }
        entry.hidden_callback
    };

    if let Some(callback) = callback {
        callback(vm_id, probe_gva, current_pc, regs, phase);
        return true;
    }
    false
}

/// Record one hit for an enabled probe.
pub fn record_probe_hit(vm_id: u32, gva: u64) -> bool {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let Some(registry) = registry.as_mut() else {
        return false;
    };
    if registry.lookup(vm_id, gva).is_none() {
        return false;
    }
    registry.record_hit(vm_id, gva);
    true
}

/// Restore original instruction at probe point before single-step execution.
pub fn restore_insn_for_step(hva: usize, saved_insn: u32) -> Result<(), &'static str> {
    restore_guest_breakpoint(hva, saved_insn)
}

/// Re-inject BRK instruction at probe point after single-step completion.
pub fn reinject_brk(hva: usize) -> Result<(), &'static str> {
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
        Err("reinject_brk not supported on this architecture")
    }
}
