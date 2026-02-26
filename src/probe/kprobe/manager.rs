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
    /// Resolved host virtual address for BRK mode.
    pub resolved_hva: Option<usize>,
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

const STALE_BRK_MAX_ENTRIES: usize = 64;
const STALE_BRK_RETRY_BUDGET: u32 = 4096;

/// Global guest kprobe registry.
static GUEST_KPROBE_REGISTRY: Mutex<Option<GuestKprobeRegistry>> = Mutex::new(None);
static STAGE2_EXEC_HOOK: RwLock<Option<Stage2ExecHook>> = RwLock::new(None);
static STALE_BRK_REGISTRY: Mutex<BTreeMap<ProbeKey, StaleBrkEntry>> = Mutex::new(BTreeMap::new());
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

impl GuestKprobeRegistry {
    pub fn new() -> Self {
        Self {
            probes: BTreeMap::new(),
        }
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
            resolved_hva: None,
        };

        self.probes.insert(key, entry);
        log::info!(
            "guest_kprobe: registered vm{}:{:#x} (mode={:?}, prog={})",
            vm_id, gva, mode, prog_id
        );
        Ok(())
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
                set_stage2_executable(vm_id, gpa, false)?;
                entry.resolved_gpa = Some(gpa);
                log::info!("guest_kprobe: enabling Stage-2 fault mode for vm{}:{:#x}", vm_id, gva);
            }
            KprobeMode::BrkInject => {
                if super::addr_translate::vm_ttbr1_el1(vm_id).is_err() {
                    return Err("VM TTBR1_EL1 is not ready");
                }
                clear_stale_brk(key);
                let hva = super::addr_translate::gva_to_hva_for_vm(gva, vm_id)
                    .map_err(|_| "failed to translate GVA->HVA")?;
                let saved = inject_guest_breakpoint(hva)?;
                entry.saved_insn = Some(saved);
                entry.resolved_hva = Some(hva);
                log::info!(
                    "guest_kprobe: BRK patch vm{}:{:#x} hva={:#x} saved_insn={:#010x}",
                    vm_id,
                    gva,
                    hva,
                    saved
                );
                log::info!("guest_kprobe: enabling BRK inject mode for vm{}:{:#x}", vm_id, gva);
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

        if entry.state == GuestKprobeState::Disabled || entry.state == GuestKprobeState::Registered {
            return Ok(());
        }

        match entry.mode {
            KprobeMode::Stage2Fault => {
                if let Some(gpa) = entry.resolved_gpa {
                    set_stage2_executable(vm_id, gpa, true)?;
                }
                entry.resolved_gpa = None;
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
        self.probes.get(&(vm_id, gva))
            .or_else(|| self.probes.get(&(0, gva)))
    }

    /// Record a hit.
    pub fn record_hit(&mut self, vm_id: u32, gva: u64) {
        if let Some(entry) = self.probes.get_mut(&(vm_id, gva)) {
            entry.hits += 1;
        } else if let Some(entry) = self.probes.get_mut(&(0, gva)) {
            entry.hits += 1;
        }
    }

    /// List all guest kprobes.
    pub fn list(&self) -> Vec<&GuestKprobeEntry> {
        self.probes.values().collect()
    }
}

#[inline]
fn set_stage2_executable(vm_id: u32, gpa: u64, executable: bool) -> Result<(), &'static str> {
    let hook = *STAGE2_EXEC_HOOK.read();
    let Some(f) = hook else {
        return Err("Stage-2 execute hook not registered");
    };
    f(vm_id, gpa, executable).map_err(|_| "failed to update Stage-2 execute permission")
}

fn inject_guest_breakpoint(hva: usize) -> Result<u32, &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        let saved = unsafe { core::ptr::read_volatile(hva as *const u32) };
        unsafe { core::ptr::write_volatile(hva as *mut u32, GUEST_BRK_INSN) };
        crate::cache::flush_icache_range(hva, hva + core::mem::size_of::<u32>());
        return Ok(saved);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let saved = unsafe { core::ptr::read_volatile(hva as *const u8) };
        unsafe { core::ptr::write_volatile(hva as *mut u8, GUEST_BRK_INSN as u8) };
        return Ok(saved as u32);
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
        return Ok(());
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::ptr::write_volatile(hva as *mut u8, saved_insn as u8) };
        return Ok(());
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

// === Module-level convenience functions ===

pub fn init() {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    if registry.is_none() {
        *registry = Some(GuestKprobeRegistry::new());
        log::info!("guest_kprobe: subsystem initialized");
    }
}

pub fn register_stage2_exec_hook(f: Stage2ExecHook) {
    *STAGE2_EXEC_HOOK.write() = Some(f);
}

#[cfg(any(test, feature = "test-utils"))]
pub fn clear_stage2_exec_hook_for_test() {
    *STAGE2_EXEC_HOOK.write() = None;
}

pub fn register(
    vm_id: u32,
    gva: u64,
    prog_id: u32,
    is_ret: bool,
    mode: KprobeMode,
) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("guest kprobe not initialized")?;
    registry.register(vm_id, gva, prog_id, is_ret, mode)
}

pub fn enable(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("guest kprobe not initialized")?;
    registry.enable(vm_id, gva)
}

pub fn disable(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("guest kprobe not initialized")?;
    registry.disable(vm_id, gva)
}

pub fn unregister(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("guest kprobe not initialized")?;
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
        let _ = unregister(vm_id, gva);
        return Err(e);
    }
    Ok(())
}

pub fn detach(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    unregister(vm_id, gva)
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
pub fn install_mock_backend_fail_on_enable(vm_id: u32, gva: u64) {
    *MOCK_FAIL_ENABLE_TARGET.lock() = Some((vm_id, gva));
}

pub fn list_all() -> Vec<(u32, u64, Option<String>, u64, bool, bool, u32, KprobeMode)> {
    let registry = GUEST_KPROBE_REGISTRY.lock();
    match registry.as_ref() {
        Some(r) => r.list().iter().map(|e| {
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
        }).collect(),
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
