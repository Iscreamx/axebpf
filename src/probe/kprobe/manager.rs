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
}

/// Key for identifying a guest kprobe: (vm_id, gva).
type ProbeKey = (u32, u64);

/// Global guest kprobe registry.
static GUEST_KPROBE_REGISTRY: Mutex<Option<GuestKprobeRegistry>> = Mutex::new(None);

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

        match entry.mode {
            KprobeMode::Stage2Fault => {
                // TODO: Translate GVA→GPA, then modify Stage-2 XN bit
                log::info!("guest_kprobe: enabling Stage-2 fault mode for vm{}:{:#x}", vm_id, gva);
            }
            KprobeMode::BrkInject => {
                // TODO: Translate GVA→HVA, save original insn, write BRK
                log::info!("guest_kprobe: enabling BRK inject mode for vm{}:{:#x}", vm_id, gva);
            }
        }

        entry.state = GuestKprobeState::Enabled;
        Ok(())
    }

    /// Disable a guest kprobe.
    pub fn disable(&mut self, vm_id: u32, gva: u64) -> Result<(), &'static str> {
        let key = (vm_id, gva);
        let entry = self.probes.get_mut(&key).ok_or("guest kprobe not found")?;

        if entry.state == GuestKprobeState::Disabled || entry.state == GuestKprobeState::Registered {
            return Ok(());
        }

        match entry.mode {
            KprobeMode::Stage2Fault => {
                // TODO: Restore Stage-2 page execute permission
            }
            KprobeMode::BrkInject => {
                // TODO: Restore original instruction
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
        self.probes.remove(&key).ok_or("guest kprobe not found")?;
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

// === Module-level convenience functions ===

pub fn init() {
    let mut registry = GUEST_KPROBE_REGISTRY.lock();
    if registry.is_none() {
        *registry = Some(GuestKprobeRegistry::new());
        log::info!("guest_kprobe: subsystem initialized");
    }
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
    enable(vm_id, gva)
}

pub fn detach(vm_id: u32, gva: u64) -> Result<(), &'static str> {
    unregister(vm_id, gva)
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
