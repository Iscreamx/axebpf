//! Kprobe manager for AxVisor.
//!
//! Provides high-level API for registering, unregistering, and triggering kprobes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::probe::hprobe::ops::AxKprobeOps;
use crate::symbols;

/// Lock type alias for the kprobe library
type LockType = spin::Mutex<()>;

/// User data attached to each probe instance.
/// Passed to callbacks via `ProbeData`, avoiding lock-table lookups.
#[derive(Clone, Debug)]
struct HprobeUserData {
    prog_id: u32,
    probe_addr: usize,
    symbol: String,
}

/// Kprobe state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KprobeState {
    /// Kprobe is registered but not active
    Disabled,
    /// Kprobe is active and will trigger on function entry
    Enabled,
}

/// Handle to a registered probe in the kprobe library.
/// Dropping this handle triggers instruction restoration and slot cleanup.
enum ProbeHandle {
    Kprobe(Arc<kprobe::Kprobe<LockType, AxKprobeOps>>),
    Kretprobe(Arc<kprobe::Kretprobe<LockType, AxKprobeOps>>),
}

/// Kprobe entry for tracking registered probes
pub struct KprobeEntry {
    /// Symbol name
    pub name: String,
    /// Probe address
    pub addr: usize,
    /// Hit count
    pub hits: u64,
    /// State
    pub state: KprobeState,
    /// Is this a kretprobe?
    pub is_ret: bool,
    /// Associated eBPF program ID
    pub prog_id: u32,
    /// Handle to the kprobe library probe, used for proper unregistration
    handle: Option<ProbeHandle>,
}

/// Global kprobe registry
pub(super) static KPROBE_REGISTRY: Mutex<Option<KprobeRegistry>> = Mutex::new(None);

/// Kprobe registry
pub struct KprobeRegistry {
    /// Registered kprobes by address
    probes: BTreeMap<usize, KprobeEntry>,
    /// Name to address mapping
    name_map: BTreeMap<String, usize>,
    /// The kprobe library's probe manager
    manager: kprobe::ProbeManager<LockType, AxKprobeOps>,
    /// Probe point list
    probe_points: kprobe::ProbePointList<AxKprobeOps>,
}

impl KprobeRegistry {
    /// Create a new kprobe registry
    pub fn new() -> Self {
        Self {
            probes: BTreeMap::new(),
            name_map: BTreeMap::new(),
            manager: kprobe::ProbeManager::new(),
            probe_points: kprobe::ProbePointList::new(),
        }
    }

    /// Register a kprobe by symbol name.
    pub fn register(&mut self, name: &str, prog_id: u32, is_ret: bool) -> Result<usize, &'static str> {
        // Look up symbol address
        let addr = symbols::lookup_addr(name).ok_or("symbol not found")? as usize;

        if self.probes.contains_key(&addr) {
            return Err("kprobe already registered at this address");
        }

        log::info!(
            "kprobe: registering {} at {:#x} (is_ret={}, prog_id={})",
            name, addr, is_ret, prog_id
        );

        let entry = KprobeEntry {
            name: String::from(name),
            addr,
            hits: 0,
            state: KprobeState::Disabled,
            is_ret,
            prog_id,
            handle: None,
        };

        self.probes.insert(addr, entry);
        self.name_map.insert(String::from(name), addr);

        Ok(addr)
    }

    /// Enable a kprobe (insert breakpoint).
    pub fn enable(&mut self, addr: usize) -> Result<(), &'static str> {
        let entry = self.probes.get_mut(&addr).ok_or("kprobe not found")?;

        if entry.state == KprobeState::Enabled {
            return Ok(());
        }

        let handle = if entry.is_ret {
            // For kretprobe, use the kretprobe builder with user data
            let ret_builder = kprobe::KretprobeBuilder::<LockType>::new(16) // maxactive = 16
                .with_symbol_addr(addr)
                .with_symbol(entry.name.clone())
                .with_enable(true)
                .with_entry_handler(kprobe_entry_handler)
                .with_ret_handler(kprobe_ret_handler)
                .with_data(HprobeUserData { prog_id: entry.prog_id, probe_addr: addr, symbol: entry.name.clone() });

            let kretprobe = kprobe::register_kretprobe(
                &mut self.manager,
                &mut self.probe_points,
                ret_builder,
            );
            ProbeHandle::Kretprobe(kretprobe)
        } else {
            // For kprobe, use the probe builder with user data
            let builder = kprobe::ProbeBuilder::<AxKprobeOps>::new()
                .with_symbol_addr(addr)
                .with_symbol(entry.name.clone())
                .with_enable(true)
                .with_pre_handler(kprobe_pre_handler)
                .with_data(HprobeUserData { prog_id: entry.prog_id, probe_addr: addr, symbol: entry.name.clone() });

            let kp = kprobe::register_kprobe(
                &mut self.manager,
                &mut self.probe_points,
                builder,
            );
            ProbeHandle::Kprobe(kp)
        };

        entry.handle = Some(handle);
        entry.state = KprobeState::Enabled;
        log::info!("kprobe: enabled {} at {:#x}", entry.name, addr);

        Ok(())
    }

    /// Disable a kprobe (restore original instruction).
    pub fn disable(&mut self, addr: usize) -> Result<(), &'static str> {
        let entry = self.probes.get_mut(&addr).ok_or("kprobe not found")?;

        if entry.state == KprobeState::Disabled {
            return Ok(());
        }

        // Take the handle out and unregister via the kprobe library.
        // This triggers Drop on ProbePoint, which restores the original
        // instruction and frees the instruction slot.
        if let Some(handle) = entry.handle.take() {
            match handle {
                ProbeHandle::Kprobe(kp) => {
                    kprobe::unregister_kprobe(
                        &mut self.manager,
                        &mut self.probe_points,
                        kp,
                    );
                }
                ProbeHandle::Kretprobe(krp) => {
                    kprobe::unregister_kretprobe(
                        &mut self.manager,
                        &mut self.probe_points,
                        krp,
                    );
                }
            }
        }

        entry.state = KprobeState::Disabled;
        log::info!("kprobe: disabled {} at {:#x}", entry.name, addr);

        Ok(())
    }

    /// Unregister a kprobe.
    pub fn unregister(&mut self, addr: usize) -> Result<(), &'static str> {
        // Disable first if enabled
        self.disable(addr)?;

        let entry = self.probes.remove(&addr).ok_or("kprobe not found")?;
        self.name_map.remove(&entry.name);

        log::info!("kprobe: unregistered {} at {:#x}", entry.name, addr);
        Ok(())
    }

    /// Look up a kprobe by address.
    pub fn get(&self, addr: usize) -> Option<&KprobeEntry> {
        self.probes.get(&addr)
    }

    /// Look up a kprobe by address (mutable).
    pub fn get_mut(&mut self, addr: usize) -> Option<&mut KprobeEntry> {
        self.probes.get_mut(&addr)
    }

    /// Look up a kprobe by name.
    pub fn get_by_name(&self, name: &str) -> Option<&KprobeEntry> {
        self.name_map.get(name).and_then(|addr| self.probes.get(addr))
    }

    /// Get address by name.
    pub fn get_addr_by_name(&self, name: &str) -> Option<usize> {
        self.name_map.get(name).copied()
    }

    /// List all registered kprobes.
    pub fn list(&self) -> Vec<&KprobeEntry> {
        self.probes.values().collect()
    }

    /// Record a hit for a kprobe.
    pub fn record_hit(&mut self, addr: usize) {
        if let Some(entry) = self.probes.get_mut(&addr) {
            entry.hits += 1;
        }
    }

    /// Get mutable reference to the probe manager for exception handling.
    pub fn manager_mut(&mut self) -> &mut kprobe::ProbeManager<LockType, AxKprobeOps> {
        &mut self.manager
    }
}

/// Pre-handler for kprobe (non-ret): execute eBPF on function entry.
/// Retrieves prog_id from user_data instead of locking the registry.
fn kprobe_pre_handler(data: &dyn kprobe::ProbeData, pt_regs: &mut kprobe::PtRegs) {
    let Some(ud) = data.as_any().downcast_ref::<HprobeUserData>() else {
        return;
    };

    #[cfg(feature = "runtime")]
    {
        let ctx_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                pt_regs as *mut kprobe::PtRegs as *mut u8,
                core::mem::size_of::<kprobe::PtRegs>(),
            )
        };
        if let Err(e) = crate::runtime::run_program(ud.prog_id, Some(ctx_bytes)) {
            log::warn!("hprobe: eBPF execution failed at {:#x}: {:?}", ud.probe_addr, e);
        }

        if crate::attach::is_verbose() {
            let regs = &*pt_regs;
            log::info!(
                "[hprobe] ENTRY {} x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
                ud.symbol, regs.regs[0], regs.regs[1], regs.regs[2], regs.regs[3]
            );
        }
    }
}

/// Entry handler for kretprobe: called at function entry before LR replacement.
/// No eBPF execution here; the return handler runs eBPF on function return.
fn kprobe_entry_handler(_data: &dyn kprobe::ProbeData, _pt_regs: &mut kprobe::PtRegs) {
    // Intentionally empty: for kretprobe, eBPF runs on return, not entry.
}

/// Return handler for kretprobe: execute eBPF when the probed function returns.
/// Called from the kprobe library's trampoline mechanism.
fn kprobe_ret_handler(data: &dyn kprobe::ProbeData, pt_regs: &mut kprobe::PtRegs) {
    let Some(ud) = data.as_any().downcast_ref::<HprobeUserData>() else {
        return;
    };

    #[cfg(feature = "runtime")]
    {
        let ctx_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                pt_regs as *mut kprobe::PtRegs as *mut u8,
                core::mem::size_of::<kprobe::PtRegs>(),
            )
        };
        if let Err(e) = crate::runtime::run_program(ud.prog_id, Some(ctx_bytes)) {
            log::warn!("hretprobe: eBPF execution failed at {:#x}: {:?}", ud.probe_addr, e);
        }

        if crate::attach::is_verbose() {
            let regs = &*pt_regs;
            log::info!(
                "[hprobe] EXIT {} retval={:#x}",
                ud.symbol, regs.regs[0]
            );
        }
    }
}

/// Initialize the kprobe subsystem.
pub fn init() {
    static INITIALIZED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    if INITIALIZED.swap(true, core::sync::atomic::Ordering::SeqCst) {
        return; // Already initialized
    }

    let mut registry = KPROBE_REGISTRY.lock();
    if registry.is_none() {
        *registry = Some(KprobeRegistry::new());
    }
    drop(registry);

    log::info!("kprobe: subsystem initialized");
}

/// Register a kprobe by symbol name.
pub fn register(name: &str, prog_id: u32, is_ret: bool) -> Result<usize, &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.register(name, prog_id, is_ret)
}

/// Enable a kprobe.
pub fn enable(addr: usize) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.enable(addr)
}

/// Disable a kprobe.
pub fn disable(addr: usize) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.disable(addr)
}

/// Unregister a kprobe.
pub fn unregister(addr: usize) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.unregister(addr)
}

/// List all kprobes for shell command.
pub fn list_all() -> Vec<(String, usize, u64, bool, bool, u32)> {
    let registry = KPROBE_REGISTRY.lock();
    match registry.as_ref() {
        Some(r) => r.list().iter().map(|e| {
            (e.name.clone(), e.addr, e.hits, e.state == KprobeState::Enabled, e.is_ret, e.prog_id)
        }).collect(),
        None => Vec::new(),
    }
}

/// Register and enable a kprobe by name.
pub fn attach(name: &str, prog_id: u32, is_ret: bool) -> Result<usize, &'static str> {
    let addr = register(name, prog_id, is_ret)?;
    enable(addr)?;
    Ok(addr)
}

/// Disable and unregister a kprobe by name.
pub fn detach(name: &str) -> Result<(), &'static str> {
    let registry = KPROBE_REGISTRY.lock();
    let addr = registry.as_ref()
        .and_then(|r| r.get_addr_by_name(name))
        .ok_or("kprobe not found")?;
    drop(registry);

    unregister(addr)
}
