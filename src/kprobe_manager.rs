//! Kprobe manager for AxVisor.
//!
//! Provides high-level API for registering, unregistering, and triggering kprobes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::kprobe_ops::AxKprobeOps;
use crate::symbols;

/// Lock type alias for the kprobe library
type LockType = spin::Mutex<()>;

/// Kprobe state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KprobeState {
    /// Kprobe is registered but not active
    Disabled,
    /// Kprobe is active and will trigger on function entry
    Enabled,
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
}

/// Global kprobe registry
static KPROBE_REGISTRY: Mutex<Option<KprobeRegistry>> = Mutex::new(None);

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
    pub fn register(&mut self, name: &str, is_ret: bool) -> Result<usize, &'static str> {
        // Look up symbol address
        let addr = symbols::lookup_addr(name).ok_or("symbol not found")? as usize;

        if self.probes.contains_key(&addr) {
            return Err("kprobe already registered at this address");
        }

        log::info!(
            "kprobe: registering {} at {:#x} (is_ret={})",
            name, addr, is_ret
        );

        let entry = KprobeEntry {
            name: String::from(name),
            addr,
            hits: 0,
            state: KprobeState::Disabled,
            is_ret,
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

        // Build and register the kprobe with the library
        let builder = kprobe::ProbeBuilder::<AxKprobeOps>::new()
            .with_symbol_addr(addr)
            .with_symbol(entry.name.clone())
            .with_enable(true)
            .with_pre_handler(kprobe_pre_handler);

        if entry.is_ret {
            // For kretprobe, use the kretprobe builder
            let ret_builder = kprobe::KretprobeBuilder::<LockType>::new(16) // maxactive = 16
                .with_symbol_addr(addr)
                .with_symbol(entry.name.clone())
                .with_enable(true)
                .with_entry_handler(kprobe_pre_handler)
                .with_ret_handler(kprobe_post_handler);

            let _kretprobe = kprobe::register_kretprobe(
                &mut self.manager,
                &mut self.probe_points,
                ret_builder,
            );
        } else {
            let _kprobe = kprobe::register_kprobe(
                &mut self.manager,
                &mut self.probe_points,
                builder,
            );
        }

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

        // TODO: Implement proper unregistration with the kprobe library
        // For now, just mark as disabled
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

/// Pre-handler callback for kprobes
fn kprobe_pre_handler(_data: &dyn kprobe::ProbeData, _pt_regs: &mut kprobe::PtRegs) {
    // Note: break_address is private in the kprobe crate, so we can't get the address here.
    // The hit counting is done via the probe point mechanism instead.
    log::debug!("kprobe: pre_handler triggered");
}

/// Post-handler callback for kretprobes
fn kprobe_post_handler(_data: &dyn kprobe::ProbeData, _pt_regs: &mut kprobe::PtRegs) {
    log::debug!("kprobe: post_handler triggered");
}

/// Initialize the kprobe subsystem.
pub fn init() {
    let mut registry = KPROBE_REGISTRY.lock();
    if registry.is_none() {
        *registry = Some(KprobeRegistry::new());
        log::info!("kprobe: subsystem initialized");
    }
}

/// Register a kprobe by symbol name.
pub fn register(name: &str, is_ret: bool) -> Result<usize, &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.register(name, is_ret)
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

/// Look up kprobe by address.
pub fn lookup(addr: usize) -> Option<bool> {
    let registry = KPROBE_REGISTRY.lock();
    registry.as_ref().and_then(|r| r.get(addr).map(|e| e.state == KprobeState::Enabled))
}

/// Record a kprobe hit.
pub fn record_hit(addr: usize) {
    let mut registry = KPROBE_REGISTRY.lock();
    if let Some(registry) = registry.as_mut() {
        registry.record_hit(addr);
    }
}

/// List all kprobes for shell command.
pub fn list_all() -> Vec<(String, usize, u64, bool, bool)> {
    let registry = KPROBE_REGISTRY.lock();
    match registry.as_ref() {
        Some(r) => r.list().iter().map(|e| {
            (e.name.clone(), e.addr, e.hits, e.state == KprobeState::Enabled, e.is_ret)
        }).collect(),
        None => Vec::new(),
    }
}

/// Register and enable a kprobe by name.
pub fn attach(name: &str, is_ret: bool) -> Result<usize, &'static str> {
    let addr = register(name, is_ret)?;
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
