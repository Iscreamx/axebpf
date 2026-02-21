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

#[inline]
fn arg_at(regs: &kprobe::PtRegs, idx: usize) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        return regs.regs[idx];
    }
    #[cfg(target_arch = "x86_64")]
    {
        return match idx {
            0 => regs.rdi as u64,
            1 => regs.rsi as u64,
            2 => regs.rdx as u64,
            3 => regs.rcx as u64,
            _ => 0,
        };
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (regs, idx);
        0
    }
}

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

/// One probe slot for either entry probe or return probe.
struct ProbeSlot {
    /// Hit count collected at breakpoint handling time.
    hits: u64,
    /// Slot state.
    state: KprobeState,
    /// Associated eBPF program ID.
    prog_id: u32,
    /// Handle to the underlying kprobe library object.
    handle: Option<ProbeHandle>,
}

impl ProbeSlot {
    fn new(prog_id: u32) -> Self {
        Self {
            hits: 0,
            state: KprobeState::Disabled,
            prog_id,
            handle: None,
        }
    }
}

/// One address can host both an entry probe and a return probe.
struct ProbePairEntry {
    /// Symbol name.
    name: String,
    /// Probe address.
    addr: usize,
    /// Entry probe slot (`hprobe`).
    entry_slot: Option<ProbeSlot>,
    /// Return probe slot (`hretprobe`).
    ret_slot: Option<ProbeSlot>,
}

/// Global kprobe registry
pub(super) static KPROBE_REGISTRY: Mutex<Option<KprobeRegistry>> = Mutex::new(None);

/// Kprobe registry
pub struct KprobeRegistry {
    /// Registered probe pairs by address.
    probes: BTreeMap<usize, ProbePairEntry>,
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

    fn slot_mut(entry: &mut ProbePairEntry, is_ret: bool) -> &mut Option<ProbeSlot> {
        if is_ret {
            &mut entry.ret_slot
        } else {
            &mut entry.entry_slot
        }
    }

    fn slot_ref(entry: &ProbePairEntry, is_ret: bool) -> &Option<ProbeSlot> {
        if is_ret {
            &entry.ret_slot
        } else {
            &entry.entry_slot
        }
    }

    fn register_with_addr(
        &mut self,
        name: &str,
        addr: usize,
        prog_id: u32,
        is_ret: bool,
    ) -> Result<usize, &'static str> {
        if let Some(existing_addr) = self.name_map.get(name).copied() {
            if existing_addr != addr {
                return Err("kprobe symbol already registered at different address");
            }
        }

        if let Some(existing) = self.probes.get(&addr) {
            if existing.name != name {
                return Err("kprobe already registered at this address");
            }
        }

        let entry = self.probes.entry(addr).or_insert_with(|| ProbePairEntry {
            name: String::from(name),
            addr,
            entry_slot: None,
            ret_slot: None,
        });

        let slot = Self::slot_mut(entry, is_ret);
        if slot.is_some() {
            return Err("kprobe already registered at this address");
        }
        *slot = Some(ProbeSlot::new(prog_id));

        self.name_map.insert(String::from(name), addr);
        log::info!(
            "kprobe: registering {} at {:#x} (is_ret={}, prog_id={})",
            name,
            addr,
            is_ret,
            prog_id
        );

        Ok(addr)
    }

    /// Register a kprobe by symbol name.
    pub fn register(
        &mut self,
        name: &str,
        prog_id: u32,
        is_ret: bool,
    ) -> Result<usize, &'static str> {
        let addr = symbols::lookup_addr(name).ok_or("symbol not found")? as usize;
        self.register_with_addr(name, addr, prog_id, is_ret)
    }

    /// Enable a kprobe (insert breakpoint).
    pub fn enable(&mut self, addr: usize, is_ret: bool) -> Result<(), &'static str> {
        let entry = self.probes.get_mut(&addr).ok_or("kprobe not found")?;
        let symbol = entry.name.clone();
        let slot_ro = Self::slot_ref(entry, is_ret)
            .as_ref()
            .ok_or("kprobe not found")?;
        let prog_id = slot_ro.prog_id;
        let already_enabled = slot_ro.state == KprobeState::Enabled;
        if already_enabled {
            return Ok(());
        }

        let handle = if is_ret {
            let ret_builder = kprobe::KretprobeBuilder::<LockType>::new(16)
                .with_symbol_addr(addr)
                .with_symbol(symbol.clone())
                .with_enable(true)
                .with_entry_handler(kprobe_entry_handler)
                .with_ret_handler(kprobe_ret_handler)
                .with_data(HprobeUserData {
                    prog_id,
                    probe_addr: addr,
                    symbol: symbol.clone(),
                });

            let kretprobe =
                kprobe::register_kretprobe(&mut self.manager, &mut self.probe_points, ret_builder);
            ProbeHandle::Kretprobe(kretprobe)
        } else {
            let builder = kprobe::ProbeBuilder::<AxKprobeOps>::new()
                .with_symbol_addr(addr)
                .with_symbol(symbol.clone())
                .with_enable(true)
                .with_pre_handler(kprobe_pre_handler)
                .with_data(HprobeUserData {
                    prog_id,
                    probe_addr: addr,
                    symbol: symbol.clone(),
                });

            let kp = kprobe::register_kprobe(&mut self.manager, &mut self.probe_points, builder);
            ProbeHandle::Kprobe(kp)
        };

        let slot = Self::slot_mut(entry, is_ret)
            .as_mut()
            .ok_or("kprobe not found")?;
        slot.handle = Some(handle);
        slot.state = KprobeState::Enabled;
        log::info!(
            "kprobe: enabled {} at {:#x} (is_ret={})",
            symbol,
            addr,
            is_ret
        );
        Ok(())
    }

    /// Disable one probe slot (entry or ret) and restore original instruction if needed.
    pub fn disable(&mut self, addr: usize, is_ret: bool) -> Result<(), &'static str> {
        let entry = self.probes.get_mut(&addr).ok_or("kprobe not found")?;
        let slot = Self::slot_mut(entry, is_ret)
            .as_mut()
            .ok_or("kprobe not found")?;

        if slot.state == KprobeState::Disabled {
            return Ok(());
        }

        if let Some(handle) = slot.handle.take() {
            match handle {
                ProbeHandle::Kprobe(kp) => {
                    kprobe::unregister_kprobe(&mut self.manager, &mut self.probe_points, kp);
                }
                ProbeHandle::Kretprobe(krp) => {
                    kprobe::unregister_kretprobe(&mut self.manager, &mut self.probe_points, krp);
                }
            }
        }

        slot.state = KprobeState::Disabled;
        log::info!(
            "kprobe: disabled {} at {:#x} (is_ret={})",
            entry.name,
            addr,
            is_ret
        );
        Ok(())
    }

    /// Unregister one probe slot (entry or ret).
    pub fn unregister(&mut self, addr: usize, is_ret: bool) -> Result<(), &'static str> {
        self.disable(addr, is_ret)?;

        let mut remove_pair = false;
        let mut remove_name: Option<String> = None;
        {
            let entry = self.probes.get_mut(&addr).ok_or("kprobe not found")?;
            let slot = Self::slot_mut(entry, is_ret);
            if slot.is_none() {
                return Err("kprobe not found");
            }
            *slot = None;
            if entry.entry_slot.is_none() && entry.ret_slot.is_none() {
                remove_pair = true;
                remove_name = Some(entry.name.clone());
            }
        }

        if remove_pair {
            self.probes.remove(&addr);
            if let Some(name) = remove_name {
                self.name_map.remove(&name);
                log::info!("kprobe: unregistered {} at {:#x}", name, addr);
            }
        }

        Ok(())
    }

    /// Get address by name.
    pub fn get_addr_by_name(&self, name: &str) -> Option<usize> {
        self.name_map.get(name).copied()
    }

    /// Disable and unregister all slots for one symbol.
    pub fn unregister_by_name(&mut self, name: &str) -> Result<(), &'static str> {
        let addr = self.get_addr_by_name(name).ok_or("kprobe not found")?;

        let (has_entry, has_ret) = {
            let entry = self.probes.get(&addr).ok_or("kprobe not found")?;
            (entry.entry_slot.is_some(), entry.ret_slot.is_some())
        };

        if has_entry {
            self.unregister(addr, false)?;
        }
        if has_ret {
            self.unregister(addr, true)?;
        }
        Ok(())
    }

    /// Collect flat view used by shell command display.
    pub fn list_flat(&self) -> Vec<(String, usize, u64, bool, bool, u32)> {
        let mut out = Vec::new();
        for entry in self.probes.values() {
            if let Some(slot) = Self::slot_ref(entry, false).as_ref() {
                out.push((
                    entry.name.clone(),
                    entry.addr,
                    slot.hits,
                    slot.state == KprobeState::Enabled,
                    false,
                    slot.prog_id,
                ));
            }
            if let Some(slot) = Self::slot_ref(entry, true).as_ref() {
                out.push((
                    entry.name.clone(),
                    entry.addr,
                    slot.hits,
                    slot.state == KprobeState::Enabled,
                    true,
                    slot.prog_id,
                ));
            }
        }
        out
    }

    /// Record hits at breakpoint entry.
    /// Returns `(entry_slot_hit, ret_slot_hit)`.
    pub fn record_break_hit(&mut self, addr: usize) -> (bool, bool) {
        let mut entry_hit = false;
        let mut ret_hit = false;

        if let Some(entry) = self.probes.get_mut(&addr) {
            if let Some(slot) = entry.entry_slot.as_mut() {
                slot.hits += 1;
                entry_hit = true;
            }
            if let Some(slot) = entry.ret_slot.as_mut() {
                slot.hits += 1;
                ret_hit = true;
            }
        }

        (entry_hit, ret_hit)
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
                ud.symbol,
                arg_at(regs, 0),
                arg_at(regs, 1),
                arg_at(regs, 2),
                arg_at(regs, 3)
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
                ud.symbol,
                arg_at(regs, 0)
            );
        }

        #[cfg(feature = "tracepoint-support")]
        emit_hretprobe_event(ud.probe_addr, arg_at(pt_regs, 0));
    }
}

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
fn emit_hretprobe_event(probe_addr: usize, retval: u64) {
    let mut event =
        crate::event::TraceEvent::new(crate::event::PROBE_HRETPROBE, probe_addr as u32);
    event.name_offset = crate::event::register_event_name("hretprobe");
    event.nr_args = 1;
    event.args[0] = retval;
    crate::event::emit_event(&event);
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

/// Enable a kprobe slot.
pub fn enable(addr: usize, is_ret: bool) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.enable(addr, is_ret)
}

/// Disable a kprobe slot.
pub fn disable(addr: usize, is_ret: bool) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.disable(addr, is_ret)
}

/// Unregister a kprobe slot.
pub fn unregister(addr: usize, is_ret: bool) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.unregister(addr, is_ret)
}

/// List all kprobes for shell command.
pub fn list_all() -> Vec<(String, usize, u64, bool, bool, u32)> {
    let registry = KPROBE_REGISTRY.lock();
    match registry.as_ref() {
        Some(r) => r.list_flat(),
        None => Vec::new(),
    }
}

/// Register and enable a kprobe by name.
pub fn attach(name: &str, prog_id: u32, is_ret: bool) -> Result<usize, &'static str> {
    let addr = register(name, prog_id, is_ret)?;
    if let Err(e) = enable(addr, is_ret) {
        let _ = unregister(addr, is_ret);
        return Err(e);
    }
    Ok(addr)
}

/// Disable and unregister a kprobe by name.
pub fn detach(name: &str) -> Result<(), &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.unregister_by_name(name)
}

#[cfg(feature = "test-utils")]
/// Test helper: register one slot using a synthetic address, bypassing symbol lookup.
pub fn register_with_addr_for_test(
    name: &str,
    addr: usize,
    prog_id: u32,
    is_ret: bool,
) -> Result<usize, &'static str> {
    let mut registry = KPROBE_REGISTRY.lock();
    let registry = registry.as_mut().ok_or("kprobe subsystem not initialized")?;
    registry.register_with_addr(name, addr, prog_id, is_ret)
}

#[cfg(all(feature = "test-utils", feature = "runtime", feature = "tracepoint-support"))]
/// Test helper: emit one synthetic hretprobe event without trap handling.
pub fn emit_hretprobe_event_for_test(probe_addr: usize, retval: u64) {
    emit_hretprobe_event(probe_addr, retval);
}
