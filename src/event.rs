//! Unified trace event format and built-in event pipeline.
//!
//! All probe sources write `TraceEvent` records through `emit_event()`.
//! Events are best-effort written to RingBuf, while a local fallback queue
//! guarantees shell consumption even when RingBuf map push/pop is unavailable.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::maps::{self, MapDef, MapType};
use crate::platform;

/// Probe type identifiers stored in `TraceEvent::probe_type`.
pub const PROBE_TRACEPOINT: u8 = 0;
pub const PROBE_HPROBE: u8 = 1;
pub const PROBE_HRETPROBE: u8 = 2;
pub const PROBE_KPROBE: u8 = 3;
pub const PROBE_KRETPROBE: u8 = 4;

const PAGE_SIZE: u32 = 4096;
const DEFAULT_RINGBUF_SIZE: u32 = 64 * 1024;
const FALLBACK_QUEUE_CAPACITY: usize = 8192;

/// Unified trace event record.
///
/// Fixed 64-byte layout keeps event parsing straightforward and cache-friendly.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct TraceEvent {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Probe type (`PROBE_TRACEPOINT`, `PROBE_HPROBE`, ...).
    pub probe_type: u8,
    /// Physical CPU ID.
    pub cpu_id: u8,
    /// VM ID (0 = host/VMM, >0 = guest).
    pub vm_id: u16,
    /// Event identifier (tracepoint ID or probe key).
    pub event_id: u32,
    /// Index into the global event-name table.
    pub name_offset: u16,
    /// Number of valid args in `args`.
    pub nr_args: u8,
    /// Padding to keep 8-byte alignment.
    pub _pad: u8,
    /// Generic argument slots.
    pub args: [u64; 4],
    /// Optional duration in nanoseconds.
    pub duration_ns: u64,
}

const _: () = assert!(core::mem::size_of::<TraceEvent>() == 64);

impl TraceEvent {
    /// Create a new event with common metadata pre-filled.
    pub fn new(probe_type: u8, event_id: u32) -> Self {
        Self {
            timestamp_ns: platform::time_ns(),
            probe_type,
            cpu_id: platform::cpu_id() as u8,
            vm_id: 0,
            event_id,
            name_offset: 0,
            nr_args: 0,
            _pad: 0,
            args: [0; 4],
            duration_ns: 0,
        }
    }

    /// View this event as raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Parse one event from a raw byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < core::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Self) })
    }

    /// Human-readable probe type.
    pub fn probe_type_str(&self) -> &'static str {
        match self.probe_type {
            PROBE_TRACEPOINT => "tracepoint",
            PROBE_HPROBE => "hprobe",
            PROBE_HRETPROBE => "hretprobe",
            PROBE_KPROBE => "kprobe",
            PROBE_KRETPROBE => "kretprobe",
            _ => "unknown",
        }
    }
}

// =============================================================================
// Global Name Tables
// =============================================================================

/// Maps name offset -> event name.
static NAME_TABLE: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Maps event id -> name offset, used by `trace stat` display.
static EVENT_NAME_MAP: Mutex<BTreeMap<u32, u16>> = Mutex::new(BTreeMap::new());

/// Register an event name and return its offset.
pub fn register_event_name(name: &str) -> u16 {
    let mut table = NAME_TABLE.lock();

    for (idx, existing) in table.iter().enumerate() {
        if existing == name {
            return idx as u16;
        }
    }

    if table.len() >= u16::MAX as usize {
        log::warn!("event name table is full, dropping '{}'", name);
        return u16::MAX;
    }

    let idx = table.len() as u16;
    table.push(name.to_string());
    idx
}

/// Look up event name by offset.
pub fn get_event_name(offset: u16) -> Option<String> {
    let table = NAME_TABLE.lock();
    table.get(offset as usize).cloned()
}

/// Look up event name by event id.
pub fn event_name_for_id(event_id: u32) -> Option<String> {
    let offset = EVENT_NAME_MAP.lock().get(&event_id).copied()?;
    get_event_name(offset)
}

fn remember_event_name(event_id: u32, name_offset: u16) {
    if name_offset == u16::MAX {
        return;
    }
    EVENT_NAME_MAP.lock().entry(event_id).or_insert(name_offset);
}

// =============================================================================
// Global RingBuf + Fallback Queue
// =============================================================================

/// Global trace RingBuf map FD (`None` means uninitialized).
static RINGBUF_FD: Mutex<Option<u32>> = Mutex::new(None);

/// Fallback software queue used when RingBuf map operations are unavailable.
static FALLBACK_EVENTS: Mutex<VecDeque<TraceEvent>> = Mutex::new(VecDeque::new());

/// Initialize the global trace RingBuf with default size.
pub fn init_ringbuf() {
    init_ringbuf_with_size(DEFAULT_RINGBUF_SIZE / 1024);
}

/// Initialize the global trace RingBuf with a custom size in KB.
///
/// `size_kb` must translate to a power-of-two byte size and be page aligned.
pub fn init_ringbuf_with_size(size_kb: u32) {
    let size_bytes = match size_kb.checked_mul(1024) {
        Some(v) => v,
        None => {
            log::error!("invalid RingBuf size: {}KB", size_kb);
            return;
        }
    };

    if size_bytes == 0 || (size_bytes & (size_bytes - 1)) != 0 || (size_bytes % PAGE_SIZE) != 0 {
        log::error!("RingBuf size must be power-of-2 and page-aligned, got {}KB", size_kb);
        return;
    }

    let def = MapDef {
        map_type: MapType::RingBuf,
        key_size: 0,
        value_size: 0,
        max_entries: size_bytes,
    };

    match maps::create(&def) {
        Ok(fd) => {
            *RINGBUF_FD.lock() = Some(fd);
            log::info!("Trace RingBuf initialized: fd={}, size={}KB", fd, size_kb);
        }
        Err(e) => {
            log::error!("failed to create trace RingBuf ({}KB): {:?}", size_kb, e);
        }
    }
}

/// Get the current RingBuf map FD.
pub fn ringbuf_fd() -> Option<u32> {
    *RINGBUF_FD.lock()
}

fn fallback_push(event: TraceEvent) {
    let mut q = FALLBACK_EVENTS.lock();
    if q.len() >= FALLBACK_QUEUE_CAPACITY {
        let _ = q.pop_front();
    }
    q.push_back(event);
}

fn fallback_pop(max_events: usize) -> Vec<TraceEvent> {
    let mut q = FALLBACK_EVENTS.lock();
    let mut out = Vec::new();
    let limit = if max_events == 0 { usize::MAX } else { max_events };

    while out.len() < limit {
        match q.pop_front() {
            Some(ev) => out.push(ev),
            None => break,
        }
    }

    out
}

/// Write one event into the global stream.
///
/// Returns `true` if RingBuf map write succeeded. The fallback queue is always
/// updated so shell commands can still read recent events.
pub fn ringbuf_push(event: &TraceEvent) -> bool {
    let pushed = if let Some(fd) = ringbuf_fd() {
        use crate::map_ops::AxKernelAuxOps;
        use kbpf_basic::KernelAuxiliaryOps;

        matches!(
            AxKernelAuxOps::get_unified_map_from_fd(fd, |unified_map| {
                unified_map.map_mut().push_elem(event.as_bytes(), 0)
            }),
            Ok(())
        )
    } else {
        false
    };

    // Keep a software copy for shell-side consumption.
    fallback_push(*event);
    pushed
}

/// Read and consume events from the global stream.
///
/// `max_events == 0` means no explicit limit.
pub fn consume_events(max_events: usize) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    let limit = if max_events == 0 { usize::MAX } else { max_events };

    if let Some(fd) = ringbuf_fd() {
        use crate::map_ops::AxKernelAuxOps;
        use kbpf_basic::KernelAuxiliaryOps;

        while events.len() < limit {
            let mut raw = [0u8; core::mem::size_of::<TraceEvent>()];
            let res = AxKernelAuxOps::get_unified_map_from_fd(fd, |unified_map| {
                unified_map.map_mut().pop_elem(&mut raw)
            });
            if !matches!(res, Ok(())) {
                break;
            }
            if let Some(ev) = TraceEvent::from_bytes(&raw) {
                events.push(ev);
            }
        }
    }

    if events.len() < limit {
        let remain = if limit == usize::MAX {
            0
        } else {
            limit - events.len()
        };
        events.extend(fallback_pop(remain));
    }

    events
}

// =============================================================================
// Built-in ProbeStats Aggregator
// =============================================================================

/// Per-event statistics updated on every `emit_event()`.
pub struct ProbeStats {
    pub count: AtomicU64,
    pub last_ts: AtomicU64,
    pub duration_samples: AtomicU64,
    pub duration_min: AtomicU64,
    pub duration_max: AtomicU64,
    pub duration_sum: AtomicU64,
    pub histogram: crate::tracepoints::LatencyHistogram,
}

impl ProbeStats {
    pub fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            last_ts: AtomicU64::new(0),
            duration_samples: AtomicU64::new(0),
            duration_min: AtomicU64::new(u64::MAX),
            duration_max: AtomicU64::new(0),
            duration_sum: AtomicU64::new(0),
            histogram: crate::tracepoints::LatencyHistogram::new(),
        }
    }

    /// Record one event hit, optionally with duration.
    pub fn record(&self, timestamp: u64, duration_ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_ts.store(timestamp, Ordering::Relaxed);

        if duration_ns == 0 {
            return;
        }

        self.duration_samples.fetch_add(1, Ordering::Relaxed);

        let mut current_min = self.duration_min.load(Ordering::Relaxed);
        while duration_ns < current_min {
            match self.duration_min.compare_exchange_weak(
                current_min,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current_min = v,
            }
        }

        self.duration_max.fetch_max(duration_ns, Ordering::Relaxed);
        self.duration_sum.fetch_add(duration_ns, Ordering::Relaxed);
        self.histogram.record(duration_ns);
    }

    pub fn snapshot(&self) -> ProbeStatsSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let duration_samples = self.duration_samples.load(Ordering::Relaxed);
        let duration_sum = self.duration_sum.load(Ordering::Relaxed);

        ProbeStatsSnapshot {
            count,
            last_ts: self.last_ts.load(Ordering::Relaxed),
            duration_samples,
            duration_min: self.duration_min.load(Ordering::Relaxed),
            duration_max: self.duration_max.load(Ordering::Relaxed),
            duration_sum,
            duration_avg: if duration_samples > 0 {
                duration_sum / duration_samples
            } else {
                0
            },
            histogram: self.histogram.snapshot(),
        }
    }
}

impl Default for ProbeStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot for shell display.
#[derive(Debug, Clone)]
pub struct ProbeStatsSnapshot {
    pub count: u64,
    pub last_ts: u64,
    pub duration_samples: u64,
    pub duration_min: u64,
    pub duration_max: u64,
    pub duration_sum: u64,
    pub duration_avg: u64,
    pub histogram: crate::tracepoints::HistogramSnapshot,
}

/// Global stats registry: event_id -> ProbeStats.
static STATS_REGISTRY: Mutex<BTreeMap<u32, &'static ProbeStats>> = Mutex::new(BTreeMap::new());

fn get_or_create_stats(event_id: u32) -> &'static ProbeStats {
    let mut registry = STATS_REGISTRY.lock();
    if let Some(stats) = registry.get(&event_id) {
        return stats;
    }

    let stats = Box::leak(Box::new(ProbeStats::new()));
    registry.insert(event_id, stats);
    stats
}

/// Snapshot all statistics.
pub fn all_stats() -> Vec<(u32, ProbeStatsSnapshot)> {
    let registry = STATS_REGISTRY.lock();
    registry
        .iter()
        .map(|(&id, stats)| (id, stats.snapshot()))
        .collect()
}

// =============================================================================
// Unified Event Emission
// =============================================================================

/// Unified event emission entry point.
///
/// Sequence:
/// 1. Best-effort RingBuf write + fallback queue enqueue
/// 2. Built-in stats update
/// 3. Execute attached eBPF program by event name
pub fn emit_event(event: &TraceEvent) {
    let _ = ringbuf_push(event);

    remember_event_name(event.event_id, event.name_offset);

    let stats = get_or_create_stats(event.event_id);
    stats.record(event.timestamp_ns, event.duration_ns);

    if let Some(name) = get_event_name(event.name_offset) {
        crate::tracepoints::stats::execute_attached_program(
            &name,
            event.timestamp_ns,
            event.duration_ns,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_event_layout_is_stable() {
        assert_eq!(core::mem::size_of::<TraceEvent>(), 64);
    }

    #[test]
    fn name_registration_is_idempotent() {
        let a = register_event_name("tp:test");
        let b = register_event_name("tp:test");
        assert_eq!(a, b);
        assert_eq!(get_event_name(a).as_deref(), Some("tp:test"));
    }

    #[test]
    fn stats_records_duration() {
        let stats = ProbeStats::new();
        stats.record(100, 0);
        stats.record(200, 400);
        let snap = stats.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.duration_samples, 1);
        assert_eq!(snap.duration_sum, 400);
        assert_eq!(snap.duration_avg, 400);
    }
}
