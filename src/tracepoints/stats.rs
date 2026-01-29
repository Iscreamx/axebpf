//! Built-in tracepoint statistics.
//!
//! Provides automatic statistics collection for tracepoints without
//! requiring eBPF programs.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::histogram::{HistogramSnapshot, LatencyHistogram};

/// Statistics for a single tracepoint.
#[derive(Debug)]
pub struct TracepointStats {
    /// Number of times the tracepoint was triggered.
    count: AtomicU64,
    /// Total time spent in nanoseconds (for paired enter/exit tracepoints).
    total_ns: AtomicU64,
    /// Minimum duration in nanoseconds.
    min_ns: AtomicU64,
    /// Maximum duration in nanoseconds.
    max_ns: AtomicU64,
    /// Last trigger timestamp.
    last_timestamp: AtomicU64,
    /// Latency distribution histogram.
    histogram: LatencyHistogram,
}

impl TracepointStats {
    /// Create a new stats instance.
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            min_ns: AtomicU64::new(u64::MAX),
            max_ns: AtomicU64::new(0),
            last_timestamp: AtomicU64::new(0),
            histogram: LatencyHistogram::new(),
        }
    }

    /// Record a tracepoint hit without duration.
    pub fn record_hit(&self, timestamp: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.last_timestamp.store(timestamp, Ordering::Relaxed);
    }

    /// Record a tracepoint hit with duration.
    pub fn record_duration(&self, timestamp: u64, duration_ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(duration_ns, Ordering::Relaxed);
        self.last_timestamp.store(timestamp, Ordering::Relaxed);

        // Update min (atomic compare-and-swap loop)
        let mut current_min = self.min_ns.load(Ordering::Relaxed);
        while duration_ns < current_min {
            match self.min_ns.compare_exchange_weak(
                current_min,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }

        // Update max (atomic compare-and-swap loop)
        let mut current_max = self.max_ns.load(Ordering::Relaxed);
        while duration_ns > current_max {
            match self.max_ns.compare_exchange_weak(
                current_max,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }

        // Update histogram
        self.histogram.record(duration_ns);
    }

    /// Get current statistics snapshot.
    pub fn snapshot(&self) -> StatsSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let total_ns = self.total_ns.load(Ordering::Relaxed);
        let min_ns = self.min_ns.load(Ordering::Relaxed);
        let max_ns = self.max_ns.load(Ordering::Relaxed);

        StatsSnapshot {
            count,
            total_ns,
            min_ns: if min_ns == u64::MAX { 0 } else { min_ns },
            max_ns,
            avg_ns: if count > 0 { total_ns / count } else { 0 },
        }
    }

    /// Get histogram snapshot.
    pub fn histogram_snapshot(&self) -> HistogramSnapshot {
        self.histogram.snapshot()
    }

    /// Reset statistics.
    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.total_ns.store(0, Ordering::Relaxed);
        self.min_ns.store(u64::MAX, Ordering::Relaxed);
        self.max_ns.store(0, Ordering::Relaxed);
        self.last_timestamp.store(0, Ordering::Relaxed);
        self.histogram.reset();
    }
}

/// Immutable snapshot of tracepoint statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub avg_ns: u64,
}

/// Global statistics manager for all VMM tracepoints.
pub struct StatsManager {
    stats: BTreeMap<String, TracepointStats>,
}

impl StatsManager {
    /// Create a new stats manager.
    pub fn new() -> Self {
        let mut stats = BTreeMap::new();

        // VM Lifecycle
        stats.insert("vmm:vm_create".into(), TracepointStats::new());
        stats.insert("vmm:vm_boot".into(), TracepointStats::new());
        stats.insert("vmm:vm_shutdown".into(), TracepointStats::new());
        stats.insert("vmm:vm_destroy".into(), TracepointStats::new());

        // vCPU Lifecycle
        stats.insert("vmm:vcpu_create".into(), TracepointStats::new());
        stats.insert("vmm:vcpu_destroy".into(), TracepointStats::new());
        stats.insert("vmm:vcpu_state_change".into(), TracepointStats::new());

        // vCPU Runtime
        stats.insert("vmm:vcpu_run_enter".into(), TracepointStats::new());
        stats.insert("vmm:vcpu_run_exit".into(), TracepointStats::new());
        stats.insert("vmm:hypercall".into(), TracepointStats::new());
        stats.insert("vmm:external_interrupt".into(), TracepointStats::new());
        stats.insert("vmm:vcpu_halt".into(), TracepointStats::new());
        stats.insert("vmm:cpu_up".into(), TracepointStats::new());
        stats.insert("vmm:ipi_send".into(), TracepointStats::new());

        // Memory Management
        stats.insert("vmm:memory_map".into(), TracepointStats::new());
        stats.insert("vmm:memory_unmap".into(), TracepointStats::new());
        stats.insert("vmm:page_fault".into(), TracepointStats::new());

        // Device & IRQ
        stats.insert("vmm:device_access".into(), TracepointStats::new());
        stats.insert("vmm:irq_inject".into(), TracepointStats::new());
        stats.insert("vmm:irq_handle".into(), TracepointStats::new());

        // System Initialization
        stats.insert("vmm:vmm_init".into(), TracepointStats::new());
        stats.insert("vmm:vhal_init".into(), TracepointStats::new());
        stats.insert("vmm:config_load".into(), TracepointStats::new());
        stats.insert("vmm:image_load".into(), TracepointStats::new());

        // Shell
        stats.insert("shell:command".into(), TracepointStats::new());
        stats.insert("shell:init".into(), TracepointStats::new());

        // Timer & Scheduling
        stats.insert("vmm:timer_tick".into(), TracepointStats::new());
        stats.insert("vmm:timer_event".into(), TracepointStats::new());
        stats.insert("vmm:task_switch".into(), TracepointStats::new());

        Self { stats }
    }

    /// Get stats for a specific tracepoint.
    pub fn get(&self, name: &str) -> Option<&TracepointStats> {
        self.stats.get(name)
    }

    /// Get all stats as snapshots.
    pub fn all_snapshots(&self) -> Vec<(String, StatsSnapshot)> {
        self.stats
            .iter()
            .map(|(name, stats)| (name.clone(), stats.snapshot()))
            .collect()
    }

    /// Reset all statistics.
    pub fn reset_all(&self) {
        for stats in self.stats.values() {
            stats.reset();
        }
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global stats manager instance.
static STATS_MANAGER: Mutex<Option<StatsManager>> = Mutex::new(None);

/// Initialize the stats manager.
pub fn init_stats() {
    let mut guard = STATS_MANAGER.lock();
    if guard.is_none() {
        *guard = Some(StatsManager::new());
        log::info!("VMM tracepoint stats manager initialized");
    }
}

/// Get global stats manager reference.
pub fn stats_manager() -> spin::MutexGuard<'static, Option<StatsManager>> {
    STATS_MANAGER.lock()
}

/// Record a hit for a tracepoint.
pub fn record_hit(name: &str, timestamp: u64) {
    if let Some(ref manager) = *STATS_MANAGER.lock()
        && let Some(stats) = manager.get(name)
    {
        stats.record_hit(timestamp);
    }
}

/// Record a duration for a tracepoint.
pub fn record_duration(name: &str, timestamp: u64, duration_ns: u64) {
    if let Some(ref manager) = *STATS_MANAGER.lock()
        && let Some(stats) = manager.get(name)
    {
        stats.record_duration(timestamp, duration_ns);
    }
}
