//! Latency histogram for tracepoint statistics.
//!
//! Fixed logarithmic bucket histogram for collecting latency distribution.

use core::sync::atomic::{AtomicU64, Ordering};

/// Bucket boundaries in nanoseconds (logarithmic distribution).
pub const BUCKET_BOUNDS_NS: [u64; 8] = [
    1_000,         // 0: 0-1us
    10_000,        // 1: 1-10us
    100_000,       // 2: 10-100us
    1_000_000,     // 3: 100us-1ms
    10_000_000,    // 4: 1-10ms
    100_000_000,   // 5: 10-100ms
    1_000_000_000, // 6: 100ms-1s
    u64::MAX,      // 7: >1s
];

/// Bucket labels for display.
pub const BUCKET_LABELS: [&str; 8] = [
    "     0-1us",
    "    1-10us",
    "  10-100us",
    "100us-1ms ",
    "   1-10ms ",
    " 10-100ms ",
    "100ms-1s  ",
    "      >1s ",
];

/// Latency histogram with 8 logarithmic buckets.
#[derive(Debug)]
pub struct LatencyHistogram {
    buckets: [AtomicU64; 8],
}

impl LatencyHistogram {
    /// Create a new empty histogram.
    pub const fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Record a latency sample.
    pub fn record(&self, duration_ns: u64) {
        let idx = self.find_bucket(duration_ns);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Find the bucket index for a given duration.
    fn find_bucket(&self, duration_ns: u64) -> usize {
        for (i, &bound) in BUCKET_BOUNDS_NS.iter().enumerate() {
            if duration_ns < bound {
                return i;
            }
        }
        7
    }

    /// Get a snapshot of the histogram.
    pub fn snapshot(&self) -> HistogramSnapshot {
        let mut buckets = [0u64; 8];
        let mut total = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            buckets[i] = bucket.load(Ordering::Relaxed);
            total += buckets[i];
        }

        let p50 = Self::percentile_from_buckets(&buckets, total, 0.50);
        let p90 = Self::percentile_from_buckets(&buckets, total, 0.90);
        let p99 = Self::percentile_from_buckets(&buckets, total, 0.99);

        HistogramSnapshot {
            buckets,
            total,
            p50_ns: p50,
            p90_ns: p90,
            p99_ns: p99,
        }
    }

    /// Calculate approximate percentile from bucket distribution.
    fn percentile_from_buckets(buckets: &[u64; 8], total: u64, p: f64) -> u64 {
        if total == 0 {
            return 0;
        }
        let target = (total as f64 * p) as u64;
        let mut cumulative = 0u64;
        for (i, &count) in buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return BUCKET_BOUNDS_NS[i];
            }
        }
        BUCKET_BOUNDS_NS[7]
    }

    /// Reset all buckets to zero.
    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of histogram data.
#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    /// Count in each bucket.
    pub buckets: [u64; 8],
    /// Total sample count.
    pub total: u64,
    /// Approximate 50th percentile in nanoseconds.
    pub p50_ns: u64,
    /// Approximate 90th percentile in nanoseconds.
    pub p90_ns: u64,
    /// Approximate 99th percentile in nanoseconds.
    pub p99_ns: u64,
}
