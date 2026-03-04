//! Integration tests for tracepoint stats facade.
//!
//! The legacy `StatsManager`/`TracepointStats` API was removed. These tests
//! validate the current function-style entry points and event-driven stats path.

#![cfg(all(feature = "tracepoint-support", feature = "runtime"))]

use core::sync::atomic::{AtomicU32, Ordering};
use std::boxed::Box;
use std::sync::Mutex;

use axebpf::event;
use axebpf::tracepoints::stats;
use axebpf::{all_stats, consume_events, get_event_name};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TRACEPOINT_ID: AtomicU32 = AtomicU32::new(10_000);

fn register_test_tracepoint(prefix: &str) -> (u32, &'static str) {
    let id = NEXT_TRACEPOINT_ID.fetch_add(1, Ordering::Relaxed);
    let name = format!("test:{}_{}", prefix, id);
    let name: &'static str = Box::leak(name.into_boxed_str());
    axebpf::tracepoints::registry::register(id, name);
    (id, name)
}

fn snapshot_for(event_id: u32) -> Option<(u64, u64, u64, u64, u64)> {
    all_stats()
        .into_iter()
        .find(|(id, _)| *id == event_id)
        .map(|(_, snapshot)| {
            (
                snapshot.count,
                snapshot.duration_samples,
                snapshot.duration_sum,
                snapshot.duration_min,
                snapshot.duration_max,
            )
        })
}

#[test]
fn record_hit_emits_tracepoint_event_and_updates_stats() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = consume_events(0);

    let (event_id, name) = register_test_tracepoint("hit");
    let timestamp = 1_000_000u64;

    assert!(snapshot_for(event_id).is_none());

    stats::record_hit(name, timestamp);

    let events = consume_events(32);
    let matched = events.into_iter().any(|ev| {
        ev.probe_type == event::PROBE_TRACEPOINT
            && ev.event_id == event_id
            && ev.timestamp_ns == timestamp
            && ev.duration_ns == 0
            && get_event_name(ev.name_offset).as_deref() == Some(name)
    });
    assert!(matched, "record_hit must emit a tracepoint event");

    let snapshot = snapshot_for(event_id).expect("stats entry must exist after record_hit");
    assert_eq!(snapshot.0, 1);
    assert_eq!(snapshot.1, 0);
    assert_eq!(snapshot.2, 0);
    assert_eq!(snapshot.3, u64::MAX);
    assert_eq!(snapshot.4, 0);
}

#[test]
fn record_duration_emits_tracepoint_event_and_updates_duration_stats() {
    let _guard = TEST_LOCK.lock().unwrap();
    let _ = consume_events(0);

    let (event_id, name) = register_test_tracepoint("duration");
    let timestamp = 2_000_000u64;
    let duration = 777u64;

    assert!(snapshot_for(event_id).is_none());

    stats::record_duration(name, timestamp, duration);

    let events = consume_events(32);
    let matched = events.into_iter().any(|ev| {
        ev.probe_type == event::PROBE_TRACEPOINT
            && ev.event_id == event_id
            && ev.timestamp_ns == timestamp
            && ev.duration_ns == duration
            && get_event_name(ev.name_offset).as_deref() == Some(name)
    });
    assert!(matched, "record_duration must emit a tracepoint event");

    let snapshot = snapshot_for(event_id).expect("stats entry must exist after record_duration");
    assert_eq!(snapshot.0, 1);
    assert_eq!(snapshot.1, 1);
    assert_eq!(snapshot.2, duration);
    assert_eq!(snapshot.3, duration);
    assert_eq!(snapshot.4, duration);
}
