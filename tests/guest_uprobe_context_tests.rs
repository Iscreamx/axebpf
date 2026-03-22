#![cfg(all(feature = "runtime", feature = "guest-uprobe"))]

use axebpf::probe::ProbeType;
use axebpf::{TraceContext, TraceEvent};

#[test]
fn uprobe_probe_type_metadata_is_exposed() {
    assert_eq!(ProbeType::Uprobe.label(), "uprobe");
    assert_eq!(ProbeType::Uretprobe.label(), "uretprobe");
    assert!(ProbeType::Uprobe.is_guest_probe());
    assert!(ProbeType::Uretprobe.is_return_probe());
}

#[test]
fn trace_event_and_context_accept_uprobe_types() {
    let ctx = TraceContext::new(1).with_probe_type(5);
    assert_eq!(ctx.probe_type, 5);

    let event = TraceEvent::new(5, 1);
    assert_eq!(event.probe_type_str(), "uprobe");
}
