#![cfg(all(
    feature = "runtime",
    feature = "tracepoint-support",
    feature = "hprobe",
    feature = "test-utils"
))]

use axebpf::event;
use axebpf::hprobe_manager;

#[test]
fn ret_path_emits_hretprobe_event_type() {
    // Drain stale events first so this test only inspects its own emission.
    let _ = event::consume_events(0);

    let probe_addr = 0x3456usize;
    let retval = 0x7788u64;

    hprobe_manager::emit_hretprobe_event_for_test(probe_addr, retval);

    let events = event::consume_events(16);
    let matched = events.into_iter().any(|ev| {
        ev.probe_type == event::PROBE_HRETPROBE
            && ev.event_id == probe_addr as u32
            && ev.nr_args >= 1
            && ev.args[0] == retval
            && event::get_event_name(ev.name_offset).as_deref() == Some("hretprobe")
    });

    assert!(matched, "ret event must be emitted as PROBE_HRETPROBE");
}
