#![cfg(all(feature = "hprobe", feature = "test-utils"))]

use axebpf::hprobe_manager;

#[test]
fn same_symbol_allows_entry_and_ret_coexist() {
    hprobe_manager::init();

    // Use a fixed synthetic address for deterministic registry behavior in tests.
    let addr = 0x1000usize;
    let symbol = "test_hprobe_coexist_symbol";

    // Best-effort cleanup in case a prior failed run left state behind.
    let _ = hprobe_manager::detach(symbol);

    hprobe_manager::register_with_addr_for_test(symbol, addr, 11, false).unwrap();
    hprobe_manager::register_with_addr_for_test(symbol, addr, 22, true).unwrap();

    let probes = hprobe_manager::list_all();
    let mut has_entry = false;
    let mut has_ret = false;

    for (name, probe_addr, _hits, _enabled, is_ret, prog_id) in probes {
        if name != symbol || probe_addr != addr {
            continue;
        }
        if is_ret && prog_id == 22 {
            has_ret = true;
        }
        if !is_ret && prog_id == 11 {
            has_entry = true;
        }
    }

    assert!(has_entry, "entry probe must exist");
    assert!(has_ret, "ret probe must exist");

    hprobe_manager::detach(symbol).unwrap();
}

#[test]
fn unhprobe_removes_both_entry_and_ret_slots() {
    hprobe_manager::init();

    let addr = 0x2000usize;
    let symbol = "test_hprobe_unhprobe_symbol";

    let _ = hprobe_manager::detach(symbol);

    hprobe_manager::register_with_addr_for_test(symbol, addr, 33, false).unwrap();
    hprobe_manager::register_with_addr_for_test(symbol, addr, 44, true).unwrap();

    hprobe_manager::detach(symbol).unwrap();

    let probes = hprobe_manager::list_all();
    let still_present = probes.into_iter().any(|(name, probe_addr, _, _, _, _)| {
        name == symbol && probe_addr == addr
    });
    assert!(!still_present, "all probe slots must be removed by unhprobe");
}
