#![cfg(all(feature = "hprobe", feature = "test-utils"))]

use axebpf::hprobe_manager;

#[test]
fn verbose_hprobe_logs_only_emit_initial_burst_and_periodic_samples() {
    for hit in 1..=8 {
        assert!(
            hprobe_manager::should_log_verbose_hit_for_test(hit),
            "initial burst hit {} must stay visible",
            hit
        );
    }

    for hit in [9_u64, 10, 42, 255, 257, 511] {
        assert!(
            !hprobe_manager::should_log_verbose_hit_for_test(hit),
            "non-sampled hit {} must stay quiet",
            hit
        );
    }

    for hit in [256_u64, 512, 768] {
        assert!(
            hprobe_manager::should_log_verbose_hit_for_test(hit),
            "periodic sampled hit {} must stay visible",
            hit
        );
    }
}
