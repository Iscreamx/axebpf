#![cfg(feature = "guest-uprobe")]

use axebpf::probe::{
    kprobe::manager as guest_kprobe_manager,
    uprobe::{
        handler::{self, UprobeStage2ExecFaultResult},
        manager, object,
    },
};
use axerrno::AxResult;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[derive(Default)]
struct Stage2HookState {
    calls: Vec<(u32, u64, bool)>,
}

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn stage2_hook_state() -> &'static Mutex<Stage2HookState> {
    static STATE: OnceLock<Mutex<Stage2HookState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Stage2HookState::default()))
}

fn reset_stage2_hook_state() {
    let mut state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *state = Stage2HookState::default();
}

fn recording_stage2_exec(vm_id: u32, gpa: u64, executable: bool) -> AxResult<()> {
    let mut state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.calls.push((vm_id, gpa, executable));
    Ok(())
}

fn mock_stage2_exec_region(_vm_id: u32, gpa: u64) -> AxResult<(u64, u64)> {
    Ok((gpa & !0xfff, 0x1000))
}

#[test]
fn non_target_fault_single_steps_and_exact_target_fault_releases_exec_barrier() {
    let _guard = test_guard();
    manager::init();
    manager::clear_all_for_test();
    reset_stage2_hook_state();
    guest_kprobe_manager::clear_stage2_exec_hook_for_test();
    guest_kprobe_manager::clear_stage2_exec_region_hook_for_test();
    guest_kprobe_manager::register_stage2_exec_hook(recording_stage2_exec);
    guest_kprobe_manager::register_stage2_exec_region_hook(mock_stage2_exec_region);

    object::load_text_symbols(1, "/usr/bin/demo", "0000000000000010 T main\n").unwrap();
    manager::attach_symbol(1, "/usr/bin/demo", "main", 7, false).unwrap();
    manager::install_mock_patch_backend_for_test();
    manager::set_mock_patch_result_for_test(0x8000, 0x1234_5678, 0x9000);

    manager::activate_for_mapping_for_test(
        1,
        "/usr/bin/demo",
        0x1000,
        0x400000,
        0,
        0x8000,
        0x1234_5678,
    )
    .unwrap();

    let state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(state.calls, vec![(1, 0x9000, false)]);
    drop(state);

    assert!(manager::has_armed_exec_barrier_for_test(1, 0x9004));

    let handled = handler::handle_stage2_exec_fault_for_test(1, 0x9004);
    assert_eq!(handled, UprobeStage2ExecFaultResult::ProbeHitSingleStep);

    let state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(state.calls, vec![(1, 0x9000, false), (1, 0x9000, true)]);
    drop(state);

    assert!(manager::has_armed_exec_barrier_for_test(1, 0x9004));
    assert!(handler::handle_software_step());

    let state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        state.calls,
        vec![(1, 0x9000, false), (1, 0x9000, true), (1, 0x9000, false)]
    );
    drop(state);

    assert!(manager::has_armed_exec_barrier_for_test(1, 0x9004));
    let handled = handler::handle_stage2_exec_fault_for_test(1, 0x9000);
    assert_eq!(handled, UprobeStage2ExecFaultResult::RetryInstruction);

    let state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        state.calls,
        vec![
            (1, 0x9000, false),
            (1, 0x9000, true),
            (1, 0x9000, false),
            (1, 0x9000, true),
        ]
    );
    drop(state);

    assert!(!manager::has_armed_exec_barrier_for_test(1, 0x9004));
    assert_eq!(
        handler::handle_stage2_exec_fault_for_test(1, 0x9004),
        UprobeStage2ExecFaultResult::Unhandled
    );
}
