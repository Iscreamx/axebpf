#![cfg(feature = "guest-kprobe")]

#[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
use axebpf::event;
use axebpf::probe::kprobe::{
    addr_translate::{
        register_guest_pt_read_hook, register_gva_to_hva_hook, register_vm_ttbr1_hook,
    },
    handler::{self, GuestBrkHandleResult, Stage2ExecFaultResult},
    manager::{self, KprobeMode},
    return_stack::{self, ReturnEntry},
    single_step::{self, SingleStepMode},
};
use axerrno::AxResult;
use std::sync::{Mutex, MutexGuard, OnceLock};

static mut MOCK_GUEST_INSN: u32 = 0x1400_0000;
static mut MOCK_RETURN_INSN: u32 = 0xd65f03c0;

const RETURN_ADDR_GVA: u64 = 0xffff_8000_0001_0000;
const ENTRY_ADDR_GVA: u64 = 0xffff_8000_8000_9000;

#[derive(Default)]
struct Stage2HookState {
    calls: Vec<(u32, u64, bool)>,
    nested_fault: Option<(u32, u64, u64)>,
    nested_result: Option<Stage2ExecFaultResult>,
}

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn mock_vm_ttbr1(vm_id: u32) -> AxResult<u64> {
    Ok(0x1000_0000 + ((vm_id as u64) << 20))
}

fn mock_guest_pt_read(paddr: u64, vm_id: u32) -> AxResult<u64> {
    let ttbr1 = mock_vm_ttbr1(vm_id)?;
    let l1 = ttbr1 + 0x1000;
    let l2 = ttbr1 + 0x2000;
    let l3 = ttbr1 + 0x3000;

    let table_base = paddr & !0xfff;
    let index = (paddr & 0xfff) / 8;
    let desc = if table_base == ttbr1 {
        l1 | 0b11
    } else if table_base == l1 {
        l2 | 0b11
    } else if table_base == l2 {
        l3 | 0b11
    } else if table_base == l3 {
        (0x4000_0000 + (index << 12)) | 0b11
    } else {
        return axerrno::ax_err!(NotFound, "mock pte missing");
    };
    Ok(desc)
}

fn mock_gva_to_hva(gva: u64, _vm_id: u32) -> AxResult<usize> {
    if gva == RETURN_ADDR_GVA {
        return Ok(core::ptr::addr_of_mut!(MOCK_RETURN_INSN) as usize);
    }
    Ok(core::ptr::addr_of_mut!(MOCK_GUEST_INSN) as usize)
}

fn mock_stage2_exec(_vm_id: u32, _gpa: u64, _executable: bool) -> AxResult<()> {
    Ok(())
}

fn mock_stage2_exec_region(_vm_id: u32, gpa: u64) -> AxResult<(u64, u64)> {
    Ok((gpa & !0x1f_ffff, 0x20_0000))
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

fn reset_mock_guest_insns() {
    unsafe {
        MOCK_GUEST_INSN = 0x1400_0000;
        MOCK_RETURN_INSN = 0xd65f03c0;
    }
}

fn read_mock_insn(hva: usize) -> u32 {
    unsafe { core::ptr::read_volatile(hva as *const u32) }
}

#[cfg(target_arch = "aarch64")]
fn insn_has_guest_break(word: u32) -> bool {
    word == 0xd4200000
}

#[cfg(target_arch = "x86_64")]
fn insn_has_guest_break(word: u32) -> bool {
    (word as u8) == 0xcc
}

#[cfg(target_arch = "aarch64")]
fn expected_saved_return_insn() -> u32 {
    0xd65f03c0
}

#[cfg(target_arch = "x86_64")]
fn expected_saved_return_insn() -> u32 {
    0xc0
}

fn recording_stage2_exec(vm_id: u32, gpa: u64, executable: bool) -> AxResult<()> {
    let nested_fault = {
        let mut state = match stage2_hook_state().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.calls.push((vm_id, gpa, executable));
        if executable {
            state.nested_fault.take()
        } else {
            None
        }
    };

    if let Some((fault_vm_id, fault_gpa, fault_gva)) = nested_fault {
        let handled =
            handler::handle_stage2_exec_fault(fault_vm_id, fault_gpa, fault_gva, true, &[0u64; 31]);
        let mut state = match stage2_hook_state().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.nested_result = Some(handled);
    }

    Ok(())
}

fn setup_mock_backends() {
    register_vm_ttbr1_hook(mock_vm_ttbr1);
    register_guest_pt_read_hook(mock_guest_pt_read);
    register_gva_to_hva_hook(mock_gva_to_hva);
    manager::register_stage2_exec_hook(mock_stage2_exec);
    manager::register_stage2_exec_region_hook(mock_stage2_exec_region);
    #[cfg(feature = "test-utils")]
    {
        manager::clear_stale_brk_for_test();
        single_step::clear_pending_for_test();
    }
}

#[test]
fn stage2_match_must_request_single_step() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    let vm_id = 7;
    let gva = 0xffff_8000_8000_1000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 1, false, KprobeMode::Stage2Fault).unwrap();
    let handled = handler::handle_stage2_exec_fault(vm_id, 0x1000, gva, true, &[0u64; 31]);
    assert_eq!(
        handled,
        Stage2ExecFaultResult::ProbeHitSingleStep,
        "matched stage2 fault must request hardware single-step"
    );
    let _ = single_step::clear_pending(0);

    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn stage2_same_barrier_non_target_fault_must_single_step() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 8;
    let probe_gva = 0xffff_8000_8000_1800_u64;
    let fault_gva = probe_gva + 0x40;
    let _ = manager::detach(vm_id, probe_gva);

    manager::attach(vm_id, probe_gva, 11, false, KprobeMode::Stage2Fault).unwrap();
    let fault_gpa =
        axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(fault_gva, vm_id).unwrap();

    let handled = handler::handle_stage2_exec_fault(vm_id, fault_gpa, fault_gva, true, &[0u64; 31]);
    assert_eq!(
        handled,
        Stage2ExecFaultResult::ProbeHitSingleStep,
        "same Stage-2 barrier page must keep single-stepping instead of escaping as unhandled"
    );

    let pending = single_step::peek_pending(0).unwrap();
    assert_eq!(
        pending.probe_gva, probe_gva,
        "page-level stepping must keep tracking the original probe address"
    );
    assert_eq!(pending.mode, SingleStepMode::Stage2Fault);

    let _ = single_step::clear_pending(0);
    manager::detach(vm_id, probe_gva).unwrap();
}

#[test]
fn guest_brk_match_must_return_true() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    let vm_id = 9;
    let pc = 0xffff_8000_8000_2000_u64;
    let _ = manager::detach(vm_id, pc);

    manager::attach(vm_id, pc, 2, false, KprobeMode::BrkInject).unwrap();
    let handled = handler::handle_guest_brk(vm_id, pc, 0x123, &[0u64; 31]);
    assert_eq!(
        handled,
        handler::GuestBrkHandleResult::ProbeHitSingleStep,
        "matched guest brk must set up single-step"
    );
    let expected_gpa =
        axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(pc, vm_id).unwrap();
    let pending = single_step::peek_pending(0).unwrap();
    assert_eq!(
        pending.gpa,
        expected_gpa & !0x1f_ffff,
        "pending state must carry barrier base GPA"
    );
    assert_eq!(
        pending.gpa_size, 0x20_0000,
        "pending state must carry barrier size"
    );
    assert_eq!(
        pending.mode,
        SingleStepMode::BrkInject,
        "BRK path must tag pending state with BRK mode"
    );
    let _ = single_step::clear_pending(0);

    manager::detach(vm_id, pc).unwrap();
}

#[test]
fn guest_brk_single_step_setup_fail_must_fallback_skip() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    let vm_id = 11;
    let pc = 0xffff_8000_8000_4000_u64;
    let _ = manager::detach(vm_id, pc);

    manager::attach(vm_id, pc, 4, false, KprobeMode::BrkInject).unwrap();
    single_step::set_force_pending_fail_for_test(true);
    let handled = handler::handle_guest_brk(vm_id, pc, 0x456, &[0u64; 31]);
    single_step::set_force_pending_fail_for_test(false);
    assert_eq!(
        handled,
        handler::GuestBrkHandleResult::ProbeHitFallbackSkip,
        "single-step setup failure must fallback to legacy skip handling"
    );

    manager::detach(vm_id, pc).unwrap();
}

#[test]
fn single_step_state_must_support_large_cpu_id() {
    let _guard = test_guard();
    single_step::clear_pending_for_test();

    let cpu = 4096usize;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0x1000,
        saved_insn: 0x1400_0000,
        vm_id: 99,
        hva: 0x2000,
        gpa: 0x3000,
        gpa_size: 0x1000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(cpu, state).unwrap();
    assert!(
        single_step::is_pending(cpu),
        "pending state must be recorded"
    );

    let recovered = single_step::take_pending(cpu).unwrap();
    assert_eq!(recovered.probe_gva, state.probe_gva);
    assert_eq!(recovered.saved_insn, state.saved_insn);
    assert_eq!(recovered.vm_id, state.vm_id);
    assert_eq!(recovered.hva, state.hva);
    assert_eq!(recovered.gpa, state.gpa);
    assert_eq!(recovered.mode, state.mode);
    assert!(
        !single_step::is_pending(cpu),
        "pending state must be consumed"
    );

    single_step::clear_pending_for_test();
}

#[test]
fn is_stepping_on_page_must_detect_same_page() {
    let _guard = test_guard();
    single_step::clear_pending_for_test();

    let cpu = 0usize;
    let vm_id = 50;
    let gpa = 0x4000_1000_u64;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_1000,
        saved_insn: 0x1400_0000,
        vm_id,
        hva: 0x5000,
        gpa,
        gpa_size: 0x1000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(cpu, state).unwrap();

    assert!(
        single_step::is_stepping_on_page(vm_id, gpa),
        "exact GPA must match"
    );
    assert!(
        single_step::is_stepping_on_page(vm_id, gpa + 0x100),
        "same page different offset must match"
    );
    assert!(
        !single_step::is_stepping_on_page(vm_id, gpa + 0x1000),
        "different page must not match"
    );
    assert!(
        !single_step::is_stepping_on_page(vm_id + 1, gpa),
        "different VM must not match"
    );
    assert!(
        !single_step::is_stepping_on_page(vm_id, 0),
        "gpa=0 must return false"
    );

    single_step::clear_pending_for_test();
}

#[test]
fn peek_pending_must_not_consume_state() {
    let _guard = test_guard();
    single_step::clear_pending_for_test();

    let cpu = 7usize;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0x2000,
        saved_insn: 0x1400_0000,
        vm_id: 77,
        hva: 0x3000,
        gpa: 0x4000,
        gpa_size: 0x1000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(cpu, state).unwrap();

    let peeked = single_step::peek_pending(cpu).unwrap();
    assert_eq!(peeked.probe_gva, state.probe_gva);
    assert_eq!(peeked.gpa, state.gpa);
    assert!(single_step::is_pending(cpu), "peek must not consume state");

    let cleared = single_step::clear_pending(cpu).unwrap();
    assert_eq!(cleared.hva, state.hva);
    assert_eq!(cleared.mode, state.mode);
    assert!(!single_step::is_pending(cpu), "clear must remove state");

    single_step::clear_pending_for_test();
}

#[test]
fn exec_fault_during_stepping_must_busy_retry() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 20;
    let gpa = 0x4000_1000_u64;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_1000,
        saved_insn: 0x1400_0000,
        vm_id,
        hva: 0x5000,
        gpa,
        gpa_size: 0x1000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(0, state).unwrap();

    let handled = handler::handle_stage2_exec_fault(
        vm_id,
        gpa + 0x100,
        0xffff_8000_8000_1100,
        true,
        &[0u64; 31],
    );
    assert_eq!(
        handled,
        Stage2ExecFaultResult::BusyRetry,
        "same-page exec fault must busy-retry"
    );

    let handled_other = handler::handle_stage2_exec_fault(
        vm_id,
        gpa + 0x1000,
        0xffff_8000_8000_2000,
        true,
        &[0u64; 31],
    );
    assert_eq!(
        handled_other,
        Stage2ExecFaultResult::Unhandled,
        "different page must not busy-retry"
    );

    single_step::clear_pending_for_test();
}

#[test]
fn software_step_must_keep_pending_until_xn_clear() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();
    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(recording_stage2_exec);

    let vm_id = 21;
    let gpa = 0x4000_2000_u64;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_2000,
        saved_insn: 0x1400_0000,
        vm_id,
        hva: core::ptr::addr_of_mut!(MOCK_GUEST_INSN) as usize,
        gpa,
        gpa_size: 0x1000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(0, state).unwrap();

    {
        let mut hook_state = match stage2_hook_state().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        hook_state.nested_fault = Some((vm_id, gpa + 0x100, 0xffff_8000_8000_2100));
    }

    assert!(
        handler::handle_software_step(),
        "pending state must be consumed by handler"
    );

    let hook_state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        hook_state.nested_result,
        Some(Stage2ExecFaultResult::BusyRetry),
        "pending state must remain visible while XN is being cleared"
    );
    drop(hook_state);

    single_step::clear_pending_for_test();
    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(mock_stage2_exec);
}

#[test]
fn stale_guest_brk_after_detach_must_request_retry() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    let vm_id = 10;
    let pc = 0xffff_8000_8000_3000_u64;
    let _ = manager::detach(vm_id, pc);

    manager::attach(vm_id, pc, 3, false, KprobeMode::BrkInject).unwrap();
    manager::detach(vm_id, pc).unwrap();

    let handled = handler::handle_guest_brk(vm_id, pc, 0, &[0u64; 31]);
    assert_eq!(
        handled,
        handler::GuestBrkHandleResult::RetryInstruction,
        "stale BRK after detach must be consumed and retried at same PC"
    );
}

#[test]
fn is_stepping_on_page_must_respect_barrier_size() {
    let _guard = test_guard();
    single_step::clear_pending_for_test();

    let cpu = 3usize;
    let vm_id = 88;
    let barrier_base = 0x4000_0000_u64;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_2000,
        saved_insn: 0x1400_0000,
        vm_id,
        hva: 0x7000,
        gpa: barrier_base,
        gpa_size: 0x20_0000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(cpu, state).unwrap();

    assert!(
        single_step::is_stepping_on_page(vm_id, barrier_base + 0x1f_000),
        "fault within protected huge-page range must busy-retry"
    );
    assert!(
        !single_step::is_stepping_on_page(vm_id, barrier_base + 0x20_0000),
        "fault outside protected range must not busy-retry"
    );

    single_step::clear_pending_for_test();
}

#[test]
fn gva_busy_retry_must_skip_owner_cpu_and_match_peer_cpu() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 91;
    let gva = 0xffff_8000_8000_2100_u64;
    let gpa = axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(gva, vm_id).unwrap();
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_2000,
        saved_insn: 0x1400_0000,
        vm_id,
        hva: 0x9000,
        gpa: gpa & !0x1f_ffff,
        gpa_size: 0x20_0000,
        mode: SingleStepMode::BrkInject,
    };
    single_step::set_pending(0, state).unwrap();

    axebpf::platform::set_mock_cpu_id(0);
    assert!(
        !handler::should_busy_retry_gva(vm_id, gva),
        "owner CPU must not self-busy-retry"
    );

    axebpf::platform::set_mock_cpu_id(1);
    assert!(
        handler::should_busy_retry_gva(vm_id, gva),
        "peer CPU within the protected barrier must busy-retry"
    );

    axebpf::platform::set_mock_cpu_id(0);
    single_step::clear_pending_for_test();
}

#[test]
fn stage2_single_step_must_set_pending_with_stage2_mode() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 32;
    let gva = 0xffff_8000_8000_5000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 6, false, KprobeMode::Stage2Fault).unwrap();
    let gpa = axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(gva, vm_id).unwrap();

    let handled = handler::handle_stage2_exec_fault(vm_id, gpa, gva, true, &[0u64; 31]);
    assert_eq!(
        handled,
        Stage2ExecFaultResult::ProbeHitSingleStep,
        "matched stage2 fault must arm single-step completion"
    );

    let pending = single_step::peek_pending(0).unwrap();
    assert_eq!(pending.probe_gva, gva);
    assert_eq!(
        pending.saved_insn, 0,
        "stage2 flow does not restore guest BRK bytes"
    );
    assert_eq!(
        pending.hva, 0,
        "stage2 flow does not need guest HVA reinjection"
    );
    assert_eq!(
        pending.gpa,
        gpa & !0x1f_ffff,
        "pending state must store barrier base"
    );
    assert_eq!(
        pending.gpa_size, 0x20_0000,
        "pending state must store barrier size"
    );
    assert_eq!(
        pending.mode,
        SingleStepMode::Stage2Fault,
        "stage2 flow must record stage2 completion mode"
    );

    let _ = single_step::clear_pending(0);
    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn stage2_software_step_must_restore_xn() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();
    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(recording_stage2_exec);

    let vm_id = 33;
    let barrier_gpa = 0x4000_0000_u64;
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: 0xffff_8000_8000_6000,
        saved_insn: 0,
        vm_id,
        hva: 0,
        gpa: barrier_gpa,
        gpa_size: 0x20_0000,
        mode: SingleStepMode::Stage2Fault,
    };
    single_step::set_pending(0, state).unwrap();

    assert!(
        handler::handle_software_step(),
        "stage2 pending step must be completed"
    );
    assert!(
        single_step::peek_pending(0).is_none(),
        "software-step completion must clear pending state"
    );

    let hook_state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        hook_state.calls,
        vec![(vm_id, barrier_gpa, false)],
        "stage2 completion must restore execute-never on the barrier"
    );
    drop(hook_state);

    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(mock_stage2_exec);
}

#[test]
fn stage2_fault_pending_fail_must_rollback_xn() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 34;
    let gva = 0xffff_8000_8000_7000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 7, false, KprobeMode::Stage2Fault).unwrap();
    let gpa = axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(gva, vm_id).unwrap();
    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(recording_stage2_exec);

    single_step::set_force_pending_fail_for_test(true);
    let handled = handler::handle_stage2_exec_fault(vm_id, gpa, gva, true, &[0u64; 31]);
    single_step::set_force_pending_fail_for_test(false);

    assert_eq!(
        handled,
        Stage2ExecFaultResult::Unhandled,
        "pending failure must rollback XN and report unhandled"
    );
    assert!(
        single_step::peek_pending(0).is_none(),
        "failed stage2 single-step setup must not leave pending state behind"
    );

    let hook_state = match stage2_hook_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(
        hook_state.calls,
        vec![
            (vm_id, gpa & !0x1f_ffff, true),
            (vm_id, gpa & !0x1f_ffff, false)
        ],
        "XN must be opened before arming step and rolled back on failure"
    );
    drop(hook_state);

    reset_stage2_hook_state();
    manager::register_stage2_exec_hook(mock_stage2_exec);
    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn stage2_non_exec_fault_must_return_unhandled() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    single_step::clear_pending_for_test();

    let vm_id = 35;
    let gva = 0xffff_8000_8000_8000_u64;
    let _ = manager::detach(vm_id, gva);

    manager::attach(vm_id, gva, 8, false, KprobeMode::Stage2Fault).unwrap();
    let gpa = axebpf::probe::kprobe::addr_translate::gva_to_gpa_with_vm(gva, vm_id).unwrap();

    let handled = handler::handle_stage2_exec_fault(vm_id, gpa, gva, false, &[0u64; 31]);
    assert_eq!(
        handled,
        Stage2ExecFaultResult::Unhandled,
        "non-exec faults must not enter guest-kprobe single-step flow"
    );
    assert!(
        single_step::peek_pending(0).is_none(),
        "non-exec faults must not create pending single-step state"
    );

    manager::detach(vm_id, gva).unwrap();
}

#[test]
fn return_stack_push_pop_basic() {
    let _guard = test_guard();
    return_stack::clear_all_for_test();

    let entry = ReturnEntry {
        vm_id: 1,
        return_gva: RETURN_ADDR_GVA,
        return_hva: 0x1234,
        saved_insn: 0xd65f03c0,
        entry_gva: ENTRY_ADDR_GVA,
        prog_id: 7,
    };
    return_stack::push(0, entry).unwrap();

    let popped = return_stack::pop_matching(0, 1, RETURN_ADDR_GVA).unwrap();
    assert_eq!(popped.vm_id, entry.vm_id);
    assert_eq!(popped.return_gva, entry.return_gva);
    assert_eq!(popped.return_hva, entry.return_hva);
    assert_eq!(popped.saved_insn, entry.saved_insn);
    assert_eq!(popped.entry_gva, entry.entry_gva);
    assert_eq!(popped.prog_id, entry.prog_id);
}

#[test]
fn return_stack_pop_wrong_gva_returns_none() {
    let _guard = test_guard();
    return_stack::clear_all_for_test();

    return_stack::push(
        0,
        ReturnEntry {
            vm_id: 1,
            return_gva: RETURN_ADDR_GVA,
            return_hva: 0x1234,
            saved_insn: 0xd65f03c0,
            entry_gva: ENTRY_ADDR_GVA,
            prog_id: 7,
        },
    )
    .unwrap();

    assert!(return_stack::pop_matching(0, 1, RETURN_ADDR_GVA + 4).is_none());
}

#[test]
fn return_stack_overflow_returns_error() {
    let _guard = test_guard();
    return_stack::clear_all_for_test();

    for idx in 0..16u64 {
        return_stack::push(
            0,
            ReturnEntry {
                vm_id: 1,
                return_gva: RETURN_ADDR_GVA + idx * 4,
                return_hva: 0x1000 + idx as usize * 4,
                saved_insn: 0xd65f03c0,
                entry_gva: ENTRY_ADDR_GVA,
                prog_id: 7,
            },
        )
        .unwrap();
    }

    let overflow = return_stack::push(
        0,
        ReturnEntry {
            vm_id: 1,
            return_gva: RETURN_ADDR_GVA + 0x100,
            return_hva: 0x2000,
            saved_insn: 0xd65f03c0,
            entry_gva: ENTRY_ADDR_GVA,
            prog_id: 7,
        },
    );
    assert!(overflow.is_err(), "push beyond stack depth must fail");
}

#[test]
fn return_stack_clear_for_vm() {
    let _guard = test_guard();
    return_stack::clear_all_for_test();

    return_stack::push(
        0,
        ReturnEntry {
            vm_id: 1,
            return_gva: RETURN_ADDR_GVA,
            return_hva: 0x1234,
            saved_insn: 0xd65f03c0,
            entry_gva: ENTRY_ADDR_GVA,
            prog_id: 7,
        },
    )
    .unwrap();
    return_stack::push(
        1,
        ReturnEntry {
            vm_id: 2,
            return_gva: RETURN_ADDR_GVA + 4,
            return_hva: 0x1238,
            saved_insn: 0xd65f03c0,
            entry_gva: ENTRY_ADDR_GVA + 4,
            prog_id: 8,
        },
    )
    .unwrap();

    return_stack::clear_for_vm(1);

    assert!(!return_stack::has_pending(0, 1, RETURN_ADDR_GVA));
    assert!(return_stack::has_pending(1, 2, RETURN_ADDR_GVA + 4));
}

#[test]
fn return_brk_acquire_first_injects_brk() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    manager::clear_return_brk_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    let (refcount, saved_insn) = manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();

    assert_eq!(refcount, 1);
    assert_eq!(saved_insn, expected_saved_return_insn());
    assert!(insn_has_guest_break(read_mock_insn(ret_hva)));
}

#[test]
fn return_brk_acquire_second_increments_refcount() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    manager::clear_return_brk_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();
    let (refcount, _) = manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();

    assert_eq!(refcount, 2);
}

#[test]
fn return_brk_release_to_zero_removes_entry() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    manager::clear_return_brk_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();

    let should_reinject = manager::release_return_brk(1, RETURN_ADDR_GVA).unwrap();
    assert!(!should_reinject, "last release must not request reinject");
}

#[test]
fn return_brk_release_with_remaining_keeps_brk() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    manager::clear_return_brk_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();
    manager::acquire_return_brk(1, RETURN_ADDR_GVA, ret_hva).unwrap();

    let should_reinject = manager::release_return_brk(1, RETURN_ADDR_GVA).unwrap();
    assert!(
        should_reinject,
        "non-last release must keep breakpoint active"
    );
}

#[test]
fn kretprobe_entry_hit_must_inject_return_brk_and_push_stack() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    return_stack::clear_all_for_test();
    manager::clear_return_brk_for_test();
    #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
    let _ = event::consume_events(0);

    let _ = manager::detach(1, ENTRY_ADDR_GVA);
    manager::attach(1, ENTRY_ADDR_GVA, 12, true, KprobeMode::BrkInject).unwrap();

    let mut regs = [0u64; 31];
    regs[30] = RETURN_ADDR_GVA;
    let handled = handler::handle_guest_brk(1, ENTRY_ADDR_GVA, 0, &regs);

    assert_eq!(handled, GuestBrkHandleResult::ProbeHitSingleStep);
    assert!(return_stack::has_pending(0, 1, RETURN_ADDR_GVA));
    #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
    assert!(
        event::consume_events(8)
            .into_iter()
            .all(|ev| ev.probe_type != event::PROBE_KRETPROBE),
        "entry hit must not emit a kretprobe event"
    );
}

#[test]
fn kretprobe_return_hit_must_return_returnprobehitsinglestep() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    return_stack::clear_all_for_test();
    manager::clear_return_brk_for_test();
    #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
    let _ = event::consume_events(0);

    let _ = manager::detach(1, ENTRY_ADDR_GVA);
    manager::attach(1, ENTRY_ADDR_GVA, 12, true, KprobeMode::BrkInject).unwrap();

    let mut regs = [0u64; 31];
    regs[30] = RETURN_ADDR_GVA;
    assert_eq!(
        handler::handle_guest_brk(1, ENTRY_ADDR_GVA, 0, &regs),
        GuestBrkHandleResult::ProbeHitSingleStep
    );
    assert!(handler::handle_software_step());

    let handled = handler::handle_guest_brk(1, RETURN_ADDR_GVA, 0, &regs);

    assert_eq!(handled, GuestBrkHandleResult::ReturnProbeHitSingleStep);
    assert!(!return_stack::has_pending(0, 1, RETURN_ADDR_GVA));
    #[cfg(all(feature = "runtime", feature = "tracepoint-support"))]
    {
        let events = event::consume_events(8);
        let matched = events.into_iter().any(|ev| {
            ev.probe_type == event::PROBE_KRETPROBE && ev.event_id == ENTRY_ADDR_GVA as u32
        });
        assert!(
            matched,
            "return hit must be attributed to the entry probe address"
        );
    }
}

#[test]
fn kretprobe_software_step_reinject_when_refcount_positive() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    manager::clear_return_brk_for_test();
    single_step::clear_pending_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: RETURN_ADDR_GVA,
        saved_insn: 0xd65f03c0,
        vm_id: 1,
        hva: ret_hva,
        gpa: 0x4000_0000,
        gpa_size: 0x1000,
        mode: SingleStepMode::ReturnProbe {
            should_reinject: true,
        },
    };
    single_step::set_pending(0, state).unwrap();

    assert!(handler::handle_software_step());
    assert!(insn_has_guest_break(read_mock_insn(ret_hva)));
}

#[test]
fn kretprobe_software_step_no_reinject_when_refcount_zero() {
    let _guard = test_guard();
    manager::init();
    setup_mock_backends();
    reset_mock_guest_insns();
    single_step::clear_pending_for_test();

    let ret_hva = mock_gva_to_hva(RETURN_ADDR_GVA, 1).unwrap();
    let state = single_step::KprobeSingleStepState {
        active: true,
        probe_gva: RETURN_ADDR_GVA,
        saved_insn: 0xd65f03c0,
        vm_id: 1,
        hva: ret_hva,
        gpa: 0x4000_0000,
        gpa_size: 0x1000,
        mode: SingleStepMode::ReturnProbe {
            should_reinject: false,
        },
    };
    single_step::set_pending(0, state).unwrap();

    assert!(handler::handle_software_step());
    assert_eq!(read_mock_insn(ret_hva), 0xd65f03c0);
}
