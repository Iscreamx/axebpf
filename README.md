# axebpf

eBPF runtime, symbol table, and probe framework for AxVisor Hypervisor.

## Overview

`axebpf` provides tracing and dynamic probing infrastructure for AxVisor. It supports:

1. Hypervisor-side probes (`hprobe` / `hretprobe`)
2. Guest kernel probes (`guest-kprobe`)
3. Static tracepoints (`tracepoint-support`)
4. eBPF program loading/execution (`runtime`)

All modules are `#![no_std]`.

## Feature Highlights

1. Symbol lookup via `ksym` (`symbols`)
2. Tracepoint manager with filter support (`tracepoint-support`)
3. ELF loading and relocation via `aya-obj` (`runtime`)
4. Event pipeline with RingBuf + fallback queue (`event`)
5. Hprobe/Hretprobe coexistence on the same symbol (`hprobe`)
6. Guest-kprobe in two modes:
   - `Stage2Fault`: mark guest code page non-executable
   - `BrkInject`: patch guest instruction with BRK/INT3
7. Stale BRK recovery after detach to reduce guest trap races

## Layout (High Level)

```
src/
  lib.rs
  platform.rs
  symbols.rs
  tracepoint.rs
  tracepoints/
  runtime.rs
  maps.rs
  map_ops.rs
  event.rs
  context.rs
  attach.rs
  helpers.rs
  programs/
  probe/
    hprobe/
    kprobe/
tests/
  runtime_tests.rs
  symbols_tests.rs
  tracepoint_tests.rs
  guest_addr_translate_tests.rs
  guest_kprobe_manager_tests.rs
  guest_kprobe_handler_tests.rs
  hprobe_coexistence_tests.rs
  hretprobe_event_tests.rs
```

Note: this is intentionally non-exhaustive. Use `rg --files src tests` for full file list.

## Feature Flags

| Feature | Description | Dependencies |
|---|---|---|
| `symbols` | Symbol table support | `ksym` |
| `tracepoint-support` | Tracepoint subsystem and static keys | `symbols`, `tracepoint`, `tp-lexer`, `spin`, `static-keys` |
| `runtime` | eBPF VM, ELF loader, maps, ringbuf pipeline | `rbpf`, `kbpf-basic`, `aya-obj`, `hashbrown`, `spin`, `axalloc` |
| `axhal` | Real kernel platform operations | `axhal` |
| `precompiled-ebpf` | Embed `.o` files from `target/bpf` | none |
| `hprobe` | EL2 self-probing with breakpoints | `tracepoint-support`, `kprobe` |
| `guest-kprobe` | Guest kernel probing support | `hprobe` |
| `test-utils` | Extra test hooks/mocks | none |

Default features: `symbols`, `tracepoint-support`, `runtime`, `axhal`

## Dependency and Integration Notes

### Use inside AxVisor workspace (recommended)

```toml
[dependencies]
axebpf = { path = "modules/axebpf" }
```

### Use as a standalone external crate

Current `Cargo.toml` inherits `axalloc` from workspace dependencies. If you copy this crate out of AxVisor without adapting dependency sources, cargo manifest resolution fails.

If you need standalone usage, either:

1. Keep it in a workspace that provides `workspace.dependencies.axalloc`, or
2. Replace inherited workspace dependency entries with explicit crate/git dependencies.

## Initialization

Call one of:

1. `axebpf::init()` for runtime/tracepoint setup without loading kallsyms
2. `axebpf::init_with_symbols(kallsyms_blob, stext, etext)` when kprobe symbol lookup is required

`init_with_symbols` loads symbol table first, then initializes tracepoint/runtime modules.

## Guest-Kprobe Bring-Up Checklist

Guest-kprobe depends on VM integration hooks. Before `attach`, register hooks from your VMM side.

### Required hooks

1. `probe::kprobe::addr_translate::register_vm_ttbr1_hook`
2. `probe::kprobe::addr_translate::register_guest_pt_read_hook`
3. One of:
   - `probe::kprobe::addr_translate::register_gpa_to_hpa_hook` (for translation chain), or
   - `probe::kprobe::addr_translate::register_gva_to_hva_hook` (direct translation shortcut)
4. `probe::kprobe::manager::register_stage2_exec_hook` (required for `Stage2Fault` mode)

### Typical flow

```rust
use axebpf::probe::kprobe::{
    addr_translate,
    manager::{self, KprobeMode},
    handler,
};

// 1) Initialize subsystem once
manager::init();

// 2) Register integration hooks from VMM
addr_translate::register_vm_ttbr1_hook(vm_ttbr1_hook);
addr_translate::register_guest_pt_read_hook(guest_pt_read_hook);
addr_translate::register_gpa_to_hpa_hook(gpa_to_hpa_hook);
addr_translate::register_gva_to_hva_hook(gva_to_hva_hook); // optional if direct path is preferred
manager::register_stage2_exec_hook(stage2_exec_hook);

// 3) Attach probe
manager::attach(vm_id, gva, prog_id, false, KprobeMode::BrkInject)?;

// 4) In trap/exit path, dispatch events to handler
let _ = handler::handle_guest_brk(vm_id, pc, iss);
let _ = handler::handle_stage2_exec_fault(vm_id, gpa, gva, true);

// 5) Detach when finished
manager::detach(vm_id, gva)?;
# Ok::<(), &'static str>(())
```

## Probe Types

| Probe | Target | Mechanism | Feature |
|---|---|---|---|
| Hprobe | VMM function entry (EL2) | Breakpoint patching + single-step | `hprobe` |
| Hretprobe | VMM function return (EL2) | Return probe bookkeeping + breakpoint | `hprobe` |
| Guest Kprobe | Guest kernel (EL1) | Stage-2 fault or BRK injection | `guest-kprobe` |
| Tracepoint | VMM static points | Compile-time instrumentation | `tracepoint-support` |

## Event Pipeline

`event` module provides a unified `TraceEvent` record (64 bytes):

1. Producers: tracepoint / hprobe / guest-kprobe handlers
2. Sink 1: RingBuf map (best effort)
3. Sink 2: fallback queue (always keeps recent events for shell-side consumption)

Probe tags include:

1. `tracepoint`
2. `hprobe`
3. `hretprobe`
4. `kprobe`
5. `kretprobe`

## eBPF Helpers

Standard helper IDs include:

1. `bpf_map_lookup_elem`
2. `bpf_map_update_elem`
3. `bpf_map_delete_elem`
4. `bpf_probe_read`
5. `bpf_ktime_get_ns`
6. `bpf_trace_printk`
7. `bpf_get_smp_processor_id`

Hypervisor-specific helper IDs include:

1. `bpf_get_current_vm_id`
2. `bpf_get_current_vcpu_id`
3. `bpf_get_exit_reason`

## Build and Verification Commands

Commands below were checked in this repository state.

### Compile checks

```bash
# Minimal practical set for runtime development
cargo check --no-default-features --features "symbols,tracepoint-support,runtime"

# Full default feature check
cargo check
```

### Focused tests (compile-only)

```bash
# guest-kprobe handler path
cargo test --no-default-features \
  --features "symbols,tracepoint-support,runtime,hprobe,guest-kprobe,test-utils" \
  --test guest_kprobe_handler_tests --no-run

# hprobe entry/ret coexistence
cargo test --no-default-features \
  --features "symbols,tracepoint-support,runtime,hprobe,test-utils" \
  --test hprobe_coexistence_tests --no-run
```

### Notes on `runtime_tests`

`tests/runtime_tests.rs` loads object files from `target/bpf/*.o` via `include_bytes!`. Make sure these files exist before building that test target.

The `precompiled-ebpf` feature in `src/programs/bytecode.rs` also expects prebuilt objects under `target/bpf`.

## License

GPL-3.0-or-later OR Apache-2.0
