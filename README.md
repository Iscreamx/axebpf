# axebpf

eBPF runtime, symbol table, and tracepoint framework for AxVisor Hypervisor.

## Overview

`axebpf` provides eBPF-based tracing and dynamic probing infrastructure for AxVisor, enabling runtime performance analysis and observability of both the hypervisor (EL2) and guest kernels (EL1).

## Features

- **Platform Abstraction** (`platform`) - Testable abstraction over kernel operations
- **Symbol Table** (`symbols`) - Kernel symbol resolution via `ksym`
- **Tracepoint Framework** (`tracepoint-support`) - Static instrumentation points for VMM events
- **eBPF Runtime** (`runtime`) - Program execution via `rbpf` VM, ELF loading via `aya-obj`, map support
- **Hprobe** (`hprobe`) - VMM self-introspection via EL2 breakpoints
- **Guest Kprobe** (`guest-kprobe`) - Guest kernel probing via Stage-2 faults or BRK injection

## Module Structure

```
axebpf/
├── src/
│   ├── lib.rs                # Module entry point and initialization
│   ├── platform.rs           # Platform abstraction (mock/real kernel ops)
│   ├── symbols.rs            # Symbol table management (ksym wrapper)
│   ├── tracepoint.rs         # Tracepoint framework (TracepointManager)
│   ├── runtime.rs            # eBPF VM, ELF loader (aya-obj), program registry
│   ├── maps.rs               # eBPF map implementations (Array, HashMap, LRU, Queue)
│   ├── helpers.rs            # Standard eBPF helper functions
│   ├── attach.rs             # Program attachment management
│   ├── context.rs            # eBPF program execution context (TraceContext)
│   ├── output.rs             # eBPF output formatting
│   ├── trace_ops.rs          # Tracepoint operations (KernelTraceOps)
│   ├── map_ops.rs            # Map operations (KernelAuxiliaryOps for kbpf-basic)
│   ├── cache.rs              # Cache operations
│   ├── insn_slot.rs          # Instruction slot allocator for probe trampolines
│   ├── page_table.rs         # Page table manipulation for text patching
│   ├── macros.rs             # Helper macros
│   ├── probe/                # Unified probe framework
│   │   ├── mod.rs            # ProbeType enum (Hprobe/Hretprobe/Kprobe/Kretprobe/Tracepoint)
│   │   ├── hprobe/           # VMM self-introspection (EL2 breakpoints)
│   │   │   ├── mod.rs
│   │   │   ├── handler.rs    # BRK exception handler
│   │   │   ├── manager.rs    # Probe registration and lifecycle
│   │   │   └── ops.rs        # Low-level patching (instruction slot, text write)
│   │   └── kprobe/           # Guest kernel probing (cross-privilege)
│   │       ├── mod.rs
│   │       ├── handler.rs    # Guest probe exception handler
│   │       ├── manager.rs    # Guest probe registration (Stage2Fault/BrkInject modes)
│   │       └── addr_translate.rs  # GVA → IPA address translation
│   ├── programs/             # Pre-compiled eBPF programs
│   │   ├── mod.rs
│   │   ├── bytecode.rs       # Embedded .o files (include_bytes!)
│   │   └── registry.rs       # ProgramRegistry for name-based lookup
│   ├── examples/
│   │   ├── mod.rs
│   │   └── runtime_example.rs
│   └── tracepoints/          # VMM-specific tracepoint definitions
│       ├── mod.rs
│       ├── vmm.rs            # VMM tracepoints (vm, vcpu, memory, etc.)
│       ├── shell.rs          # Shell tracepoints
│       ├── stats.rs          # Built-in statistics collector
│       ├── registry.rs       # Tracepoint registry
│       ├── histogram.rs      # Latency distribution histograms
│       └── hypervisor_helpers.rs  # Hypervisor-specific eBPF helpers
└── tests/
    ├── runtime_tests.rs           # Runtime/program/ELF loading tests
    ├── maps_tests.rs              # Map CRUD tests
    ├── helpers_tests.rs           # Helper function tests
    ├── hypervisor_helpers_tests.rs # Hypervisor helper tests
    ├── attach_tests.rs            # Program attachment tests
    ├── symbols_tests.rs           # Symbol table tests
    ├── tracepoint_tests.rs        # Tracepoint framework tests
    ├── histogram_tests.rs         # Histogram tests
    └── stats_tests.rs             # Statistics collector tests
```

## Dependencies

| Crate | Source | Purpose |
|-------|--------|---------|
| `ksym` | [Starry-OS](https://github.com/Starry-OS/ksym) | Symbol table generation and lookup |
| `tracepoint` | [Starry-OS](https://github.com/Starry-OS/tracepoint) | Static tracepoint framework |
| `tp-lexer` | [Starry-OS](https://github.com/Starry-OS/tp-lexer) | Tracepoint filter expressions |
| `rbpf` | [qmonnet](https://github.com/qmonnet/rbpf) | eBPF virtual machine |
| `kbpf-basic` | [Starry-OS](https://github.com/Starry-OS/kbpf-basic) | eBPF map implementations |
| `aya-obj` | [aya-rs](https://github.com/aya-rs/aya) | ELF parsing, map/call relocation |
| `hashbrown` | [crates.io](https://crates.io/crates/hashbrown) | no_std HashMap (required by aya-obj relocation API) |
| `kprobe` | [Starry-OS](https://github.com/Starry-OS/kprobe.git) | Low-level breakpoint primitives |
| `axhal` | [arceos](https://github.com/arceos-org/arceos) | Kernel operations (optional, for real platform) |

## Usage

### Cargo.toml

```toml
[dependencies]
axebpf = { git = "https://github.com/Iscreamx/axebpf.git" }

# With specific features
axebpf = { git = "https://github.com/Iscreamx/axebpf.git", features = ["tracepoint-support", "runtime"] }

# With probe support
axebpf = { git = "https://github.com/Iscreamx/axebpf.git", features = ["hprobe", "guest-kprobe"] }
```

### Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `symbols` | Symbol table support | `ksym` |
| `tracepoint-support` | Tracepoint framework | `symbols`, `tracepoint`, `tp-lexer`, `spin`, `static-keys` |
| `runtime` | eBPF VM, ELF loader, maps | `rbpf`, `kbpf-basic`, `aya-obj`, `hashbrown`, `spin` |
| `axhal` | Real kernel platform ops | `axhal` |
| `precompiled-ebpf` | Embed pre-compiled eBPF .o files | (none) |
| `hprobe` | VMM self-introspection probes | `tracepoint-support`, `kprobe` |
| `guest-kprobe` | Guest kernel probing | `hprobe` |

**Default features:** `symbols`, `tracepoint-support`, `runtime`, `axhal`

### Running Tests

```bash
# Run tests without kernel dependencies (uses mock platform)
cargo test --no-default-features --features runtime

# Run tests with symbols feature
cargo test --no-default-features --features "runtime,symbols"
```

### Basic Example

```rust
use axebpf::tracepoint::TracepointManager;

// Initialize tracepoint subsystem
axebpf::init();

// List available tracepoints
let mgr = TracepointManager::global();
for tp in mgr.list_tracepoints() {
    println!("{}: {}", tp.name, if tp.enabled { "on" } else { "off" });
}

// Enable a tracepoint
mgr.enable("vmm:vm_create").unwrap();
```

## Probe Types

axebpf supports three probing mechanisms at different privilege levels:

| Probe | Target | Mechanism | Feature |
|-------|--------|-----------|---------|
| Hprobe | VMM functions (EL2) | BRK instruction patching + instruction slot single-step | `hprobe` |
| Guest Kprobe | Guest kernel (EL1) | Stage-2 XN fault or BRK injection into guest memory | `guest-kprobe` |
| Tracepoint | VMM static points | Compile-time instrumentation via `static-keys` | `tracepoint-support` |

## Defined Tracepoints

### VM Lifecycle
- `vmm:vm_create` / `vmm:vm_boot` / `vmm:vm_shutdown` / `vmm:vm_destroy`

### vCPU Lifecycle
- `vmm:vcpu_create` / `vmm:vcpu_destroy` / `vmm:vcpu_state_change`

### vCPU Runtime
- `vmm:vcpu_run_enter` / `vmm:vcpu_run_exit` / `vmm:hypercall`
- `vmm:external_interrupt` / `vmm:vcpu_halt` / `vmm:cpu_up` / `vmm:ipi_send`

### Memory Management
- `vmm:memory_map` / `vmm:memory_unmap` / `vmm:page_fault`

### Device & IRQ
- `vmm:device_access` / `vmm:irq_inject` / `vmm:irq_handle`

### System Initialization
- `vmm:vmm_init` / `vmm:vhal_init` / `vmm:config_load` / `vmm:image_load`

### Shell
- `shell:shell_init` / `shell:shell_command`

### Timer
- `vmm:timer_tick` / `vmm:timer_event` / `vmm:task_switch`

## eBPF Helpers

### Standard Helpers

| ID | Function | Description |
|----|----------|-------------|
| 1 | `bpf_map_lookup_elem` | Map element lookup |
| 2 | `bpf_map_update_elem` | Map element update |
| 3 | `bpf_map_delete_elem` | Map element deletion |
| 5 | `bpf_ktime_get_ns` | Get current time (ns) |
| 6 | `bpf_trace_printk` | Debug print |
| 8 | `bpf_get_smp_processor_id` | Get current CPU ID |

### Hypervisor Helpers

| ID | Function | Description |
|----|----------|-------------|
| 100 | `bpf_get_current_vm_id` | Get current VM ID |
| 101 | `bpf_get_current_vcpu_id` | Get current vCPU ID |
| 102 | `bpf_get_exit_reason` | Get VM exit reason |

## ELF Loading

The runtime uses `aya-obj` for ELF parsing and relocation, supporting:

- **Map relocation** (`R_BPF_64_64`) - Patches `ld_imm64` instructions with map FDs
- **Call relocation** (`R_BPF_64_32`) - Links BPF-to-BPF function calls (memcpy/memmove/memset)
- **`.text` section merging** - Compiler-generated helpers are merged into program bytecode
- **BTF and legacy map sections** - Both map definition formats supported

ELF data from `include_bytes!()` is automatically copied to an aligned buffer when needed (aarch64 requires 8-byte alignment for ELF header parsing).

## Architecture

### Platform Abstraction

The `platform` module provides an abstraction layer that enables:
- **Kernel mode**: Uses `axhal` for real time/CPU operations
- **Test mode**: Uses mock implementations with configurable values

```rust
// In tests, you can control mock values:
use axebpf::platform::{set_mock_time, set_mock_cpu_id};

set_mock_time(1_000_000_000); // 1 second
set_mock_cpu_id(2);
```

## License

GPL-3.0-or-later OR Apache-2.0
