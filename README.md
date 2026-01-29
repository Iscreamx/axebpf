# axebpf

eBPF runtime, symbol table, and tracepoint framework for AxVisor Hypervisor.

## Overview

`axebpf` provides a comprehensive eBPF-based tracing infrastructure for AxVisor, enabling dynamic performance analysis and observability of the hypervisor's critical paths.

## Features

- **Platform Abstraction** (`platform`) - Testable abstraction over kernel operations
- **Symbol Table Management** (`symbols`) - Kernel symbol resolution via `ksym`
- **Tracepoint Framework** (`tracepoint-support`) - Static instrumentation points for VMM events
- **eBPF Runtime** (`runtime`) - Program execution via `rbpf` VM with map support

## Module Structure

```
axebpf/
├── src/
│   ├── lib.rs              # Module entry point
│   ├── platform.rs         # Platform abstraction (mock/real kernel ops)
│   ├── symbols.rs          # Symbol table management (ksym wrapper)
│   ├── tracepoint.rs       # Tracepoint framework (TracepointManager)
│   ├── runtime.rs          # eBPF VM and program management
│   ├── maps.rs             # eBPF map implementations (Array, HashMap, LRU, Queue)
│   ├── helpers.rs          # Standard eBPF helper functions
│   ├── attach.rs           # Program attachment management
│   ├── kops.rs             # Kernel operations interface (AxKops)
│   ├── macros.rs           # Helper macros
│   ├── examples/           # Usage examples
│   │   └── mod.rs
│   └── tracepoints/        # VMM-specific tracepoints
│       ├── mod.rs          # VMM tracepoint exports
│       ├── definitions.rs  # Tracepoint definitions
│       ├── stats.rs        # Built-in statistics collector
│       ├── histogram.rs    # Latency distribution histograms
│       └── hypervisor_helpers.rs  # Hypervisor-specific eBPF helpers
└── tests/
    ├── runtime_tests.rs    # Runtime/program tests
    ├── maps_tests.rs       # Map CRUD tests
    ├── helpers_tests.rs    # Helper function tests
    ├── attach_tests.rs     # Program attachment tests
    └── symbols_tests.rs    # Symbol table tests
```

## Dependencies

| Crate | Source | Purpose |
|-------|--------|---------|
| `ksym` | [Starry-OS](https://github.com/Starry-OS/ksym) | Symbol table generation and lookup |
| `tracepoint` | [Starry-OS](https://github.com/Starry-OS/tracepoint) | Static tracepoint framework |
| `tp-lexer` | [Starry-OS](https://github.com/Starry-OS/tp-lexer) | Tracepoint filter expressions |
| `rbpf` | [qmonnet](https://github.com/qmonnet/rbpf) | eBPF virtual machine |
| `kbpf-basic` | [Iscreamx](https://github.com/Iscreamx/kbpf-basic) | eBPF map implementations |
| `axhal` | [arceos](https://github.com/arceos-org/arceos) | Kernel operations (optional, for real platform) |

## Usage

### Cargo.toml

```toml
[dependencies]
axebpf = { path = "modules/axebpf" }

# Or with specific features
axebpf = { path = "modules/axebpf", features = ["tracepoint-support", "runtime"] }
```

### Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `symbols` | Symbol table support | `ksym` |
| `tracepoint-support` | Tracepoint framework | `symbols`, `tracepoint`, `tp-lexer`, `spin`, `static-keys` |
| `runtime` | eBPF VM and maps | `rbpf`, `kbpf-basic`, `spin` |
| `axhal` | Real kernel platform ops | `axhal` |

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

## Defined Tracepoints

### VM Lifecycle
- `vmm:vm_create` - VM creation
- `vmm:vm_boot` - VM boot sequence
- `vmm:vm_shutdown` - VM shutdown
- `vmm:vm_destroy` - VM destruction

### vCPU Lifecycle
- `vmm:vcpu_create` - vCPU creation
- `vmm:vcpu_destroy` - vCPU destruction
- `vmm:vcpu_state_change` - vCPU state transitions

### vCPU Runtime
- `vmm:vcpu_run_enter` - VM entry
- `vmm:vcpu_run_exit` - VM exit
- `vmm:hypercall` - Hypercall handling
- `vmm:external_interrupt` - External interrupt
- `vmm:vcpu_halt` - vCPU halt
- `vmm:cpu_up` - Secondary CPU boot
- `vmm:ipi_send` - IPI sending

### Memory Management
- `vmm:memory_map` - Memory mapping
- `vmm:memory_unmap` - Memory unmapping
- `vmm:page_fault` - Page fault handling

### Device & IRQ
- `vmm:device_access` - Device MMIO access
- `vmm:irq_inject` - Interrupt injection
- `vmm:irq_handle` - Interrupt handling

### System Initialization
- `vmm:vmm_init` - VMM initialization
- `vmm:vhal_init` - VHal initialization
- `vmm:config_load` - Configuration loading
- `vmm:image_load` - Image loading

### Shell
- `shell:shell_init` - Shell initialization
- `shell:shell_command` - Shell command execution

### Timer
- `vmm:timer_tick` - Timer tick
- `vmm:timer_event` - Timer event
- `vmm:task_switch` - Task context switch

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
