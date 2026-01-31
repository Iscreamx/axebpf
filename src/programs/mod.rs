//! Pre-compiled eBPF program management.

mod bytecode;
mod registry;

pub use registry::{PrecompiledProgram, ProgramRegistry};
