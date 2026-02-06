//! Pre-compiled eBPF program registry.

use alloc::vec::Vec;

use super::bytecode;

/// Pre-compiled program information
#[derive(Debug, Clone)]
pub struct PrecompiledProgram {
    /// Program name
    pub name: &'static str,
    /// Program description
    pub description: &'static str,
    /// Bytecode
    pub bytecode: &'static [u8],
}

/// Pre-compiled program registry
pub struct ProgramRegistry;

impl ProgramRegistry {
    /// Get all available pre-compiled programs
    pub fn list() -> Vec<PrecompiledProgram> {
        let mut programs = Vec::new();

        if !bytecode::STATS.is_empty() {
            programs.push(PrecompiledProgram {
                name: "stats",
                description: "Statistics collector (COUNT/TOTAL/MIN/MAX)",
                bytecode: bytecode::STATS,
            });
        }

        if !bytecode::PRINTK.is_empty() {
            programs.push(PrecompiledProgram {
                name: "printk",
                description: "Debug logger (prints tracepoint name and count)",
                bytecode: bytecode::PRINTK,
            });
        }

        if !bytecode::KPROBE_ARGS.is_empty() {
            programs.push(PrecompiledProgram {
                name: "kprobe_args",
                description: "Kprobe argument tracer (captures x0-x3)",
                bytecode: bytecode::KPROBE_ARGS,
            });
        }

        if !bytecode::KPROBE_SIMPLE.is_empty() {
            programs.push(PrecompiledProgram {
                name: "kprobe_simple",
                description: "Simple kprobe tracer (captures x0 only)",
                bytecode: bytecode::KPROBE_SIMPLE,
            });
        }

        if !bytecode::KPROBE_NOOP.is_empty() {
            programs.push(PrecompiledProgram {
                name: "kprobe_noop",
                description: "Minimal noop kprobe (just returns 1)",
                bytecode: bytecode::KPROBE_NOOP,
            });
        }

        programs
    }

    /// Get pre-compiled program by name
    pub fn get(name: &str) -> Option<PrecompiledProgram> {
        match name {
            "stats" if !bytecode::STATS.is_empty() => Some(PrecompiledProgram {
                name: "stats",
                description: "Statistics collector (COUNT/TOTAL/MIN/MAX)",
                bytecode: bytecode::STATS,
            }),
            "printk" if !bytecode::PRINTK.is_empty() => Some(PrecompiledProgram {
                name: "printk",
                description: "Debug logger (prints tracepoint name and count)",
                bytecode: bytecode::PRINTK,
            }),
            "kprobe_args" if !bytecode::KPROBE_ARGS.is_empty() => Some(PrecompiledProgram {
                name: "kprobe_args",
                description: "Kprobe argument tracer (captures x0-x3)",
                bytecode: bytecode::KPROBE_ARGS,
            }),
            "kprobe_simple" if !bytecode::KPROBE_SIMPLE.is_empty() => Some(PrecompiledProgram {
                name: "kprobe_simple",
                description: "Simple kprobe tracer (captures x0 only)",
                bytecode: bytecode::KPROBE_SIMPLE,
            }),
            "kprobe_noop" if !bytecode::KPROBE_NOOP.is_empty() => Some(PrecompiledProgram {
                name: "kprobe_noop",
                description: "Minimal noop kprobe (just returns 1)",
                bytecode: bytecode::KPROBE_NOOP,
            }),
            _ => None,
        }
    }

    /// Check if any pre-compiled programs are available
    pub fn is_available() -> bool {
        !bytecode::STATS.is_empty() || !bytecode::PRINTK.is_empty() || !bytecode::KPROBE_ARGS.is_empty()
    }
}
