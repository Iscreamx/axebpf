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

        if !bytecode::PRINTK.is_empty() {
            programs.push(PrecompiledProgram {
                name: "printk",
                description: "Debug logger (prints tracepoint name and count)",
                bytecode: bytecode::PRINTK,
            });
        }

        if !bytecode::HPROBE_ENTRY.is_empty() {
            programs.push(PrecompiledProgram {
                name: "hprobe_entry",
                description: "Hprobe entry tracer (captures x0-x3 arguments)",
                bytecode: bytecode::HPROBE_ENTRY,
            });
        }

        if !bytecode::HPROBE_EXIT.is_empty() {
            programs.push(PrecompiledProgram {
                name: "hprobe_exit",
                description: "Hprobe exit tracer (captures return value x0)",
                bytecode: bytecode::HPROBE_EXIT,
            });
        }

        programs
    }

    /// Get pre-compiled program by name
    pub fn get(name: &str) -> Option<PrecompiledProgram> {
        match name {
            "printk" if !bytecode::PRINTK.is_empty() => Some(PrecompiledProgram {
                name: "printk",
                description: "Debug logger (prints tracepoint name and count)",
                bytecode: bytecode::PRINTK,
            }),
            "hprobe_entry" if !bytecode::HPROBE_ENTRY.is_empty() => Some(PrecompiledProgram {
                name: "hprobe_entry",
                description: "Hprobe entry tracer (captures x0-x3 arguments)",
                bytecode: bytecode::HPROBE_ENTRY,
            }),
            "hprobe_exit" if !bytecode::HPROBE_EXIT.is_empty() => Some(PrecompiledProgram {
                name: "hprobe_exit",
                description: "Hprobe exit tracer (captures return value x0)",
                bytecode: bytecode::HPROBE_EXIT,
            }),
            _ => None,
        }
    }

    /// Check if any pre-compiled programs are available
    pub fn is_available() -> bool {
        !bytecode::PRINTK.is_empty() || !bytecode::HPROBE_ENTRY.is_empty() || !bytecode::HPROBE_EXIT.is_empty()
    }
}
