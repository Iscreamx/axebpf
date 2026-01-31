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
            _ => None,
        }
    }

    /// Check if any pre-compiled programs are available
    pub fn is_available() -> bool {
        !bytecode::STATS.is_empty() || !bytecode::PRINTK.is_empty()
    }
}
