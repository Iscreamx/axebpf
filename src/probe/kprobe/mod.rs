//! Guest Kernel Probe (kprobe) — cross-privilege probing.
//!
//! Probes guest VM kernel code (EL1) from the VMM (EL2).
//! Analogous to Linux uprobe: a higher-privilege observer
//! instruments lower-privilege code across address space boundaries.
//!
//! Two modes:
//! - Stage-2 fault (default): mark guest page as non-executable via Stage-2 XN bit
//! - BRK injection (advanced): write BRK instruction directly into guest memory

pub mod addr_translate;
pub mod manager;
pub mod handler;
