//! Linux userspace lifecycle observer adapters.

use alloc::string::ToString;

use super::manager;
use super::process_maps::{ObserverEvent, ProcessMaps};

pub fn on_exec(maps: &ProcessMaps, vm_id: u32, pid: u32, tgid: u32, mm: u64, comm: &str) {
    maps.apply(ObserverEvent::Exec {
        vm_id,
        pid,
        tgid,
        mm,
        comm: comm.to_string(),
    });
}

pub fn on_mmap(
    maps: &ProcessMaps,
    vm_id: u32,
    mm: u64,
    start: u64,
    end: u64,
    file_offset: u64,
    guest_path: &str,
) -> usize {
    maps.apply(ObserverEvent::Mmap {
        vm_id,
        mm,
        start,
        end,
        file_offset,
        guest_path: guest_path.to_string(),
    });
    match manager::try_activate_for_mm(maps, vm_id, mm) {
        Ok(count) => count,
        Err(err) => {
            log::debug!(
                "guest_uprobe: observer activation skipped vm{} mm={:#x}: {}",
                vm_id,
                mm,
                err
            );
            0
        }
    }
}

pub fn on_munmap(maps: &ProcessMaps, vm_id: u32, mm: u64, start: u64, end: u64) {
    maps.apply(ObserverEvent::Munmap {
        vm_id,
        mm,
        start,
        end,
    });
}

pub fn on_exit_mm(maps: &ProcessMaps, vm_id: u32, mm: u64) {
    maps.apply(ObserverEvent::ExitMm { vm_id, mm });
}

pub fn on_exit(maps: &ProcessMaps, vm_id: u32, pid: u32) {
    maps.apply(ObserverEvent::Exit { vm_id, pid });
}
