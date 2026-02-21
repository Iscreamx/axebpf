//! eBPF Map data structures.
//!
//! Wraps kbpf-basic to provide Map storage for eBPF programs.
//! API remains compatible with the previous simplified implementation.

use alloc::vec::Vec;

use kbpf_basic::linux_bpf::BpfMapType;
use kbpf_basic::map::{BpfMapMeta, UnifiedMap, bpf_map_create};
use kbpf_basic::{BpfError, KernelAuxiliaryOps};

use crate::map_ops::{AxKernelAuxOps, DummyPerCpuOps, map_count, register_map, unregister_map};

/// Map type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    /// Fixed-size array, integer keys 0..max_entries.
    Array,
    /// Hash table with arbitrary keys.
    HashMap,
    /// Hash table with LRU eviction.
    LruHash,
    /// FIFO queue.
    Queue,
    /// Ring buffer for event streaming (key_size=0, value_size=0).
    RingBuf,
}

/// Map definition for creating new maps.
#[derive(Debug, Clone)]
pub struct MapDef {
    /// Type of map.
    pub map_type: MapType,
    /// Size of key in bytes.
    pub key_size: u32,
    /// Size of value in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
}

/// Error types for map operations.
#[derive(Debug, Clone)]
pub enum Error {
    /// Map not found.
    NotFound,
    /// Key not found in map.
    KeyNotFound,
    /// Map is full.
    NoSpace,
    /// Invalid argument.
    InvalidArgument,
    /// Map type not supported.
    NotSupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Map not found"),
            Self::KeyNotFound => write!(f, "Key not found"),
            Self::NoSpace => write!(f, "Map is full"),
            Self::InvalidArgument => write!(f, "Invalid argument"),
            Self::NotSupported => write!(f, "Map type not supported"),
        }
    }
}

impl core::error::Error for Error {}

impl From<BpfError> for Error {
    fn from(e: BpfError) -> Self {
        match e {
            BpfError::NotFound => Error::NotFound,
            BpfError::NoSpace => Error::NoSpace,
            BpfError::InvalidArgument => Error::InvalidArgument,
            BpfError::NotSupported => Error::NotSupported,
            BpfError::TryAgain => Error::InvalidArgument,
            BpfError::TooBig => Error::InvalidArgument,
        }
    }
}

/// Convert MapType to kbpf-basic BpfMapType.
fn to_bpf_map_type(map_type: MapType) -> BpfMapType {
    match map_type {
        MapType::Array => BpfMapType::BPF_MAP_TYPE_ARRAY,
        MapType::HashMap => BpfMapType::BPF_MAP_TYPE_HASH,
        MapType::LruHash => BpfMapType::BPF_MAP_TYPE_LRU_HASH,
        MapType::Queue => BpfMapType::BPF_MAP_TYPE_QUEUE,
        MapType::RingBuf => BpfMapType::BPF_MAP_TYPE_RINGBUF,
    }
}

/// Convert MapDef to kbpf-basic BpfMapMeta.
fn to_bpf_map_meta(def: &MapDef) -> BpfMapMeta {
    BpfMapMeta {
        map_type: to_bpf_map_type(def.map_type),
        key_size: def.key_size,
        value_size: def.value_size,
        max_entries: def.max_entries,
        ..Default::default()
    }
}

/// Create a new map and return its ID.
///
/// # Arguments
/// * `def` - Map definition specifying type, sizes, and capacity.
///
/// # Returns
/// Map ID on success.
pub fn create(def: &MapDef) -> Result<u32, Error> {
    let meta = to_bpf_map_meta(def);

    // RingBuf requires a PollWaker
    let poll_waker = if def.map_type == MapType::RingBuf {
        Some(crate::map_ops::TracePollWaker::new() as alloc::sync::Arc<dyn kbpf_basic::PollWaker>)
    } else {
        None
    };

    let unified_map =
        bpf_map_create::<AxKernelAuxOps, DummyPerCpuOps>(meta, poll_waker).map_err(Error::from)?;

    let id = register_map(unified_map);
    log::debug!("Created map {} with type {:?}", id, def.map_type);
    Ok(id)
}

/// Lookup an element in a map.
///
/// # Arguments
/// * `map_id` - Map ID returned by create().
/// * `key` - Key bytes.
///
/// # Returns
/// Value bytes if found.
pub fn lookup_elem(map_id: u32, key: &[u8]) -> Option<Vec<u8>> {
    AxKernelAuxOps::get_unified_map_from_fd(map_id, |unified_map: &mut UnifiedMap| {
        let result = unified_map.map_mut().lookup_elem(key)?;
        match result {
            Some(value) => Ok(Some(value.to_vec())),
            None => Ok(None),
        }
    })
    .ok()
    .flatten()
}

/// Update an element in a map.
///
/// # Arguments
/// * `map_id` - Map ID.
/// * `key` - Key bytes.
/// * `value` - Value bytes.
/// * `flags` - Update flags (0 = create or update).
pub fn update_elem(map_id: u32, key: &[u8], value: &[u8], flags: u64) -> Result<(), Error> {
    AxKernelAuxOps::get_unified_map_from_fd(map_id, |unified_map: &mut UnifiedMap| {
        unified_map.map_mut().update_elem(key, value, flags)
    })
    .map_err(Error::from)
}

/// Delete an element from a map.
///
/// # Arguments
/// * `map_id` - Map ID.
/// * `key` - Key bytes.
pub fn delete_elem(map_id: u32, key: &[u8]) -> Result<(), Error> {
    AxKernelAuxOps::get_unified_map_from_fd(map_id, |unified_map: &mut UnifiedMap| {
        unified_map.map_mut().delete_elem(key)
    })
    .map_err(Error::from)
}

/// Get the number of maps in the registry.
pub fn count() -> usize {
    map_count()
}

/// Delete a map by ID.
pub fn destroy(map_id: u32) -> Result<(), Error> {
    unregister_map(map_id).map_err(Error::from)?;
    log::debug!("Destroyed map {}", map_id);
    Ok(())
}

/// Iterate all entries in a map.
///
/// # Arguments
/// * `map_fd` - Map ID returned by create().
///
/// # Returns
/// Vector of (key, value) byte pairs.
pub fn iter_entries(map_fd: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    use crate::map_ops::iter_map_keys;

    let mut entries = Vec::new();

    // Iterate all keys
    let keys = iter_map_keys(map_fd);

    // Lookup value for each key
    for key in keys {
        if let Some(value) = lookup_elem(map_fd, &key) {
            entries.push((key, value));
        }
    }

    entries
}
