//! eBPF Map data structures.
//!
//! Wraps kbpf-basic to provide Map storage for eBPF programs.

use alloc::vec::Vec;
use spin::Mutex;

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

/// Internal map storage using simple Vec-based implementation.
struct MapStorage {
    def: MapDef,
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MapStorage {
    fn new(def: MapDef) -> Self {
        Self {
            def,
            data: Vec::new(),
        }
    }

    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        for (k, v) in &self.data {
            if k == key {
                return Some(v.clone());
            }
        }
        None
    }

    fn update(&mut self, key: &[u8], value: &[u8], _flags: u64) -> Result<(), Error> {
        // Check sizes
        if key.len() != self.def.key_size as usize {
            return Err(Error::InvalidArgument);
        }
        if value.len() != self.def.value_size as usize {
            return Err(Error::InvalidArgument);
        }

        // Update existing or insert new
        for (k, v) in &mut self.data {
            if k == key {
                *v = value.to_vec();
                return Ok(());
            }
        }

        // Check capacity
        if self.data.len() >= self.def.max_entries as usize {
            // For LRU, evict first entry
            if self.def.map_type == MapType::LruHash {
                self.data.remove(0);
            } else {
                return Err(Error::NoSpace);
            }
        }

        self.data.push((key.to_vec(), value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        for i in 0..self.data.len() {
            if self.data[i].0 == key {
                self.data.remove(i);
                return Ok(());
            }
        }
        Err(Error::KeyNotFound)
    }
}

/// Global map registry.
static MAP_REGISTRY: Mutex<Vec<Option<MapStorage>>> = Mutex::new(Vec::new());

/// Create a new map and return its ID.
///
/// # Arguments
/// * `def` - Map definition specifying type, sizes, and capacity.
///
/// # Returns
/// Map ID on success.
pub fn create(def: &MapDef) -> Result<u32, Error> {
    let mut registry = MAP_REGISTRY.lock();
    let storage = MapStorage::new(def.clone());

    // Find empty slot or append
    for (i, slot) in registry.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(storage);
            log::debug!("Created map {} with type {:?}", i, def.map_type);
            return Ok(i as u32);
        }
    }

    let id = registry.len() as u32;
    registry.push(Some(storage));
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
    let registry = MAP_REGISTRY.lock();
    registry.get(map_id as usize)?.as_ref()?.lookup(key)
}

/// Update an element in a map.
///
/// # Arguments
/// * `map_id` - Map ID.
/// * `key` - Key bytes.
/// * `value` - Value bytes.
/// * `flags` - Update flags (0 = create or update).
pub fn update_elem(map_id: u32, key: &[u8], value: &[u8], flags: u64) -> Result<(), Error> {
    let mut registry = MAP_REGISTRY.lock();
    let storage = registry
        .get_mut(map_id as usize)
        .ok_or(Error::NotFound)?
        .as_mut()
        .ok_or(Error::NotFound)?;
    storage.update(key, value, flags)
}

/// Delete an element from a map.
///
/// # Arguments
/// * `map_id` - Map ID.
/// * `key` - Key bytes.
pub fn delete_elem(map_id: u32, key: &[u8]) -> Result<(), Error> {
    let mut registry = MAP_REGISTRY.lock();
    let storage = registry
        .get_mut(map_id as usize)
        .ok_or(Error::NotFound)?
        .as_mut()
        .ok_or(Error::NotFound)?;
    storage.delete(key)
}

/// Get the number of maps in the registry.
pub fn count() -> usize {
    let registry = MAP_REGISTRY.lock();
    registry.iter().filter(|s| s.is_some()).count()
}

/// Delete a map by ID.
pub fn destroy(map_id: u32) -> Result<(), Error> {
    let mut registry = MAP_REGISTRY.lock();
    let slot = registry.get_mut(map_id as usize).ok_or(Error::NotFound)?;
    if slot.is_none() {
        return Err(Error::NotFound);
    }
    *slot = None;
    log::debug!("Destroyed map {}", map_id);
    Ok(())
}
