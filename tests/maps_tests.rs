//! Integration tests for eBPF maps.
//!
//! Tests map creation, CRUD operations, and different map types.

use axebpf::maps::{self, Error, MapDef, MapType};

// =============================================================================
// Map Creation Tests
// =============================================================================

#[test]
fn test_create_array_map() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 4,
        value_size: 8,
        max_entries: 16,
    };
    let result = maps::create(&def);
    assert!(result.is_ok());
}

#[test]
fn test_create_hashmap() {
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 64,
    };
    let result = maps::create(&def);
    assert!(result.is_ok());
}

#[test]
fn test_create_lru_hash() {
    let def = MapDef {
        map_type: MapType::LruHash,
        key_size: 8,
        value_size: 16,
        max_entries: 32,
    };
    let result = maps::create(&def);
    assert!(result.is_ok());
}

#[test]
fn test_create_queue() {
    let def = MapDef {
        map_type: MapType::Queue,
        key_size: 0,
        value_size: 8,
        max_entries: 128,
    };
    let result = maps::create(&def);
    assert!(result.is_ok());
}

// =============================================================================
// Map CRUD Tests
// =============================================================================

#[test]
fn test_update_and_lookup() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let key: u64 = 0;
    let value: u64 = 12345;

    // Update
    let result = maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0);
    assert!(result.is_ok());

    // Lookup
    let retrieved = maps::lookup_elem(map_id, &key.to_le_bytes());
    assert!(retrieved.is_some());

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&retrieved.unwrap());
    assert_eq!(u64::from_le_bytes(buf), 12345);
}

#[test]
fn test_lookup_nonexistent_key() {
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let key: u64 = 999;
    let result = maps::lookup_elem(map_id, &key.to_le_bytes());
    assert!(result.is_none());
}

#[test]
fn test_delete_elem() {
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let key: u64 = 1;
    let value: u64 = 100;

    // Insert
    maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0).unwrap();

    // Delete
    let result = maps::delete_elem(map_id, &key.to_le_bytes());
    assert!(result.is_ok());

    // Verify deleted
    let lookup = maps::lookup_elem(map_id, &key.to_le_bytes());
    assert!(lookup.is_none());
}

#[test]
fn test_delete_nonexistent_key() {
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let key: u64 = 999;
    let result = maps::delete_elem(map_id, &key.to_le_bytes());
    assert!(matches!(result, Err(Error::KeyNotFound)));
}

#[test]
fn test_update_existing_key() {
    let def = MapDef {
        map_type: MapType::HashMap,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let key: u64 = 1;
    let value1: u64 = 100;
    let value2: u64 = 200;

    // Insert initial value
    maps::update_elem(map_id, &key.to_le_bytes(), &value1.to_le_bytes(), 0).unwrap();

    // Update with new value
    maps::update_elem(map_id, &key.to_le_bytes(), &value2.to_le_bytes(), 0).unwrap();

    // Verify updated
    let retrieved = maps::lookup_elem(map_id, &key.to_le_bytes()).unwrap();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&retrieved);
    assert_eq!(u64::from_le_bytes(buf), 200);
}

// =============================================================================
// Map Capacity Tests
// =============================================================================

#[test]
fn test_map_full_error() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 2,
    };
    let map_id = maps::create(&def).unwrap();

    // Fill the map
    for i in 0u64..2 {
        let value = i * 10;
        maps::update_elem(map_id, &i.to_le_bytes(), &value.to_le_bytes(), 0).unwrap();
    }

    // Try to add one more (should fail for Array type)
    let key: u64 = 3;
    let value: u64 = 30;
    let result = maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0);
    assert!(matches!(result, Err(Error::NoSpace)));
}

#[test]
fn test_lru_eviction() {
    let def = MapDef {
        map_type: MapType::LruHash,
        key_size: 8,
        value_size: 8,
        max_entries: 2,
    };
    let map_id = maps::create(&def).unwrap();

    // Fill the map
    for i in 0u64..2 {
        let value = i * 10;
        maps::update_elem(map_id, &i.to_le_bytes(), &value.to_le_bytes(), 0).unwrap();
    }

    // Add one more (should succeed, evicting oldest)
    let key: u64 = 2;
    let value: u64 = 20;
    let result = maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0);
    assert!(result.is_ok());

    // First entry should be evicted
    let lookup = maps::lookup_elem(map_id, &0u64.to_le_bytes());
    assert!(lookup.is_none());
}

// =============================================================================
// Map Destroy Tests
// =============================================================================

#[test]
fn test_destroy_map() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    let result = maps::destroy(map_id);
    assert!(result.is_ok());
}

#[test]
fn test_destroy_nonexistent_map() {
    let result = maps::destroy(9999);
    assert!(matches!(result, Err(Error::NotFound)));
}

// =============================================================================
// Invalid Argument Tests
// =============================================================================

#[test]
fn test_invalid_key_size() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    // Wrong key size (4 instead of 8)
    let key: u32 = 0;
    let value: u64 = 100;
    let result = maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0);
    assert!(matches!(result, Err(Error::InvalidArgument)));
}

#[test]
fn test_invalid_value_size() {
    let def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };
    let map_id = maps::create(&def).unwrap();

    // Wrong value size (4 instead of 8)
    let key: u64 = 0;
    let value: u32 = 100;
    let result = maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0);
    assert!(matches!(result, Err(Error::InvalidArgument)));
}
