//! Runtime usage examples.
//!
//! Demonstrates eBPF program loading and execution with maps and helpers.

use crate::maps::{MapDef, MapType};
use crate::runtime::EbpfProgram;

/// Example: Simple program that returns a constant.
///
/// eBPF bytecode: mov r0, 42; exit
pub const SIMPLE_PROGRAM: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r0, 42
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

/// Example: Create a map and use it.
///
/// This example shows how to:
/// 1. Create an array map
/// 2. Load an eBPF program
/// 3. Execute the program
#[allow(dead_code)]
pub fn example_with_map() {
    // Create an array map: u64 keys, u64 values, 16 entries
    let map_def = MapDef {
        map_type: MapType::Array,
        key_size: 8,
        value_size: 8,
        max_entries: 16,
    };

    let map_id = crate::maps::create(&map_def).expect("Failed to create map");
    log::info!("Created map with ID: {}", map_id);

    // Store a value
    let key: u64 = 0;
    let value: u64 = 12345;
    crate::maps::update_elem(map_id, &key.to_le_bytes(), &value.to_le_bytes(), 0)
        .expect("Failed to update map");

    // Lookup the value
    if let Some(result) = crate::maps::lookup_elem(map_id, &key.to_le_bytes()) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&result);
        let retrieved = u64::from_le_bytes(buf);
        log::info!("Retrieved value: {}", retrieved);
    }

    // Load and execute a simple program
    let program = EbpfProgram::new(SIMPLE_PROGRAM, None).expect("Failed to load program");
    let result = program.execute().expect("Failed to execute");
    log::info!("Program returned: {}", result);
}

/// Example: Use program registry.
#[allow(dead_code)]
pub fn example_with_registry() {
    use crate::runtime;

    // Load program into registry
    let prog_id = runtime::load_program(SIMPLE_PROGRAM, None).expect("Failed to load");
    log::info!("Loaded program with ID: {}", prog_id);

    // Run multiple times
    for i in 0..3 {
        let result = runtime::run_program(prog_id, None).expect("Failed to run");
        log::info!("Run {}: returned {}", i, result);
    }

    // Unload
    runtime::unload_program(prog_id).expect("Failed to unload");
    log::info!("Program unloaded");
}
