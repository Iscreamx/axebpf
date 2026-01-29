//! Kernel symbol table management.
//!
//! Provides symbol lookup by address and name for eBPF helpers
//! and stack trace symbolization.

use alloc::string::String;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use ksym::KallsymsMapped;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

struct GlobalSymbolTable(UnsafeCell<Option<KallsymsMapped<'static>>>);
unsafe impl Sync for GlobalSymbolTable {}
static SYMBOL_TABLE: GlobalSymbolTable = GlobalSymbolTable(UnsafeCell::new(None));

const KSYM_NAME_LEN: usize = 1024;

/// Error types for symbol operations.
#[derive(Debug)]
pub enum Error {
    /// Symbol table has already been initialized.
    AlreadyInitialized,
    /// Failed to parse the symbol table blob.
    ParseError(&'static str),
    /// Symbol table has not been initialized yet.
    NotInitialized,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "Symbol table already initialized"),
            Self::ParseError(e) => write!(f, "Failed to parse symbol table: {}", e),
            Self::NotInitialized => write!(f, "Symbol table not initialized"),
        }
    }
}

impl core::error::Error for Error {}

/// Initialize the kernel symbol table from a binary blob.
///
/// # Arguments
/// * `data` - The binary blob containing compressed symbol data
/// * `stext` - Start address of kernel text section
/// * `etext` - End address of kernel text section
///
/// # Safety
/// The `data` slice must remain valid for the lifetime of the program (static).
/// This function is not thread-safe if called concurrently with other init calls.
pub fn init(data: &'static [u8], stext: u64, etext: u64) -> Result<(), Error> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(Error::AlreadyInitialized);
    }

    let table = KallsymsMapped::from_blob(data, stext, etext).map_err(Error::ParseError)?;

    unsafe {
        *SYMBOL_TABLE.0.get() = Some(table);
    }

    Ok(())
}

/// Check if the symbol table has been initialized.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Lookup a symbol by address.
///
/// Returns (name, size, offset, type) if found.
/// - `name`: The symbol name
/// - `size`: Size of the symbol
/// - `offset`: Offset from the symbol start address
/// - `type`: Symbol type character (T, t, D, d, etc.)
pub fn lookup_symbol(addr: u64) -> Option<(String, u64, u64, char)> {
    let table_ptr = SYMBOL_TABLE.0.get();
    let table = unsafe { (*table_ptr).as_ref() }?;

    let mut name_buf = [0u8; KSYM_NAME_LEN];

    if let Some((name, size, offset, ty)) = table.lookup_address(addr, &mut name_buf) {
        Some((String::from(name), size, offset, ty))
    } else {
        None
    }
}

/// Lookup an address by symbol name.
///
/// Returns the address of the symbol if found.
pub fn lookup_addr(name: &str) -> Option<u64> {
    let table_ptr = SYMBOL_TABLE.0.get();
    let table = unsafe { (*table_ptr).as_ref() }?;
    table.lookup_name(name)
}
