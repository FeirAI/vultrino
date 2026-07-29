//! WASM plugin runtime
//!
//! This module provides the runtime for executing WASM plugins.
//! It supports the WASI preview 1 interface and provides a standardized
//! ABI for plugin communication.

mod runtime;

pub use runtime::{WasmPlugin, WasmRuntime, WasmtimeRuntime};

/// WASM plugin ABI version.
///
/// Version 2 is the credential-confining ABI: guests receive only an opaque
/// credential handle (alias + type), never serialized [`crate::CredentialData`].
/// Secret-using operations must be added as narrow host capabilities; until a
/// capability exists, the guest must fail closed rather than receive plaintext.
pub const WASM_ABI_VERSION: u32 = 2;

/// Memory allocation result from WASM
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WasmPtr {
    pub offset: u32,
    pub len: u32,
}

impl WasmPtr {
    pub fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    /// Decode from a packed i64 value (offset in lower 32 bits, len in upper 32 bits)
    pub fn from_i64(packed: i64) -> Self {
        Self {
            offset: (packed & 0xFFFFFFFF) as u32,
            len: ((packed >> 32) & 0xFFFFFFFF) as u32,
        }
    }

    /// Encode to a packed i64 value
    pub fn to_i64(&self) -> i64 {
        (self.offset as i64) | ((self.len as i64) << 32)
    }
}

/// Result codes from WASM plugin execution
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmResultCode {
    /// Success
    Ok = 0,
    /// Invalid parameters
    InvalidParams = 1,
    /// Unsupported action
    UnsupportedAction = 2,
    /// Execution failed
    ExecutionFailed = 3,
    /// Memory allocation failed
    AllocationFailed = 4,
    /// Invalid credential
    InvalidCredential = 5,
    /// Internal error
    InternalError = -1,
}

impl From<i32> for WasmResultCode {
    fn from(code: i32) -> Self {
        match code {
            0 => WasmResultCode::Ok,
            1 => WasmResultCode::InvalidParams,
            2 => WasmResultCode::UnsupportedAction,
            3 => WasmResultCode::ExecutionFailed,
            4 => WasmResultCode::AllocationFailed,
            5 => WasmResultCode::InvalidCredential,
            _ => WasmResultCode::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_ptr_packing() {
        let ptr = WasmPtr::new(0x12345678, 0xABCDEF01);
        let packed = ptr.to_i64();
        let unpacked = WasmPtr::from_i64(packed);

        assert_eq!(unpacked.offset, 0x12345678);
        assert_eq!(unpacked.len, 0xABCDEF01);
    }
}
