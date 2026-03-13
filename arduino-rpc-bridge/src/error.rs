// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC error types

use crate::msgpack::StrBuf;

/// RPC error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcErrorCode {
    /// No error
    NoError = 0x00,
    /// Parsing error
    ParsingError = 0xFC,
    /// Malformed call
    MalformedCall = 0xFD,
    /// Function not found
    FunctionNotFound = 0xFE,
    /// Generic error
    GenericError = 0xFF,
}

impl From<u8> for RpcErrorCode {
    fn from(code: u8) -> Self {
        match code {
            0x00 => RpcErrorCode::NoError,
            0xFC => RpcErrorCode::ParsingError,
            0xFD => RpcErrorCode::MalformedCall,
            0xFE => RpcErrorCode::FunctionNotFound,
            _ => RpcErrorCode::GenericError,
        }
    }
}

/// RPC error with code and message
#[derive(Debug, Clone)]
pub struct RpcError {
    /// Error code
    pub code: RpcErrorCode,
    /// Error message/traceback
    pub message: StrBuf,
}

impl RpcError {
    /// Create a new error
    pub fn new(code: RpcErrorCode, message: &str) -> Self {
        Self {
            code,
            message: StrBuf::from_bytes(message.as_bytes()).unwrap_or_default(),
        }
    }

    /// Create a "no error" result
    pub const fn none() -> Self {
        Self {
            code: RpcErrorCode::NoError,
            message: StrBuf::new(),
        }
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        self.code != RpcErrorCode::NoError
    }
}

impl Default for RpcError {
    fn default() -> Self {
        Self::none()
    }
}
