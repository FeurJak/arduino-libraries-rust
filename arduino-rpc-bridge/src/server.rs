// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Server for handling incoming requests
//
// This module provides server-side RPC functionality for the MCU to
// handle requests from the Linux side.

use crate::msgpack::{MsgPackPacker, MsgPackUnpacker, MsgPackValue};
use crate::{RpcMessageType, MAX_METHOD_NAME_LEN};

/// Maximum number of registered handlers
pub const MAX_HANDLERS: usize = 32;

/// Maximum number of parameters per RPC call
pub const MAX_PARAMS: usize = 8;

/// RPC method handler function type
///
/// Takes parameter count and returns an integer result code.
/// The handler should read params from the global param buffer.
pub type RpcHandler = fn(usize) -> RpcResult;

/// Result from an RPC handler
#[derive(Debug, Clone)]
pub enum RpcResult {
    /// Success with integer result
    Int(i64),
    /// Success with boolean result
    Bool(bool),
    /// Success with string result (static lifetime)
    Str(&'static str),
    /// Success with nil result
    Nil,
    /// Error with code and message
    Error(i32, &'static str),
}

/// Global parameter storage for RPC handlers
///
/// Since we're running on a single-threaded MCU, we use global storage
/// to pass parameters to handlers without complex lifetime management.
pub struct ParamBuffer {
    /// Integer parameters extracted from RPC call
    pub ints: [i64; MAX_PARAMS],
    /// Boolean parameters
    pub bools: [bool; MAX_PARAMS],
    /// Count of parameters
    pub count: usize,
}

impl ParamBuffer {
    pub const fn new() -> Self {
        Self {
            ints: [0; MAX_PARAMS],
            bools: [false; MAX_PARAMS],
            count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }
}

/// Global parameter buffer - handlers read parameters from here
pub static mut PARAMS: ParamBuffer = ParamBuffer::new();

/// Handler registration entry
struct HandlerEntry {
    method: [u8; MAX_METHOD_NAME_LEN],
    method_len: usize,
    handler: RpcHandler,
}

impl HandlerEntry {
    const fn empty() -> Self {
        Self {
            method: [0; MAX_METHOD_NAME_LEN],
            method_len: 0,
            handler: empty_handler,
        }
    }
}

fn empty_handler(_count: usize) -> RpcResult {
    RpcResult::Error(-1, "No handler")
}

/// RPC Server for handling incoming requests
///
/// Register method handlers and process incoming RPC messages.
pub struct RpcServer {
    handlers: [HandlerEntry; MAX_HANDLERS],
    handler_count: usize,
    /// Response buffer
    response_buffer: [u8; 256],
}

impl RpcServer {
    /// Create a new RPC server
    pub const fn new() -> Self {
        Self {
            handlers: [const { HandlerEntry::empty() }; MAX_HANDLERS],
            handler_count: 0,
            response_buffer: [0; 256],
        }
    }

    /// Register a method handler
    ///
    /// Returns true on success, false if max handlers reached or method name too long.
    pub fn register(&mut self, method: &str, handler: RpcHandler) -> bool {
        if self.handler_count >= MAX_HANDLERS {
            return false;
        }
        if method.len() > MAX_METHOD_NAME_LEN {
            return false;
        }

        let entry = &mut self.handlers[self.handler_count];
        entry.method[..method.len()].copy_from_slice(method.as_bytes());
        entry.method_len = method.len();
        entry.handler = handler;
        self.handler_count += 1;
        true
    }

    /// Find handler for a method
    fn find_handler(&self, method: &str) -> Option<RpcHandler> {
        for i in 0..self.handler_count {
            let entry = &self.handlers[i];
            if entry.method_len == method.len()
                && &entry.method[..entry.method_len] == method.as_bytes()
            {
                return Some(entry.handler);
            }
        }
        None
    }

    /// Process an RPC message
    ///
    /// Returns Some(response_bytes) if a response should be sent,
    /// None for notifications or errors.
    pub fn process(&mut self, data: &[u8]) -> Option<&[u8]> {
        let mut unpacker = MsgPackUnpacker::new(data);

        // Read array header
        let arr_len = match unpacker.unpack_array_header() {
            Some(len) => len,
            None => return None,
        };

        if arr_len < 3 {
            return None;
        }

        // Read message type
        let msg_type = match unpacker.unpack_uint() {
            Some(t) => t as u8,
            None => return None,
        };

        match RpcMessageType::try_from(msg_type) {
            Ok(RpcMessageType::Call) => self.handle_request(&mut unpacker),
            Ok(RpcMessageType::Notify) => {
                self.handle_notification(&mut unpacker);
                None
            }
            Ok(RpcMessageType::Response) => {
                // We received a response - this shouldn't happen on server side
                None
            }
            Err(_) => None,
        }
    }

    /// Handle an RPC request
    fn handle_request(&mut self, unpacker: &mut MsgPackUnpacker) -> Option<&[u8]> {
        // Read msgid
        let msg_id = match unpacker.unpack_uint() {
            Some(id) => id as u32,
            None => return None,
        };

        // Read method name
        let method = match unpacker.unpack_str() {
            Some(s) => s,
            None => return self.make_error_response(msg_id, -1, "Invalid method"),
        };

        // Read params array and populate global buffer
        let param_count = self.extract_params(unpacker);

        // Find and call handler
        if let Some(handler) = self.find_handler(method) {
            match handler(param_count) {
                RpcResult::Int(i) => self.make_response(msg_id, &MsgPackValue::Int(i)),
                RpcResult::Bool(b) => self.make_response(msg_id, &MsgPackValue::Bool(b)),
                RpcResult::Str(s) => self.make_response(msg_id, &MsgPackValue::Str(s)),
                RpcResult::Nil => self.make_response(msg_id, &MsgPackValue::Nil),
                RpcResult::Error(code, msg) => self.make_error_response(msg_id, code, msg),
            }
        } else {
            self.make_error_response(msg_id, -3, "Method not found")
        }
    }

    /// Extract parameters from unpacker into global PARAMS buffer
    fn extract_params(&mut self, unpacker: &mut MsgPackUnpacker) -> usize {
        unsafe {
            PARAMS.clear();
        }

        let arr_len = match unpacker.unpack_array_header() {
            Some(len) => len.min(MAX_PARAMS),
            None => return 0,
        };

        for i in 0..arr_len {
            match unpacker.unpack() {
                Some(MsgPackValue::Int(v)) => unsafe {
                    PARAMS.ints[i] = v;
                    PARAMS.count = i + 1;
                },
                Some(MsgPackValue::UInt(v)) => unsafe {
                    PARAMS.ints[i] = v as i64;
                    PARAMS.count = i + 1;
                },
                Some(MsgPackValue::Bool(v)) => unsafe {
                    PARAMS.bools[i] = v;
                    PARAMS.ints[i] = if v { 1 } else { 0 };
                    PARAMS.count = i + 1;
                },
                _ => break,
            }
        }

        unsafe { PARAMS.count }
    }

    /// Handle an RPC notification (fire-and-forget)
    fn handle_notification(&mut self, unpacker: &mut MsgPackUnpacker) {
        // Read method name
        let method = match unpacker.unpack_str() {
            Some(s) => s,
            None => return,
        };

        // Extract params
        let param_count = self.extract_params(unpacker);

        // Call handler (ignore result for notifications)
        if let Some(handler) = self.find_handler(method) {
            let _ = handler(param_count);
        }
    }

    /// Create a success response
    fn make_response(&mut self, msg_id: u32, result: &MsgPackValue) -> Option<&[u8]> {
        let mut packer = MsgPackPacker::new();

        // [1, msgid, nil, result]
        packer.pack_array_header(4);
        packer.pack_int(RpcMessageType::Response as i64);
        packer.pack_uint(msg_id as u64);
        packer.pack_nil(); // No error
        packer.pack_value(result);

        let bytes = packer.as_bytes();
        let len = bytes.len().min(self.response_buffer.len());
        self.response_buffer[..len].copy_from_slice(&bytes[..len]);

        Some(&self.response_buffer[..len])
    }

    /// Create an error response
    fn make_error_response(&mut self, msg_id: u32, code: i32, message: &str) -> Option<&[u8]> {
        let mut packer = MsgPackPacker::new();

        // Use pack_rpc_response helper for proper error format
        packer.pack_rpc_response(msg_id, Some((code, message)), None);

        let bytes = packer.as_bytes();
        let len = bytes.len().min(self.response_buffer.len());
        self.response_buffer[..len].copy_from_slice(&bytes[..len]);

        Some(&self.response_buffer[..len])
    }
}

impl Default for RpcServer {
    fn default() -> Self {
        Self::new()
    }
}
