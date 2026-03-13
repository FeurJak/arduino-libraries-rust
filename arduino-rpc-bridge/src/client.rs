// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Client for making calls to the Linux MPU

use crate::decoder::{RpcDecoder, RpcResponse};
use crate::error::{RpcError, RpcErrorCode};
use crate::msgpack::{MsgPackPacker, MsgPackUnpacker, MsgPackValue};
use crate::transport::Transport;

/// Maximum wait iterations for blocking calls
const MAX_WAIT_ITERATIONS: u32 = 100000;

/// RPC Client for calling methods on the Linux MPU
pub struct RpcClient {
    /// Message ID counter
    next_msg_id: u32,
    /// Last error from an RPC call
    pub last_error: RpcError,
}

impl RpcClient {
    pub const fn new() -> Self {
        Self {
            next_msg_id: 1,
            last_error: RpcError::none(),
        }
    }

    /// Get the next message ID
    fn next_id(&mut self) -> u32 {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        if self.next_msg_id == 0 {
            self.next_msg_id = 1;
        }
        id
    }

    /// Send an RPC notification (fire-and-forget, no response expected)
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to send over
    /// * `method` - The method name to call
    /// * `params` - Array of parameters
    ///
    /// # Returns
    ///
    /// `true` if the message was sent successfully
    pub fn notify<T: Transport>(
        &mut self,
        transport: &mut T,
        method: &str,
        params: &[MsgPackValue],
    ) -> bool {
        let mut packer = MsgPackPacker::new();

        if !packer.pack_rpc_notify(method, params) {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Pack failed");
            return false;
        }

        let bytes = packer.as_bytes();
        let written = transport.write(bytes);
        transport.flush();

        written == bytes.len()
    }

    /// Send an RPC call and return immediately (non-blocking)
    ///
    /// Use `get_response` to retrieve the response later.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to send over
    /// * `method` - The method name to call
    /// * `params` - Array of parameters
    ///
    /// # Returns
    ///
    /// The message ID to use with `get_response`, or 0 on error
    pub fn send_call<T: Transport>(
        &mut self,
        transport: &mut T,
        method: &str,
        params: &[MsgPackValue],
    ) -> u32 {
        let msg_id = self.next_id();
        let mut packer = MsgPackPacker::new();

        if !packer.pack_rpc_request(msg_id, method, params) {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Pack failed");
            return 0;
        }

        let bytes = packer.as_bytes();
        let written = transport.write(bytes);
        transport.flush();

        if written == bytes.len() {
            msg_id
        } else {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Write failed");
            0
        }
    }

    /// Wait for and get a response for a specific message ID
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to read from
    /// * `decoder` - The RPC decoder
    /// * `msg_id` - The message ID to wait for
    /// * `max_wait_ms` - Maximum time to wait in milliseconds (0 = check once)
    ///
    /// # Returns
    ///
    /// The response if received, None on timeout
    pub fn get_response<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        msg_id: u32,
        max_wait_ms: u32,
    ) -> Option<RpcResponse> {
        // First check if already received
        if let Some(resp) = decoder.get_response(msg_id) {
            return Some(resp);
        }

        // Wait for response
        let iterations = if max_wait_ms == 0 {
            1
        } else {
            max_wait_ms * 10
        };

        for _ in 0..iterations.min(MAX_WAIT_ITERATIONS) {
            // Process incoming data
            decoder.decode(transport);

            // Check for our response
            if let Some(resp) = decoder.get_response(msg_id) {
                return Some(resp);
            }

            // Small delay (yielding) would go here in actual implementation
            // For now, just continue checking
        }

        None
    }

    /// Make a blocking RPC call
    ///
    /// Sends the request and waits for the response.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to use
    /// * `decoder` - The RPC decoder
    /// * `method` - The method name to call
    /// * `params` - Array of parameters
    /// * `timeout_ms` - Maximum time to wait for response
    ///
    /// # Returns
    ///
    /// The response if successful, None on error/timeout
    pub fn call<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<RpcResponse> {
        let msg_id = self.send_call(transport, method, params);
        if msg_id == 0 {
            return None;
        }

        self.get_response(transport, decoder, msg_id, timeout_ms)
    }

    /// Make a blocking RPC call and extract a simple result
    ///
    /// Convenience method for calls that return a single value.
    pub fn call_get_int<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<i64> {
        let response = self.call(transport, decoder, method, params, timeout_ms)?;

        if response.error.is_error() {
            self.last_error = response.error;
            return None;
        }

        // Parse result
        let mut unpacker = MsgPackUnpacker::new(&response.result_data[..response.result_len]);
        match unpacker.unpack()? {
            MsgPackValue::Int(i) => Some(i),
            MsgPackValue::UInt(u) => Some(u as i64),
            _ => None,
        }
    }

    /// Make a blocking RPC call and extract a boolean result
    pub fn call_get_bool<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<bool> {
        let response = self.call(transport, decoder, method, params, timeout_ms)?;

        if response.error.is_error() {
            self.last_error = response.error;
            return None;
        }

        let mut unpacker = MsgPackUnpacker::new(&response.result_data[..response.result_len]);
        match unpacker.unpack()? {
            MsgPackValue::Bool(b) => Some(b),
            MsgPackValue::Nil => Some(false),
            _ => None,
        }
    }
}

impl Default for RpcClient {
    fn default() -> Self {
        Self::new()
    }
}
