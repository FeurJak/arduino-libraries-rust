// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// High-level Bridge API for Arduino Uno Q RPC communication

use crate::client::RpcClient;
use crate::decoder::RpcDecoder;
use crate::error::RpcError;
use crate::msgpack::{MsgPackPacker, MsgPackValue};
use crate::transport::{Transport, UartTransport};
use crate::DEFAULT_BAUD_RATE;

/// High-level RPC Bridge for Arduino Uno Q
///
/// This struct provides a convenient interface for RPC communication
/// between the STM32U585 MCU and the QRB2210 Linux MPU.
///
/// # Example
///
/// ```no_run
/// use arduino_rpc_bridge::{Bridge, MsgPackValue};
///
/// let mut bridge = Bridge::new();
///
/// // Initialize communication
/// if bridge.begin() {
///     // Make an RPC call
///     let result = bridge.call_int("multiply", &[
///         MsgPackValue::Int(5),
///         MsgPackValue::Int(7),
///     ]);
///     
///     // Send a notification
///     bridge.notify("log", &[MsgPackValue::Str("Hello!")]);
/// }
/// ```
pub struct Bridge {
    transport: UartTransport,
    decoder: RpcDecoder,
    client: RpcClient,
    started: bool,
    router_version: [u8; 32],
    router_version_len: usize,
}

impl Bridge {
    /// Create a new Bridge instance
    pub const fn new() -> Self {
        Self {
            transport: UartTransport::new(),
            decoder: RpcDecoder::new(),
            client: RpcClient::new(),
            started: false,
            router_version: [0u8; 32],
            router_version_len: 0,
        }
    }

    /// Initialize the bridge with default baud rate (115200)
    ///
    /// This:
    /// 1. Opens Serial1 (LPUART1) at the specified baud rate
    /// 2. Sends an initialization message
    /// 3. Calls $/reset to clear router state
    ///
    /// Returns `true` if initialization was successful
    pub fn begin(&mut self) -> bool {
        self.begin_with_baud(DEFAULT_BAUD_RATE)
    }

    /// Initialize the bridge with a custom baud rate
    pub fn begin_with_baud(&mut self, baud_rate: u32) -> bool {
        if self.started {
            return true;
        }

        // Initialize UART
        if !self.transport.init(baud_rate) {
            return false;
        }

        // Note: We don't send a text init message here as it would confuse the router
        // which expects MessagePack-RPC frames only

        // Reset router state
        if !self.call_void("$/reset", &[]) {
            // Reset failed, but we might still be able to communicate
        }

        // Try to get router version
        self.get_router_version_internal();

        self.started = true;
        true
    }

    /// Check if the bridge is initialized and ready
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Get the router version string (if available)
    pub fn router_version(&self) -> Option<&str> {
        if self.router_version_len > 0 {
            core::str::from_utf8(&self.router_version[..self.router_version_len]).ok()
        } else {
            None
        }
    }

    /// Process incoming RPC messages
    ///
    /// Call this periodically to handle incoming requests and responses.
    pub fn update(&mut self) {
        self.decoder.decode(&mut self.transport);
    }

    /// Send an RPC notification (fire-and-forget)
    ///
    /// The notification is sent but no response is expected.
    ///
    /// # Arguments
    ///
    /// * `method` - The method name
    /// * `params` - Array of parameters
    ///
    /// # Returns
    ///
    /// `true` if the notification was sent successfully
    pub fn notify(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        if !self.started {
            return false;
        }
        self.client.notify(&mut self.transport, method, params)
    }

    /// Make a blocking RPC call (with default timeout)
    ///
    /// # Arguments
    ///
    /// * `method` - The method name
    /// * `params` - Array of parameters
    ///
    /// # Returns
    ///
    /// `true` if the call succeeded (check `last_error` for details)
    pub fn call_void(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        self.call_void_timeout(method, params, 5000)
    }

    /// Make a blocking RPC call with custom timeout
    pub fn call_void_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> bool {
        if !self.started && method != "$/reset" {
            return false;
        }

        let response = self.client.call(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        );

        match response {
            Some(r) => !r.error.is_error(),
            None => false,
        }
    }

    /// Make an RPC call that returns an integer
    pub fn call_int(&mut self, method: &str, params: &[MsgPackValue]) -> Option<i64> {
        self.call_int_timeout(method, params, 5000)
    }

    /// Make an RPC call that returns an integer with custom timeout
    pub fn call_int_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<i64> {
        if !self.started {
            return None;
        }
        self.client.call_get_int(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        )
    }

    /// Make an RPC call that returns a boolean
    pub fn call_bool(&mut self, method: &str, params: &[MsgPackValue]) -> Option<bool> {
        self.call_bool_timeout(method, params, 5000)
    }

    /// Make an RPC call that returns a boolean with custom timeout
    pub fn call_bool_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<bool> {
        if !self.started {
            return None;
        }
        self.client.call_get_bool(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        )
    }

    /// Get the last error from an RPC call
    pub fn last_error(&self) -> &RpcError {
        &self.client.last_error
    }

    /// Get the number of discarded packets (parse errors)
    pub fn discarded_packets(&self) -> u32 {
        self.decoder.discarded_packets()
    }

    /// Internal: Get router version
    fn get_router_version_internal(&mut self) {
        let response = self.client.call(
            &mut self.transport,
            &mut self.decoder,
            "$/version",
            &[],
            1000,
        );

        if let Some(r) = response {
            if !r.error.is_error() && r.result_len > 0 {
                // Parse string result
                use crate::msgpack::MsgPackUnpacker;
                let mut unpacker = MsgPackUnpacker::new(&r.result_data[..r.result_len]);
                if let Some(MsgPackValue::Str(s)) = unpacker.unpack() {
                    let bytes = s.as_bytes();
                    let len = bytes.len().min(self.router_version.len());
                    self.router_version[..len].copy_from_slice(&bytes[..len]);
                    self.router_version_len = len;
                }
            }
        }
    }

    /// Register a method name with the router
    ///
    /// This tells the router that this client provides the specified method.
    /// When another client calls this method, the router will forward it here.
    ///
    /// # Arguments
    ///
    /// * `method` - The method name to register
    ///
    /// # Returns
    ///
    /// `true` if registration was successful
    pub fn register_method(&mut self, method: &str) -> bool {
        self.call_bool("$/register", &[MsgPackValue::Str(method)])
            .unwrap_or(false)
    }

    /// Check if there's an incoming RPC request to process
    pub fn has_incoming_request(&self) -> bool {
        self.decoder.has_request()
    }

    /// Get the next incoming RPC request (if any)
    ///
    /// Returns the method name and message ID. Use `get_request_params`
    /// to get the parameters.
    pub fn get_incoming_request(&mut self) -> Option<crate::decoder::RpcRequest> {
        self.decoder.get_request()
    }

    /// Send a response to an incoming request
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The message ID from the request
    /// * `result` - The result value to send
    pub fn send_response(&mut self, msg_id: u32, result: &MsgPackValue) -> bool {
        let mut packer = MsgPackPacker::new();
        if !packer.pack_rpc_response(msg_id, None, Some(result)) {
            return false;
        }

        let bytes = packer.as_bytes();
        let written = self.transport.write(bytes);
        self.transport.flush();

        written == bytes.len()
    }

    /// Send an error response to an incoming request
    ///
    /// # Arguments
    ///
    /// * `msg_id` - The message ID from the request
    /// * `error_code` - The error code
    /// * `error_msg` - The error message
    pub fn send_error_response(&mut self, msg_id: u32, error_code: i32, error_msg: &str) -> bool {
        let mut packer = MsgPackPacker::new();
        if !packer.pack_rpc_response(msg_id, Some((error_code, error_msg)), None) {
            return false;
        }

        let bytes = packer.as_bytes();
        let written = self.transport.write(bytes);
        self.transport.flush();

        written == bytes.len()
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience type aliases
pub type RpcValue<'a> = MsgPackValue<'a>;
