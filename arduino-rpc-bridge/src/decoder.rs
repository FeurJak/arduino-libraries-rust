// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Decoder for parsing incoming MessagePack-RPC messages

use crate::error::{RpcError, RpcErrorCode};
use crate::msgpack::{MsgPackUnpacker, MsgPackValue, StrBuf};
use crate::transport::Transport;
use crate::{RpcMessageType, DECODER_BUFFER_SIZE, MIN_RPC_BYTES};

/// Parsed RPC response
#[derive(Debug)]
pub struct RpcResponse {
    /// Message ID this response is for
    pub msg_id: u32,
    /// Error (if any)
    pub error: RpcError,
    /// Result value (if no error) - stored as raw bytes for later parsing
    pub result_data: [u8; 256],
    pub result_len: usize,
}

impl RpcResponse {
    pub fn new() -> Self {
        Self {
            msg_id: 0,
            error: RpcError::none(),
            result_data: [0u8; 256],
            result_len: 0,
        }
    }
}

impl Default for RpcResponse {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed RPC request (incoming call from router)
#[derive(Debug)]
pub struct RpcRequest {
    /// Message ID
    pub msg_id: u32,
    /// Method name
    pub method: StrBuf,
    /// Parameters data (raw MessagePack)
    pub params_data: [u8; 256],
    pub params_len: usize,
    /// Whether this is a notification (no response needed)
    pub is_notify: bool,
}

impl RpcRequest {
    pub fn new() -> Self {
        Self {
            msg_id: 0,
            method: StrBuf::new(),
            params_data: [0u8; 256],
            params_len: 0,
            is_notify: false,
        }
    }
}

impl Default for RpcRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// RPC Decoder state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    /// Waiting for data
    Idle,
    /// Receiving packet data
    Receiving,
    /// Packet complete, ready to process
    PacketReady,
}

/// RPC Decoder for parsing MessagePack-RPC messages from the transport
pub struct RpcDecoder {
    /// Receive buffer
    buffer: [u8; DECODER_BUFFER_SIZE],
    /// Current position in buffer
    pos: usize,
    /// Current state
    state: DecoderState,
    /// Detected packet type
    packet_type: Option<RpcMessageType>,
    /// Expected packet size (if known)
    expected_size: usize,
    /// Number of discarded packets (parse errors)
    discarded_packets: u32,
    /// Pending responses (simple queue - holds up to 4)
    pending_responses: [Option<RpcResponse>; 4],
    /// Pending requests (simple queue - holds up to 4)
    pending_requests: [Option<RpcRequest>; 4],
}

impl RpcDecoder {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; DECODER_BUFFER_SIZE],
            pos: 0,
            state: DecoderState::Idle,
            packet_type: None,
            expected_size: 0,
            discarded_packets: 0,
            pending_responses: [None, None, None, None],
            pending_requests: [None, None, None, None],
        }
    }

    /// Reset the decoder state
    pub fn reset(&mut self) {
        self.pos = 0;
        self.state = DecoderState::Idle;
        self.packet_type = None;
        self.expected_size = 0;
    }

    /// Get number of discarded packets
    pub fn discarded_packets(&self) -> u32 {
        self.discarded_packets
    }

    /// Check if a response is waiting for the given message ID
    pub fn has_response(&self, msg_id: u32) -> bool {
        self.pending_responses
            .iter()
            .any(|r| r.as_ref().map_or(false, |resp| resp.msg_id == msg_id))
    }

    /// Get a response for the given message ID
    pub fn get_response(&mut self, msg_id: u32) -> Option<RpcResponse> {
        for slot in self.pending_responses.iter_mut() {
            if slot.as_ref().map_or(false, |r| r.msg_id == msg_id) {
                return slot.take();
            }
        }
        None
    }

    /// Check if any request is pending
    pub fn has_request(&self) -> bool {
        self.pending_requests.iter().any(|r| r.is_some())
    }

    /// Get the next pending request
    pub fn get_request(&mut self) -> Option<RpcRequest> {
        for slot in self.pending_requests.iter_mut() {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// Process incoming data from transport
    ///
    /// Call this repeatedly to process incoming RPC messages.
    /// Parsed responses and requests are queued internally.
    pub fn decode<T: Transport>(&mut self, transport: &mut T) {
        // Read available data
        while transport.available() && self.pos < DECODER_BUFFER_SIZE {
            if let Some(byte) = transport.read_byte() {
                self.buffer[self.pos] = byte;
                self.pos += 1;
            } else {
                break;
            }
        }

        // Try to parse complete messages
        self.try_parse();
    }

    /// Try to parse buffered data as RPC messages
    fn try_parse(&mut self) {
        if self.pos < MIN_RPC_BYTES {
            return;
        }

        // Copy buffer data to avoid borrow issues
        let mut temp_buf = [0u8; DECODER_BUFFER_SIZE];
        temp_buf[..self.pos].copy_from_slice(&self.buffer[..self.pos]);
        let buf_len = self.pos;

        // Try to parse as MessagePack array
        let mut unpacker = MsgPackUnpacker::new(&temp_buf[..buf_len]);

        // Get array header
        let array_len = match unpacker.unpack_array_header() {
            Some(len) => len,
            None => {
                // Not a valid array - discard first byte and retry
                self.discard_byte();
                return;
            }
        };

        // First element should be message type
        let msg_type = match unpacker.unpack_uint() {
            Some(t) if t <= 2 => RpcMessageType::try_from(t as u8).ok(),
            _ => {
                self.discard_byte();
                return;
            }
        };

        // Validate array size for message type
        let expected_size = match msg_type {
            Some(RpcMessageType::Call) | Some(RpcMessageType::Response) => 4,
            Some(RpcMessageType::Notify) => 3,
            None => {
                self.discard_byte();
                return;
            }
        };

        if array_len != expected_size {
            self.discard_byte();
            return;
        }

        // Parse based on message type - pass temp_buf for result extraction
        match msg_type {
            Some(RpcMessageType::Response) => {
                self.parse_response_from_buf(&temp_buf[..buf_len], &mut unpacker);
            }
            Some(RpcMessageType::Call) => {
                self.parse_request_from_buf(&temp_buf[..buf_len], &mut unpacker, false);
            }
            Some(RpcMessageType::Notify) => {
                self.parse_request_from_buf(&temp_buf[..buf_len], &mut unpacker, true);
            }
            None => {
                self.discard_byte();
            }
        }
    }

    /// Parse an RPC response message from temporary buffer
    fn parse_response_from_buf(&mut self, buf: &[u8], unpacker: &mut MsgPackUnpacker) {
        // [type=1, msgid, error, result]
        // type already consumed

        let msg_id = match unpacker.unpack_uint() {
            Some(id) => id as u32,
            None => {
                self.discard_byte();
                return;
            }
        };

        // Parse error (nil or array [code, message])
        let error = match unpacker.unpack() {
            Some(MsgPackValue::Nil) => RpcError::none(),
            Some(MsgPackValue::ArrayHeader(len)) if len >= 2 => {
                // Read error code
                let code = match unpacker.unpack() {
                    Some(MsgPackValue::Int(i)) => i as u8,
                    Some(MsgPackValue::UInt(u)) => u as u8,
                    _ => 0xFF,
                };

                // Read error message
                let msg = match unpacker.unpack() {
                    Some(MsgPackValue::Str(s)) => {
                        StrBuf::from_bytes(s.as_bytes()).unwrap_or_default()
                    }
                    _ => StrBuf::new(),
                };

                // Skip remaining array elements if any
                for _ in 2..len {
                    unpacker.unpack();
                }

                RpcError {
                    code: RpcErrorCode::from(code),
                    message: msg,
                }
            }
            _ => {
                self.discard_byte();
                return;
            }
        };

        // Store result position for later extraction
        let result_start = unpacker.position();

        // Skip the result value to get end position
        if unpacker.unpack().is_none() {
            self.discard_byte();
            return;
        }

        let result_end = unpacker.position();

        // Create response
        let mut response = RpcResponse::new();
        response.msg_id = msg_id;
        response.error = error;

        let result_len = (result_end - result_start).min(response.result_data.len());
        response.result_data[..result_len]
            .copy_from_slice(&buf[result_start..result_start + result_len]);
        response.result_len = result_len;

        // Queue the response
        self.queue_response(response);

        // Remove parsed data from buffer
        let consumed = unpacker.position();
        self.consume_buffer(consumed);
    }

    /// Parse an RPC request/notification message from temporary buffer
    fn parse_request_from_buf(
        &mut self,
        buf: &[u8],
        unpacker: &mut MsgPackUnpacker,
        is_notify: bool,
    ) {
        // Call: [type=0, msgid, method, params]
        // Notify: [type=2, method, params]

        let msg_id = if !is_notify {
            match unpacker.unpack_uint() {
                Some(id) => id as u32,
                None => {
                    self.discard_byte();
                    return;
                }
            }
        } else {
            0
        };

        // Get method name
        let method = match unpacker.unpack_str() {
            Some(s) => match StrBuf::from_bytes(s.as_bytes()) {
                Some(buf) => buf,
                None => {
                    self.discard_byte();
                    return;
                }
            },
            None => {
                self.discard_byte();
                return;
            }
        };

        // Store params position
        let params_start = unpacker.position();

        // Skip params array - first get the header
        match unpacker.unpack() {
            Some(MsgPackValue::ArrayHeader(len)) => {
                // Skip all array elements
                for _ in 0..len {
                    if unpacker.unpack().is_none() {
                        self.discard_byte();
                        return;
                    }
                }
            }
            None => {
                self.discard_byte();
                return;
            }
            _ => {
                // Not an array - that's OK, could be nil or other value
            }
        }

        let params_end = unpacker.position();

        // Create request
        let mut request = RpcRequest::new();
        request.msg_id = msg_id;
        request.method = method;
        request.is_notify = is_notify;

        let params_len = (params_end - params_start).min(request.params_data.len());
        request.params_data[..params_len]
            .copy_from_slice(&buf[params_start..params_start + params_len]);
        request.params_len = params_len;

        // Queue the request
        self.queue_request(request);

        // Remove parsed data from buffer
        let consumed = unpacker.position();
        self.consume_buffer(consumed);
    }

    /// Queue a response
    fn queue_response(&mut self, response: RpcResponse) {
        for slot in self.pending_responses.iter_mut() {
            if slot.is_none() {
                *slot = Some(response);
                return;
            }
        }
        // Queue full - discard oldest
        self.pending_responses[0] = Some(response);
        self.discarded_packets += 1;
    }

    /// Queue a request
    fn queue_request(&mut self, request: RpcRequest) {
        for slot in self.pending_requests.iter_mut() {
            if slot.is_none() {
                *slot = Some(request);
                return;
            }
        }
        // Queue full - discard oldest
        self.pending_requests[0] = Some(request);
        self.discarded_packets += 1;
    }

    /// Discard the first byte (invalid data)
    fn discard_byte(&mut self) {
        if self.pos > 0 {
            // Shift buffer left by 1
            for i in 0..self.pos - 1 {
                self.buffer[i] = self.buffer[i + 1];
            }
            self.pos -= 1;
            self.discarded_packets += 1;
        }
    }

    /// Remove consumed bytes from buffer
    fn consume_buffer(&mut self, count: usize) {
        if count >= self.pos {
            self.pos = 0;
        } else {
            // Shift remaining data to start
            for i in 0..self.pos - count {
                self.buffer[i] = self.buffer[i + count];
            }
            self.pos -= count;
        }
    }
}

impl Default for RpcDecoder {
    fn default() -> Self {
        Self::new()
    }
}
