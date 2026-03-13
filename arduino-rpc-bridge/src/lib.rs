// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Arduino RPC Bridge Library for Rust
//
// A Rust implementation of the Arduino RouterBridge RPC system for
// communication between the STM32U585 MCU and QRB2210 Linux MPU
// on the Arduino Uno Q board.
//
// The RPC system uses MessagePack-RPC protocol over UART to enable
// bidirectional procedure calls between the microcontroller and Linux.
//
// # Architecture
//
// ```text
// ┌─────────────────────┐         ┌─────────────────────┐
// │   STM32U585 MCU     │         │  QRB2210 Linux MPU  │
// │   (Zephyr RTOS)     │         │   (arduino-router)  │
// │                     │  UART   │                     │
// │  ┌───────────────┐  │◄───────►│  ┌───────────────┐  │
// │  │ Rust App      │  │ Serial1 │  │ Go Router     │  │
// │  │ + RpcBridge   │  │ 115200  │  │               │  │
// │  └───────────────┘  │         │  └───────────────┘  │
// └─────────────────────┘         └─────────────────────┘
// ```
//
// # Example
//
// ```no_run
// use arduino_rpc_bridge::{Bridge, RpcValue};
//
// // Initialize the bridge
// let mut bridge = Bridge::new();
// bridge.begin();
//
// // Call a method on the Linux side
// let result: i32 = bridge.call("multiply", &[RpcValue::Int(5), RpcValue::Int(7)]);
//
// // Send a notification (fire-and-forget)
// bridge.notify("log_message", &[RpcValue::Str("Hello from MCU!")]);
// ```

#![no_std]

mod bridge;
mod client;
mod decoder;
mod error;
mod msgpack;
mod server;
mod spi_transport;
mod transport;

pub use bridge::Bridge;
pub use client::RpcClient;
pub use decoder::RpcDecoder;
pub use error::{RpcError, RpcErrorCode};
pub use msgpack::{MsgPackPacker, MsgPackUnpacker, MsgPackValue};
pub use server::{RpcHandler, RpcResult, RpcServer, MAX_HANDLERS, MAX_PARAMS, PARAMS};
pub use spi_transport::SpiTransport;
pub use transport::{Transport, UartTransport};

/// RPC message types as defined in MessagePack-RPC spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcMessageType {
    /// Request: [type=0, msgid, method, params]
    Call = 0,
    /// Response: [type=1, msgid, error, result]
    Response = 1,
    /// Notification: [type=2, method, params]
    Notify = 2,
}

impl TryFrom<u8> for RpcMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RpcMessageType::Call),
            1 => Ok(RpcMessageType::Response),
            2 => Ok(RpcMessageType::Notify),
            _ => Err(()),
        }
    }
}

/// Default serial baud rate
pub const DEFAULT_BAUD_RATE: u32 = 115200;

/// Default decoder buffer size
pub const DECODER_BUFFER_SIZE: usize = 1024;

/// Default RPC buffer size
pub const DEFAULT_RPC_BUFFER_SIZE: usize = 256;

/// Minimum valid RPC message size
pub const MIN_RPC_BYTES: usize = 4;

/// Maximum method name length
pub const MAX_METHOD_NAME_LEN: usize = 64;

/// Maximum string value length
pub const MAX_STRING_LEN: usize = 256;
