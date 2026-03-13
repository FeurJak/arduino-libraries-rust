// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// SPI Transport for RPC communication
//
// This module provides SPI-based transport for communication between
// the STM32U585 MCU (peripheral/slave) and QRB2210 Linux MPU (controller/master).

use crate::transport::Transport;

/// Frame protocol constants
pub const FRAME_MAGIC: u16 = 0xAA55;
pub const FRAME_HEADER_SIZE: usize = 4;
pub const SPI_BUFFER_SIZE: usize = 512;
pub const MAX_PAYLOAD_SIZE: usize = SPI_BUFFER_SIZE - FRAME_HEADER_SIZE;

/// FFI functions for Zephyr SPI peripheral access
pub mod ffi {
    extern "C" {
        /// Initialize SPI peripheral
        pub fn spi_peripheral_init() -> i32;

        /// Populate TX buffer with data to send
        pub fn spi_peripheral_populate(data: *const u8, len: usize) -> usize;

        /// Wait for and perform SPI transaction (blocking)
        pub fn spi_peripheral_transceive() -> i32;

        /// Get pointer to received payload (after magic/length check)
        pub fn spi_peripheral_get_rx_payload(len: *mut usize) -> *const u8;

        /// Get maximum payload size
        pub fn spi_peripheral_max_payload() -> usize;
    }
}

/// SPI-based transport for Arduino Uno Q MCU
///
/// Uses SPI3 in peripheral (slave) mode to communicate with the Linux MPU.
/// The MCU prepares data in its TX buffer, then waits for the Linux controller
/// to initiate a transfer.
pub struct SpiTransport {
    initialized: bool,
    /// Internal TX buffer for building frames
    tx_buffer: [u8; SPI_BUFFER_SIZE],
    tx_len: usize,
    /// Cached RX data pointer and length
    rx_ptr: *const u8,
    rx_len: usize,
    rx_pos: usize,
}

impl SpiTransport {
    /// Create a new SPI transport (uninitialized)
    pub const fn new() -> Self {
        Self {
            initialized: false,
            tx_buffer: [0; SPI_BUFFER_SIZE],
            tx_len: 0,
            rx_ptr: core::ptr::null(),
            rx_len: 0,
            rx_pos: 0,
        }
    }

    /// Initialize the SPI peripheral
    ///
    /// Returns true on success
    pub fn init(&mut self) -> bool {
        let result = unsafe { ffi::spi_peripheral_init() };
        self.initialized = result == 0;
        self.initialized
    }

    /// Check if the transport is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Prepare data to be sent on next SPI transfer
    ///
    /// Note: The C driver (spi_peripheral_populate) handles frame headers,
    /// so we just pass the raw payload data here.
    /// Returns the number of payload bytes that will be sent.
    pub fn prepare_tx(&mut self, data: &[u8]) -> usize {
        if !self.initialized {
            return 0;
        }

        // For empty data, just populate with zero length
        // The C driver will create an empty frame header
        let payload_len = data.len().min(MAX_PAYLOAD_SIZE);

        if payload_len > 0 {
            // Copy payload to our buffer (no header - C driver adds it)
            self.tx_buffer[..payload_len].copy_from_slice(&data[..payload_len]);
        }

        self.tx_len = payload_len;

        // Populate the SPI driver's TX buffer (C driver adds frame header)
        unsafe {
            ffi::spi_peripheral_populate(self.tx_buffer.as_ptr(), self.tx_len);
        }

        payload_len
    }

    /// Wait for and perform an SPI transaction
    ///
    /// This blocks until the Linux controller initiates a transfer.
    /// Returns the number of bytes received, or 0 on error.
    pub fn transceive(&mut self) -> usize {
        if !self.initialized {
            return 0;
        }

        // Perform the transfer (blocking)
        let result = unsafe { ffi::spi_peripheral_transceive() };
        if result < 0 {
            self.rx_ptr = core::ptr::null();
            self.rx_len = 0;
            self.rx_pos = 0;
            return 0;
        }

        // Get received data
        let mut len: usize = 0;
        self.rx_ptr = unsafe { ffi::spi_peripheral_get_rx_payload(&mut len as *mut usize) };
        self.rx_len = len;
        self.rx_pos = 0;

        len
    }

    /// Get the maximum payload size
    pub fn max_payload() -> usize {
        unsafe { ffi::spi_peripheral_max_payload() }
    }
}

impl Default for SpiTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SpiTransport {
    fn write(&mut self, data: &[u8]) -> usize {
        self.prepare_tx(data)
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        if !self.initialized || self.rx_ptr.is_null() || self.rx_pos >= self.rx_len {
            return 0;
        }

        let available = self.rx_len - self.rx_pos;
        let to_read = buffer.len().min(available);

        if to_read > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.rx_ptr.add(self.rx_pos),
                    buffer.as_mut_ptr(),
                    to_read,
                );
            }
            self.rx_pos += to_read;
        }

        to_read
    }

    fn read_byte(&mut self) -> Option<u8> {
        if !self.initialized || self.rx_ptr.is_null() || self.rx_pos >= self.rx_len {
            return None;
        }

        let byte = unsafe { *self.rx_ptr.add(self.rx_pos) };
        self.rx_pos += 1;
        Some(byte)
    }

    fn available(&self) -> bool {
        self.initialized && !self.rx_ptr.is_null() && self.rx_pos < self.rx_len
    }

    fn flush(&mut self) {
        // SPI transactions are atomic, nothing to flush
    }
}

// Safety: SpiTransport is only used on single-threaded MCU
unsafe impl Send for SpiTransport {}
