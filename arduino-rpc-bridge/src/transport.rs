// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Transport trait for RPC communication

/// Transport interface for sending/receiving bytes
///
/// This trait abstracts the underlying communication channel (UART, etc.)
/// and allows the RPC system to be transport-agnostic.
pub trait Transport {
    /// Write data to the transport
    ///
    /// Returns the number of bytes written
    fn write(&mut self, data: &[u8]) -> usize;

    /// Read data from the transport into buffer
    ///
    /// Returns the number of bytes read
    fn read(&mut self, buffer: &mut [u8]) -> usize;

    /// Read a single byte
    ///
    /// Returns Some(byte) if available, None otherwise
    fn read_byte(&mut self) -> Option<u8>;

    /// Check if data is available to read
    fn available(&self) -> bool;

    /// Flush any buffered output
    fn flush(&mut self) {}
}

/// FFI functions for Zephyr UART access
/// These are implemented in C and called from Rust
pub mod ffi {
    extern "C" {
        /// Initialize UART for RPC (Serial1 on Arduino Uno Q)
        pub fn rpc_uart_init(baud_rate: u32) -> i32;

        /// Write bytes to UART
        pub fn rpc_uart_write(data: *const u8, len: usize) -> usize;

        /// Read bytes from UART (non-blocking)
        pub fn rpc_uart_read(buffer: *mut u8, max_len: usize) -> usize;

        /// Check if data is available
        pub fn rpc_uart_available() -> i32;

        /// Flush UART TX buffer
        pub fn rpc_uart_flush();
    }
}

/// UART-based transport for Arduino Uno Q
///
/// Uses Serial1 (LPUART1) to communicate with the Linux MPU via the
/// arduino-router service.
pub struct UartTransport {
    initialized: bool,
}

impl UartTransport {
    /// Create a new UART transport (uninitialized)
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the UART with the specified baud rate
    ///
    /// Returns true on success
    pub fn init(&mut self, baud_rate: u32) -> bool {
        let result = unsafe { ffi::rpc_uart_init(baud_rate) };
        self.initialized = result == 0;
        self.initialized
    }

    /// Check if the transport is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for UartTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UartTransport {
    fn write(&mut self, data: &[u8]) -> usize {
        if !self.initialized || data.is_empty() {
            return 0;
        }
        unsafe { ffi::rpc_uart_write(data.as_ptr(), data.len()) }
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        if !self.initialized || buffer.is_empty() {
            return 0;
        }
        unsafe { ffi::rpc_uart_read(buffer.as_mut_ptr(), buffer.len()) }
    }

    fn read_byte(&mut self) -> Option<u8> {
        if !self.initialized {
            return None;
        }
        let mut byte = 0u8;
        let read = unsafe { ffi::rpc_uart_read(&mut byte as *mut u8, 1) };
        if read == 1 {
            Some(byte)
        } else {
            None
        }
    }

    fn available(&self) -> bool {
        if !self.initialized {
            return false;
        }
        unsafe { ffi::rpc_uart_available() > 0 }
    }

    fn flush(&mut self) {
        if self.initialized {
            unsafe { ffi::rpc_uart_flush() };
        }
    }
}

/// Mock transport for testing (stores data in buffers)
#[cfg(test)]
pub struct MockTransport {
    pub tx_buffer: [u8; 1024],
    pub tx_len: usize,
    pub rx_buffer: [u8; 1024],
    pub rx_pos: usize,
    pub rx_len: usize,
}

#[cfg(test)]
impl MockTransport {
    pub fn new() -> Self {
        Self {
            tx_buffer: [0; 1024],
            tx_len: 0,
            rx_buffer: [0; 1024],
            rx_pos: 0,
            rx_len: 0,
        }
    }

    pub fn set_rx_data(&mut self, data: &[u8]) {
        self.rx_buffer[..data.len()].copy_from_slice(data);
        self.rx_len = data.len();
        self.rx_pos = 0;
    }

    pub fn get_tx_data(&self) -> &[u8] {
        &self.tx_buffer[..self.tx_len]
    }
}

#[cfg(test)]
impl Transport for MockTransport {
    fn write(&mut self, data: &[u8]) -> usize {
        let space = self.tx_buffer.len() - self.tx_len;
        let to_write = data.len().min(space);
        self.tx_buffer[self.tx_len..self.tx_len + to_write].copy_from_slice(&data[..to_write]);
        self.tx_len += to_write;
        to_write
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        let available = self.rx_len - self.rx_pos;
        let to_read = buffer.len().min(available);
        buffer[..to_read].copy_from_slice(&self.rx_buffer[self.rx_pos..self.rx_pos + to_read]);
        self.rx_pos += to_read;
        to_read
    }

    fn read_byte(&mut self) -> Option<u8> {
        if self.rx_pos < self.rx_len {
            let byte = self.rx_buffer[self.rx_pos];
            self.rx_pos += 1;
            Some(byte)
        } else {
            None
        }
    }

    fn available(&self) -> bool {
        self.rx_pos < self.rx_len
    }
}
