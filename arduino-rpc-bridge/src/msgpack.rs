// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// MessagePack encoding/decoding for RPC messages
//
// This module implements a minimal MessagePack encoder/decoder suitable
// for embedded systems. It supports the subset of MessagePack types
// needed for RPC communication.

use crate::MAX_STRING_LEN;

/// MessagePack format markers
mod format {
    // Positive fixint: 0x00 - 0x7f
    pub const POSITIVE_FIXINT_MAX: u8 = 0x7f;

    // Fixmap: 0x80 - 0x8f
    pub const FIXMAP_MIN: u8 = 0x80;
    pub const FIXMAP_MAX: u8 = 0x8f;

    // Fixarray: 0x90 - 0x9f
    pub const FIXARRAY_MIN: u8 = 0x90;
    pub const FIXARRAY_MAX: u8 = 0x9f;

    // Fixstr: 0xa0 - 0xbf
    pub const FIXSTR_MIN: u8 = 0xa0;
    pub const FIXSTR_MAX: u8 = 0xbf;

    // Nil, false, true
    pub const NIL: u8 = 0xc0;
    pub const FALSE: u8 = 0xc2;
    pub const TRUE: u8 = 0xc3;

    // Binary
    pub const BIN8: u8 = 0xc4;
    pub const BIN16: u8 = 0xc5;
    pub const BIN32: u8 = 0xc6;

    // Extension
    pub const EXT8: u8 = 0xc7;
    pub const EXT16: u8 = 0xc8;
    pub const EXT32: u8 = 0xc9;

    // Float
    pub const FLOAT32: u8 = 0xca;
    pub const FLOAT64: u8 = 0xcb;

    // Unsigned integers
    pub const UINT8: u8 = 0xcc;
    pub const UINT16: u8 = 0xcd;
    pub const UINT32: u8 = 0xce;
    pub const UINT64: u8 = 0xcf;

    // Signed integers
    pub const INT8: u8 = 0xd0;
    pub const INT16: u8 = 0xd1;
    pub const INT32: u8 = 0xd2;
    pub const INT64: u8 = 0xd3;

    // Fixed extension
    pub const FIXEXT1: u8 = 0xd4;
    pub const FIXEXT2: u8 = 0xd5;
    pub const FIXEXT4: u8 = 0xd6;
    pub const FIXEXT8: u8 = 0xd7;
    pub const FIXEXT16: u8 = 0xd8;

    // Strings
    pub const STR8: u8 = 0xd9;
    pub const STR16: u8 = 0xda;
    pub const STR32: u8 = 0xdb;

    // Arrays
    pub const ARRAY16: u8 = 0xdc;
    pub const ARRAY32: u8 = 0xdd;

    // Maps
    pub const MAP16: u8 = 0xde;
    pub const MAP32: u8 = 0xdf;

    // Negative fixint: 0xe0 - 0xff
    pub const NEGATIVE_FIXINT_MIN: u8 = 0xe0;
}

/// A MessagePack value that can be sent/received in RPC calls
///
/// Note: Arrays are represented as `ArrayHeader(len)` to avoid recursive types.
/// The caller is responsible for reading/writing individual array elements.
#[derive(Debug, Clone)]
pub enum MsgPackValue<'a> {
    /// Null value
    Nil,
    /// Boolean value
    Bool(bool),
    /// Signed integer (up to 64 bits)
    Int(i64),
    /// Unsigned integer (up to 64 bits)
    UInt(u64),
    /// 32-bit float
    Float32(f32),
    /// 64-bit float
    Float64(f64),
    /// String (borrowed)
    Str(&'a str),
    /// String (owned, for unpacking)
    StrOwned(StrBuf),
    /// Binary data (borrowed)
    Bin(&'a [u8]),
    /// Array header with length (elements must be read separately)
    ArrayHeader(usize),
    /// Map of key-value pairs (not commonly used in RPC)
    Map,
}

/// Fixed-size string buffer for no_std
#[derive(Debug, Clone)]
pub struct StrBuf {
    data: [u8; MAX_STRING_LEN],
    len: usize,
}

impl StrBuf {
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_STRING_LEN],
            len: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_STRING_LEN {
            return None;
        }
        let mut buf = Self::new();
        buf.data[..bytes.len()].copy_from_slice(bytes);
        buf.len = bytes.len();
        Some(buf)
    }

    pub fn as_str(&self) -> &str {
        // Safety: We only store valid UTF-8
        unsafe { core::str::from_utf8_unchecked(&self.data[..self.len]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for StrBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// MessagePack packer for encoding values to bytes
pub struct MsgPackPacker {
    buffer: [u8; 512],
    pos: usize,
}

impl MsgPackPacker {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; 512],
            pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.pos = 0;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.pos]
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    fn write_byte(&mut self, b: u8) -> bool {
        if self.pos < self.buffer.len() {
            self.buffer[self.pos] = b;
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.pos + bytes.len() <= self.buffer.len() {
            self.buffer[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    /// Pack nil value
    pub fn pack_nil(&mut self) -> bool {
        self.write_byte(format::NIL)
    }

    /// Pack boolean value
    pub fn pack_bool(&mut self, value: bool) -> bool {
        self.write_byte(if value { format::TRUE } else { format::FALSE })
    }

    /// Pack unsigned integer (uses smallest encoding)
    pub fn pack_uint(&mut self, value: u64) -> bool {
        if value <= format::POSITIVE_FIXINT_MAX as u64 {
            self.write_byte(value as u8)
        } else if value <= u8::MAX as u64 {
            self.write_byte(format::UINT8) && self.write_byte(value as u8)
        } else if value <= u16::MAX as u64 {
            self.write_byte(format::UINT16) && self.write_bytes(&(value as u16).to_be_bytes())
        } else if value <= u32::MAX as u64 {
            self.write_byte(format::UINT32) && self.write_bytes(&(value as u32).to_be_bytes())
        } else {
            self.write_byte(format::UINT64) && self.write_bytes(&value.to_be_bytes())
        }
    }

    /// Pack signed integer (uses smallest encoding)
    pub fn pack_int(&mut self, value: i64) -> bool {
        if value >= 0 {
            self.pack_uint(value as u64)
        } else if value >= -32 {
            // Negative fixint
            self.write_byte(value as u8)
        } else if value >= i8::MIN as i64 {
            self.write_byte(format::INT8) && self.write_byte(value as u8)
        } else if value >= i16::MIN as i64 {
            self.write_byte(format::INT16) && self.write_bytes(&(value as i16).to_be_bytes())
        } else if value >= i32::MIN as i64 {
            self.write_byte(format::INT32) && self.write_bytes(&(value as i32).to_be_bytes())
        } else {
            self.write_byte(format::INT64) && self.write_bytes(&value.to_be_bytes())
        }
    }

    /// Pack 32-bit float
    pub fn pack_f32(&mut self, value: f32) -> bool {
        self.write_byte(format::FLOAT32) && self.write_bytes(&value.to_be_bytes())
    }

    /// Pack 64-bit float
    pub fn pack_f64(&mut self, value: f64) -> bool {
        self.write_byte(format::FLOAT64) && self.write_bytes(&value.to_be_bytes())
    }

    /// Pack string
    pub fn pack_str(&mut self, s: &str) -> bool {
        let bytes = s.as_bytes();
        let len = bytes.len();

        let header_ok = if len <= 31 {
            self.write_byte(format::FIXSTR_MIN | len as u8)
        } else if len <= u8::MAX as usize {
            self.write_byte(format::STR8) && self.write_byte(len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::STR16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            return false; // Too long
        };

        header_ok && self.write_bytes(bytes)
    }

    /// Pack binary data
    pub fn pack_bin(&mut self, data: &[u8]) -> bool {
        let len = data.len();

        let header_ok = if len <= u8::MAX as usize {
            self.write_byte(format::BIN8) && self.write_byte(len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::BIN16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            return false; // Too long
        };

        header_ok && self.write_bytes(data)
    }

    /// Pack array header (caller must pack N values after this)
    pub fn pack_array_header(&mut self, len: usize) -> bool {
        if len <= 15 {
            self.write_byte(format::FIXARRAY_MIN | len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::ARRAY16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            false
        }
    }

    /// Pack a MsgPackValue
    pub fn pack_value(&mut self, value: &MsgPackValue) -> bool {
        match value {
            MsgPackValue::Nil => self.pack_nil(),
            MsgPackValue::Bool(b) => self.pack_bool(*b),
            MsgPackValue::Int(i) => self.pack_int(*i),
            MsgPackValue::UInt(u) => self.pack_uint(*u),
            MsgPackValue::Float32(f) => self.pack_f32(*f),
            MsgPackValue::Float64(f) => self.pack_f64(*f),
            MsgPackValue::Str(s) => self.pack_str(s),
            MsgPackValue::StrOwned(s) => self.pack_str(s.as_str()),
            MsgPackValue::Bin(b) => self.pack_bin(b),
            MsgPackValue::ArrayHeader(len) => self.pack_array_header(*len),
            MsgPackValue::Map => false, // Not implemented for now
        }
    }

    /// Pack an RPC request: [type=0, msgid, method, params]
    pub fn pack_rpc_request(&mut self, msg_id: u32, method: &str, params: &[MsgPackValue]) -> bool {
        self.pack_array_header(4)
            && self.pack_uint(0) // type = CALL
            && self.pack_uint(msg_id as u64)
            && self.pack_str(method)
            && self.pack_array_header(params.len())
            && params.iter().all(|p| self.pack_value(p))
    }

    /// Pack an RPC notification: [type=2, method, params]
    pub fn pack_rpc_notify(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        self.pack_array_header(3)
            && self.pack_uint(2) // type = NOTIFY
            && self.pack_str(method)
            && self.pack_array_header(params.len())
            && params.iter().all(|p| self.pack_value(p))
    }

    /// Pack an RPC response: [type=1, msgid, error, result]
    pub fn pack_rpc_response(
        &mut self,
        msg_id: u32,
        error: Option<(i32, &str)>,
        result: Option<&MsgPackValue>,
    ) -> bool {
        self.pack_array_header(4)
            && self.pack_uint(1) // type = RESPONSE
            && self.pack_uint(msg_id as u64)
            && match error {
                Some((code, msg)) => {
                    self.pack_array_header(2) && self.pack_int(code as i64) && self.pack_str(msg)
                }
                None => self.pack_nil(),
            }
            && match result {
                Some(v) => self.pack_value(v),
                None => self.pack_nil(),
            }
    }
}

impl Default for MsgPackPacker {
    fn default() -> Self {
        Self::new()
    }
}

/// MessagePack unpacker for decoding bytes to values
pub struct MsgPackUnpacker<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsgPackUnpacker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    fn peek_byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(slice)
        } else {
            None
        }
    }

    /// Unpack the next value
    pub fn unpack(&mut self) -> Option<MsgPackValue<'a>> {
        let marker = self.read_byte()?;

        match marker {
            // Positive fixint
            0x00..=0x7f => Some(MsgPackValue::UInt(marker as u64)),

            // Fixmap (skip for now)
            0x80..=0x8f => {
                let len = (marker & 0x0f) as usize;
                // Skip map entries
                for _ in 0..len * 2 {
                    self.unpack()?;
                }
                Some(MsgPackValue::Map)
            }

            // Fixarray - return header, caller must read elements
            0x90..=0x9f => {
                let len = (marker & 0x0f) as usize;
                Some(MsgPackValue::ArrayHeader(len))
            }

            // Fixstr
            0xa0..=0xbf => {
                let len = (marker & 0x1f) as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }

            // Nil
            format::NIL => Some(MsgPackValue::Nil),

            // Bool
            format::FALSE => Some(MsgPackValue::Bool(false)),
            format::TRUE => Some(MsgPackValue::Bool(true)),

            // Binary
            format::BIN8 => {
                let len = self.read_byte()? as usize;
                let bytes = self.read_bytes(len)?;
                Some(MsgPackValue::Bin(bytes))
            }
            format::BIN16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                let bytes = self.read_bytes(len)?;
                Some(MsgPackValue::Bin(bytes))
            }

            // Float
            format::FLOAT32 => {
                let bytes = self.read_bytes(4)?;
                let f = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(MsgPackValue::Float32(f))
            }
            format::FLOAT64 => {
                let bytes = self.read_bytes(8)?;
                let f = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                Some(MsgPackValue::Float64(f))
            }

            // Unsigned integers
            format::UINT8 => Some(MsgPackValue::UInt(self.read_byte()? as u64)),
            format::UINT16 => {
                let bytes = self.read_bytes(2)?;
                Some(MsgPackValue::UInt(
                    u16::from_be_bytes([bytes[0], bytes[1]]) as u64
                ))
            }
            format::UINT32 => {
                let bytes = self.read_bytes(4)?;
                Some(MsgPackValue::UInt(
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                ))
            }
            format::UINT64 => {
                let bytes = self.read_bytes(8)?;
                Some(MsgPackValue::UInt(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }

            // Signed integers
            format::INT8 => Some(MsgPackValue::Int(self.read_byte()? as i8 as i64)),
            format::INT16 => {
                let bytes = self.read_bytes(2)?;
                Some(MsgPackValue::Int(
                    i16::from_be_bytes([bytes[0], bytes[1]]) as i64
                ))
            }
            format::INT32 => {
                let bytes = self.read_bytes(4)?;
                Some(MsgPackValue::Int(
                    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                ))
            }
            format::INT64 => {
                let bytes = self.read_bytes(8)?;
                Some(MsgPackValue::Int(i64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }

            // Strings
            format::STR8 => {
                let len = self.read_byte()? as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }
            format::STR16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }

            // Arrays - return header, caller must read elements
            format::ARRAY16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                Some(MsgPackValue::ArrayHeader(len))
            }

            // Negative fixint
            0xe0..=0xff => Some(MsgPackValue::Int(marker as i8 as i64)),

            // Extension types - skip
            format::FIXEXT1 => {
                self.read_bytes(2)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT2 => {
                self.read_bytes(3)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT4 => {
                self.read_bytes(5)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT8 => {
                self.read_bytes(9)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT16 => {
                self.read_bytes(17)?;
                Some(MsgPackValue::Nil)
            }
            format::EXT8 => {
                let len = self.read_byte()? as usize;
                self.read_bytes(len + 1)?;
                Some(MsgPackValue::Nil)
            }

            _ => None,
        }
    }

    /// Unpack expecting an unsigned integer
    pub fn unpack_uint(&mut self) -> Option<u64> {
        match self.unpack()? {
            MsgPackValue::UInt(u) => Some(u),
            MsgPackValue::Int(i) if i >= 0 => Some(i as u64),
            _ => None,
        }
    }

    /// Unpack expecting a signed integer
    pub fn unpack_int(&mut self) -> Option<i64> {
        match self.unpack()? {
            MsgPackValue::Int(i) => Some(i),
            MsgPackValue::UInt(u) if u <= i64::MAX as u64 => Some(u as i64),
            _ => None,
        }
    }

    /// Unpack expecting a string
    pub fn unpack_str(&mut self) -> Option<&'a str> {
        match self.unpack()? {
            MsgPackValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Unpack expecting an array, returns the length
    pub fn unpack_array_header(&mut self) -> Option<usize> {
        let marker = self.read_byte()?;
        match marker {
            0x90..=0x9f => Some((marker & 0x0f) as usize),
            format::ARRAY16 => {
                let bytes = self.read_bytes(2)?;
                Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            }
            format::ARRAY32 => {
                let bytes = self.read_bytes(4)?;
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            }
            _ => None,
        }
    }
}
