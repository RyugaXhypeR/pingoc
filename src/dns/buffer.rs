use std::fmt;

/// Custom error type for the PacketBuffer
#[derive(Debug)]
pub enum PacketBufferError {
    PositionOutOfBounds(usize),
    EndOfBuffer,
    InvalidLabelLength,
    JumpLimitExceeded,
    Utf8ConversionError(std::string::FromUtf8Error),
}

impl fmt::Display for PacketBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketBufferError::PositionOutOfBounds(pos) => {
                write!(f, "Position {} exceeds buffer size", pos)
            }
            PacketBufferError::EndOfBuffer => {
                write!(f, "Attempt to read beyond the end of the buffer")
            }
            PacketBufferError::InvalidLabelLength => write!(f, "Invalid label length in DNS name"),
            PacketBufferError::JumpLimitExceeded => write!(f, "Limit of DNS jumps exceeded"),
            PacketBufferError::Utf8ConversionError(err) => {
                write!(f, "UTF-8 conversion error: {}", err)
            }
        }
    }
}

impl std::error::Error for PacketBufferError {}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A Buffer to read and write various components of a DNS packet
pub struct PacketBuffer {
    pub buffer: [u8; 512],
    pub pos: usize,
}

impl PacketBuffer {
    /// Initialize an empty buffer
    pub fn new() -> Self {
        Self {
            buffer: [0; 512],
            pos: 0,
        }
    }

    /// Set position in the buffer
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos >= self.buffer.len() {
            return Err(Box::new(PacketBufferError::PositionOutOfBounds(pos)));
        }
        self.pos = pos;
        Ok(())
    }

    /// Get byte at current position
    pub fn get(&self, pos: usize) -> Result<u8> {
        if pos >= self.buffer.len() {
            return Err(Box::new(PacketBufferError::EndOfBuffer));
        }
        Ok(self.buffer[pos])
    }

    /// Get `len` number of bytes starting from `pos`
    pub fn get_bytes(&self, pos: usize, len: usize) -> Result<&[u8]> {
        if pos + len > self.buffer.len() {
            return Err(Box::new(PacketBufferError::EndOfBuffer));
        }
        Ok(&self.buffer[pos..pos + len])
    }

    /// Read one byte from buffer and increment position
    pub fn read(&mut self) -> Result<u8> {
        let result = self.get(self.pos)?;
        self.pos += 1;
        Ok(result)
    }

    /// Read a 16-bit unsigned integer from
    pub fn read_u16(&mut self) -> Result<u16> {
        Ok((self.read()? as u16) << 8 | (self.read()? as u16))
    }

    /// Read a 32-bit unsigned integer from
    pub fn read_u32(&mut self) -> Result<u32> {
        Ok((self.read_u16()? as u32) << 16 | self.read_u16()? as u32)
    }

    /// Read a 64-bit unsigned integer from
    pub fn read_u64(&mut self) -> Result<u64> {
        Ok((self.read_u32()? as u64) << 32 | self.read_u32()? as u64)
    }

    /// Read a 128-bit unsigned integer from
    pub fn read_u128(&mut self) -> Result<u128> {
        Ok((self.read_u64()? as u128) << 64 | self.read_u64()? as u128)
    }

    /// Read `len` number of bytes from the
    pub fn read_bytes(&mut self, len: usize) -> Result<&[u8]> {
        if self.pos + len > self.buffer.len() {
            return Err(Box::new(PacketBufferError::EndOfBuffer));
        }
        let result = &self.buffer[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    /// Read a DNS name from the buffer.
    /// Supports DNS name compression using pointers.
    ///
    pub fn read_query_name(&mut self) -> Result<String> {
        let mut pos = self.pos;
        let mut result = Vec::new();
        let mut jumped = false;
        let mut jumps_performed = 0;
        const MAX_JUMPS: usize = 5;

        loop {
            if jumps_performed > MAX_JUMPS {
                return Err(Box::new(PacketBufferError::JumpLimitExceeded));
            }

            let len = self.get(pos)?;
            /*
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            | 1  1|                OFFSET                   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

            Label lengths are atmost 63 bytes, hence the first two bits of the length
            byte are always 0. If the first two bits are 11, then it is interpreted as
            a pointer to another part of the message (OFFSET).

            */
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
            } else {
                pos += 1;
                if len == 0 {
                    break;
                }

                let label_bytes = self.get_bytes(pos, len as usize)?;
                let label = String::from_utf8(label_bytes.to_vec())
                    .map_err(PacketBufferError::Utf8ConversionError)?;
                result.push(label);
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(result.join("."))
    }

    /// Write a byte to the buffer and increment position
    pub fn write(&mut self, value: u8) -> Result<()> {
        if self.pos >= self.buffer.len() {
            return Err(Box::new(PacketBufferError::EndOfBuffer));
        }
        self.buffer[self.pos] = value;
        self.pos += 1;
        Ok(())
    }

    /// Write a 16-bit unsigned integer to the buffer
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.write((value >> 8) as u8)?;
        self.write(value as u8)
    }

    /// Write a 32-bit unsigned integer to the buffer
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_u16((value >> 16) as u16)?;
        self.write_u16(value as u16)
    }

    /// Write a 64-bit unsigned integer to the buffer
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        self.write_u32((value >> 32) as u32)?;
        self.write_u32(value as u32)
    }

    /// Write a 128-bit unsigned integer to the buffer
    pub fn write_u128(&mut self, value: u128) -> Result<()> {
        self.write_u64((value >> 64) as u64)?;
        self.write_u64(value as u64)
    }

    /// Write a slice of bytes to the buffer
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        for b in bytes {
            self.write(*b)?;
        }
        Ok(())
    }

    /// Write a DNS query name to the buffer
    pub fn write_query_name(&mut self, name: &str) -> Result<()> {
        let pos = self.pos;
        for label in name.split('.') {
            if label.len() > 63 {
                self.pos = pos;
                return Err(Box::new(PacketBufferError::InvalidLabelLength));
            }

            self.write(label.len() as u8)?;
            for b in label.bytes() {
                self.write(b)?;
            }
        }
        self.write(0)
    }
}
