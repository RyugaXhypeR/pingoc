use std::fmt;

/// Custom error type for the PacketBuffer
#[derive(Debug)]
pub enum PacketBufferError {
    PositionOutOfBounds(usize),
    EndOfBuffer,
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
            PacketBufferError::Utf8ConversionError(err) => {
                write!(f, "UTF-8 conversion error: {}", err)
            }
        }
    }
}

impl std::error::Error for PacketBufferError {}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A Buffer to read and write various components of an ICMP packet
pub struct PacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl PacketBuffer {
    /// Initialize an empty buffer
    pub fn new() -> Self {
        Self {
            buffer: vec![],
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

    /// Read a 16-bit unsigned integer from buffer
    pub fn read_u16(&mut self) -> Result<u16> {
        Ok((self.read()? as u16) << 8 | (self.read()? as u16))
    }

    /// Read a 32-bit unsigned integer from buffer
    pub fn read_u32(&mut self) -> Result<u32> {
        Ok((self.read_u16()? as u32) << 16 | self.read_u16()? as u32)
    }

    /// Read a 64-bit unsigned integer from buffer
    pub fn read_u64(&mut self) -> Result<u64> {
        Ok((self.read_u32()? as u64) << 32 | self.read_u32()? as u64)
    }

    /// Read bytes from the buffer and increment position
    pub fn read_bytes(&mut self, len: usize) -> Result<&[u8]> {
        if self.pos + len > self.buffer.len() {
            return Err(Box::new(PacketBufferError::EndOfBuffer));
        }
        let result = &self.buffer[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    /// Write a byte to the buffer and increment position
    pub fn write(&mut self, value: u8) -> Result<()> {
        if self.pos < self.buffer.len() {
            self.buffer[self.pos] = value;
        } else {
            self.buffer.push(value);
        }
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

    /// Write a slice of bytes to the buffer
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        for b in bytes {
            self.write(*b)?;
        }
        Ok(())
    }
}

impl From<&[u8]> for PacketBuffer {
    fn from(buffer: &[u8]) -> Self {
        Self {
            buffer: buffer.to_vec(),
            pos: 0,
        }
    }
}
