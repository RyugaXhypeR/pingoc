use super::buffer::PacketBuffer;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DnsResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl DnsResponseCode {
    pub fn from_u8(value: u8) -> DnsResponseCode {
        match value {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormErr,
            2 => DnsResponseCode::ServFail,
            3 => DnsResponseCode::NxDomain,
            4 => DnsResponseCode::NotImp,
            5 => DnsResponseCode::Refused,
            _ => panic!("Invalid response code"),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,

    // flags
    pub query_response: bool,           // 1 bit
    pub opcode: u8,                     // 4 bits
    pub authoritative_answer: bool,     // 1 bit
    pub truncated_message: bool,        // 1 bit
    pub recursion_desired: bool,        // 1 bit
    pub recursion_available: bool,      // 1 bit
    pub reserved: u8,                   // 3 bits
    pub response_code: DnsResponseCode, // 4 bits

    // counts
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    /* Header section format


                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */

    /// Creates a new `DnsHeader` with default values.
    pub fn new() -> Self {
        Self {
            id: 0,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: DnsResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    /// Reads a `DnsHeader` from a `PacketBuffer`.
    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let mut header = DnsHeader::new();
        header.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        header.set_flags(flags);

        header.question_count = buffer.read_u16()?;
        header.answer_count = buffer.read_u16()?;
        header.authority_count = buffer.read_u16()?;
        header.additional_count = buffer.read_u16()?;

        Ok(header)
    }

    /// Sets the flags from a 16-bit integer.
    fn set_flags(&mut self, flags: u16) {
        const QR_MASK: u16 = 0b1000_0000_0000_0000; // 15th bit
        const OPCODE_MASK: u16 = 0b0111_1000_0000_0000; // 11th to 14th bits
        const AA_MASK: u16 = 0b0000_0100_0000_0000; // 10th bit
        const TC_MASK: u16 = 0b0000_0010_0000_0000; // 9th bit
        const RD_MASK: u16 = 0b0000_0001_0000_0000; // 8th bit
        const RA_MASK: u16 = 0b0000_0000_1000_0000; // 7th bit
        const RESERVED_MASK: u16 = 0b0000_0000_0111_0000; // 4th to 6th bits
        const RCODE_MASK: u16 = 0b0000_0000_0000_1111; // 0th to 3rd bits

        self.query_response = (flags & QR_MASK) != 0;
        self.opcode = ((flags & OPCODE_MASK) >> 11) as u8;
        self.authoritative_answer = (flags & AA_MASK) != 0;
        self.truncated_message = (flags & TC_MASK) != 0;
        self.recursion_desired = (flags & RD_MASK) != 0;
        self.recursion_available = (flags & RA_MASK) != 0;
        self.reserved = ((flags & RESERVED_MASK) >> 4) as u8;
        self.response_code = DnsResponseCode::from_u8((flags & RCODE_MASK) as u8);
    }

    fn get_flags(&self) -> u16 {
        let mut flags = 0;
        if self.query_response {
            flags |= 1 << 15;
        }
        flags |= (self.opcode as u16) << 11;
        if self.authoritative_answer {
            flags |= 1 << 10;
        }
        if self.truncated_message {
            flags |= 1 << 9;
        }
        if self.recursion_desired {
            flags |= 1 << 8;
        }
        if self.recursion_available {
            flags |= 1 << 7;
        }
        flags |= (self.reserved as u16) << 4;
        flags |= self.response_code as u16;
        flags
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;
        buffer.write_u16(self.get_flags())?;
        buffer.write_u16(self.question_count)?;
        buffer.write_u16(self.answer_count)?;
        buffer.write_u16(self.authority_count)?;
        buffer.write_u16(self.additional_count)?;

        Ok(())
    }
}
