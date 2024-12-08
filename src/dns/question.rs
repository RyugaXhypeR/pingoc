use super::{
    buffer::PacketBuffer,
    query::{DnsQueryClass, DnsQueryType},
};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: DnsQueryType,
    pub query_class: DnsQueryClass,
}

impl DnsQuestion {
    /* Question section format

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    pub fn new(name: String, query_type: DnsQueryType) -> Self {
        Self {
            name,
            query_type,
            query_class: DnsQueryClass::IN,
        }
    }

    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let mut question = DnsQuestion::new("".to_string(), DnsQueryType::A);
        question.name = buffer.read_query_name()?;
        question.query_type = DnsQueryType::from_u16(buffer.read_u16()?);
        question.query_class = DnsQueryClass::from_u16(buffer.read_u16()?);

        Ok(question)
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_query_name(&self.name)?;
        buffer.write_u16(self.query_type.to_u16())?;
        buffer.write_u16(self.query_class.to_u16())?;
        Ok(())
    }
}
