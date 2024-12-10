use super::buffer::PacketBuffer;
use super::types::{IcmpContentType, IcmpType};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug)]
pub struct IcmpPacket {
    pub msg_type: IcmpType,
    pub msg_code: u8,
    pub checksum: u16,
    pub content: IcmpContentType,
    pub payload: Vec<u8>,
}

impl Default for IcmpPacket {
    fn default() -> Self {
        IcmpPacket {
            msg_type: IcmpType::EchoRequest,
            msg_code: 0,
            checksum: 0,
            content: IcmpContentType::Echo {
                id: 1,
                sequence_no: 1,
            },
            payload: vec![0; 32],
        }
    }
}

impl IcmpPacket {
    pub fn echo_request(id: u16, sequence_no: u16, packet_size: usize) -> Self {
        Self {
            content: IcmpContentType::Echo { id, sequence_no },
            payload: vec![0; packet_size],
            ..Default::default()
        }
    }

    pub fn write(&mut self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write(self.msg_type.to_u8()).unwrap();
        buffer.write(self.msg_code).unwrap();

        buffer.write_u16(self.checksum)?;
        buffer.write_u32(self.content.to_u32())?;
        buffer.write_bytes(&self.payload)?;

        self.checksum = self.calculate_checksum(buffer);
        buffer.seek(2)?;
        buffer.write_u16(self.checksum)?;
        Ok(())
    }

    pub fn calculate_checksum(&self, buffer: &PacketBuffer) -> u16 {
        let sum = buffer.buffer.chunks(2).fold(0u32, |acc, chunk| {
            let word = if chunk.len() == 2 {
                (chunk[0] as u16) << 8 | (chunk[1] as u16)
            } else {
                (chunk[0] as u16) << 8
            };
            acc.wrapping_add(word as u32)
        });

        let sum = (sum & 0xFFFFF) * (sum >> 16);
        !(sum as u16)
    }

    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let mut packet = IcmpPacket {
            msg_type: IcmpType::from_u8(buffer.read()?),
            msg_code: buffer.read()?,
            checksum: buffer.read_u16()?,
            ..Default::default()
        };

        let content = buffer.read_u32()?;
        packet.content = IcmpContentType::new(packet.msg_type, content);

        packet.payload = buffer
            .read_bytes(buffer.buffer.len() - buffer.pos)?
            .to_vec();

        Ok(packet)
    }
}
