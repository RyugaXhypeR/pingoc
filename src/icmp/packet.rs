use super::types::{IcmpContentType, IcmpType};

pub struct IcmpPacket {
    msg_type: IcmpType,
    msg_code: u8,
    checksum: u16,
    content: IcmpContentType,
    payload: Vec<u8>,
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
    pub fn write(&mut self, buffer: &mut Vec<u8>) {
        buffer.push(self.msg_type.to_u8());
        buffer.push(self.msg_code);

        /* Has to be re-written after calculating checksum */
        buffer.extend(&self.checksum.to_be_bytes());

        buffer.extend(&self.content.to_be_bytes());
        buffer.extend(&self.payload);

        self.checksum = self.calculate_checksum(&buffer);
        buffer[2] = (self.checksum << 8) as u8;
        buffer[3] = (self.checksum & 0xFF) as u8;
    }

    pub fn calculate_checksum(&self, buffer: &Vec<u8>) -> u16 {
        let sum = buffer.chunks(2).fold(0u32, |acc, chunk| {
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
}
