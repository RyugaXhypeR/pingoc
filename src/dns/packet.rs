use super::{buffer::PacketBuffer, header::Header, question::Question, record::Record};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Packet {
    /* Packet format

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
    */
    pub fn new() -> Self {
        Self {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let header = Header::read(buffer)?;
        let mut packet = Packet::new();
        packet.header = header;
        for _ in 0..header.question_count {
            packet.questions.push(Question::read(buffer)?);
        }
        for _ in 0..header.answer_count {
            packet.answers.push(Record::read(buffer)?);
        }
        for _ in 0..header.authority_count {
            packet.authorities.push(Record::read(buffer)?);
        }
        for _ in 0..header.additional_count {
            packet.additional.push(Record::read(buffer)?);
        }
        Ok(packet)
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        self.header.write(buffer)?;
        self.questions.iter().try_for_each(|q| q.write(buffer))?;
        self.answers.iter().try_for_each(|a| a.write(buffer))?;
        self.authorities.iter().try_for_each(|a| a.write(buffer))?;
        self.additional.iter().try_for_each(|a| a.write(buffer))?;
        Ok(())
    }
}
