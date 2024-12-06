use super::{buffer::PacketBuffer, header::Header, question::Question, record::Record};
use std::{error::Error, net::Ipv4Addr};

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

    pub fn get_nameservers<'a>(
        &'a self,
        query_name: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(move |record| {
            if let Record::NS { domain, host, .. } = record {
                if query_name.ends_with(domain) {
                    Some((domain.as_str(), host.as_str()))
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    pub fn get_resolved_nameserver(&self, query_name: &str) -> Option<Ipv4Addr> {
        self.get_nameservers(query_name)
            .flat_map(|(_, host)| {
                self.additional
                    .iter()
                    .filter_map(move |record| match record {
                        Record::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_uresolved_nameserver<'a>(&'a self, query_name: &'a str) -> Option<&'a str> {
        self.get_nameservers(query_name)
            .map(|(_, host)| host)
            .next()
    }

    pub fn get_a_record(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                Record::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }
}
