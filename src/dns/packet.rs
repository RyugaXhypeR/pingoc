use super::{
    buffer::PacketBuffer, header::DnsHeader, query::DnsQueryType, question::DnsQuestion,
    record::DnsRecord,
};
use std::{error::Error, net::IpAddr};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsPacket {
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
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn read(buffer: &mut PacketBuffer) -> Result<Self> {
        let header = DnsHeader::read(buffer)?;
        let mut packet = DnsPacket::new();
        packet.header = header;
        for _ in 0..header.question_count {
            packet.questions.push(DnsQuestion::read(buffer)?);
        }
        for _ in 0..header.answer_count {
            packet.answers.push(DnsRecord::read(buffer)?);
        }
        for _ in 0..header.authority_count {
            packet.authorities.push(DnsRecord::read(buffer)?);
        }
        for _ in 0..header.additional_count {
            packet.additional.push(DnsRecord::read(buffer)?);
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
            if let DnsRecord::NS { domain, host, .. } = record {
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

    pub fn get_resolved_nameserver(
        &self,
        query_name: &str,
        query_type: DnsQueryType,
    ) -> Option<IpAddr> {
        self.get_nameservers(query_name)
            .flat_map(|(_, host)| {
                self.additional
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. }
                            if domain == host && record.matches_query_type(query_type) =>
                        {
                            Some(IpAddr::V4(*addr))
                        }
                        DnsRecord::AAAA { domain, addr, .. }
                            if domain == host && record.matches_query_type(query_type) =>
                        {
                            Some(IpAddr::V6(*addr))
                        }
                        _ => None,
                    })
            })
            .next()
    }

    pub fn get_uresolved_nameserver<'a>(&'a self, query_name: &'a str) -> Option<&'a str> {
        self.get_nameservers(query_name)
            .map(|(_, host)| host)
            .next()
    }

    pub fn get_record(&self, query_type: DnsQueryType) -> Option<IpAddr> {
        self.answers
            .iter()
            .find(|record| record.matches_query_type(query_type))
            .and_then(|record| match record {
                DnsRecord::A { addr, .. } => Some(IpAddr::V4(*addr)),
                DnsRecord::AAAA { addr, .. } => Some(IpAddr::V6(*addr)),
                _ => None,
            })
    }
}
