use crate::dns::header::DnsResponseCode;

use super::{buffer::PacketBuffer, packet::DnsPacket, query::DnsQueryType, question::DnsQuestion};
use std::error::Error;
use std::net::{Ipv4Addr, UdpSocket};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn lookup(domain: &str, query_type: DnsQueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    let mut packet = DnsPacket::new();

    packet.header.id = 1234;
    packet.header.question_count = 1;
    packet
        .questions
        .push(DnsQuestion::new(domain.into(), query_type));

    let mut buffer = PacketBuffer::new();
    packet.write(&mut buffer)?;

    socket.send_to(&buffer.buffer[..buffer.pos], server)?;

    let mut buffer = PacketBuffer::new();
    socket.recv_from(&mut buffer.buffer)?;

    DnsPacket::read(&mut buffer)
}

pub fn recursive_lookup(query_name: &str, query_type: DnsQueryType) -> Result<DnsPacket> {
    let mut nameserver = Ipv4Addr::new(198, 41, 0, 4);
    loop {
        if cfg!(debug_assertions) {
            println!(
                "Attempting lookup of {query_name}::{query_type:?} with nameserver {nameserver:?}"
            );
        }

        let server = (nameserver, 53);
        let response = lookup(query_name, query_type, server)?;

        if (!response.answers.is_empty() && response.header.response_code == DnsResponseCode::NoError)
            || response.header.response_code == DnsResponseCode::NxDomain
        {
            return Ok(response);
        }

        if let Some(new_nameserver) = response.get_resolved_nameserver(query_name) {
            nameserver = new_nameserver;
            continue;
        }

        let new_nameserver = match response.get_uresolved_nameserver(query_name) {
            Some(ns) => ns,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(new_nameserver, DnsQueryType::A)?;
        match recursive_response.get_a_record() {
            Some(ns) => nameserver = ns,
            None => return Ok(response),
        };
    }
}
