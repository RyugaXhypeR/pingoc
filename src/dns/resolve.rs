use super::{buffer::PacketBuffer, packet::Packet, query::QueryType, question::Question};
use std::error::Error;
use std::net::UdpSocket;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn lookup(domain: &str, query_type: QueryType, server: (Ipv4Addr, u16)) -> Result<Packet> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    let mut packet = Packet::new();

    packet.header.id = 1234;
    packet.header.question_count = 1;
    packet
        .questions
        .push(Question::new(domain.into(), query_type));

    let mut buffer = PacketBuffer::new();
    packet.write(&mut buffer)?;

    socket.send_to(&buffer.buffer[..buffer.pos], server)?;

    let mut buffer = PacketBuffer::new();
    socket.recv_from(&mut buffer.buffer)?;

    Packet::read(&mut buffer)
}
