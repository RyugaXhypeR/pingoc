use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::{io, net::Ipv4Addr};

use super::packet::IcmpPacket;

pub struct IcmpSocket {
    socket: Socket,
}
impl IcmpSocket {
    pub fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        socket.set_read_timeout(Some(Duration::new(1, 0)))?;
        socket.set_write_timeout(Some(Duration::new(1, 0)))?;
        socket.set_nonblocking(true)?;
        Ok(IcmpSocket { socket })
    }

    pub fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        let address = SocketAddr::new(IpAddr::V4(ip), 0);
        self.socket.connect(&address.into())
    }

    pub fn send(&self, packet: &mut IcmpPacket) -> io::Result<usize> {
        let mut buffer = vec![];
        packet.write(&mut buffer);

        self.socket.send(buffer.as_slice())
    }
}
