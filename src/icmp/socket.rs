use libc::{sockaddr, sockaddr_in, socket, AF_INET, IPPROTO_ICMP, SOCK_DGRAM};
use std::net::Ipv4Addr;
use std::{io, mem};

use super::buffer::PacketBuffer;
use super::packet::IcmpPacket;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const ICMP_RECV_BUFFER_SZ: usize = 2000;

pub struct IcmpSocket {
    socket: i32,
    address: sockaddr_in,
}

impl IcmpSocket {
    pub fn new() -> io::Result<Self> {
        let socket = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) };
        if socket < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut address: sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_family = AF_INET as u16;
        address.sin_port = 0;

        Ok(Self { socket, address })
    }

    pub fn connect(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        self.address.sin_addr.s_addr = ip.to_bits().to_be();
        Ok(())
    }

    pub fn send(&self, packet: &mut IcmpPacket) -> Result<usize> {
        let mut buffer = PacketBuffer::new();
        packet.write(&mut buffer)?;

        let buffer_bytes = buffer.get_bytes(0, buffer.buffer.len())?;

        let result = unsafe {
            libc::sendto(
                self.socket,
                buffer_bytes.as_ptr() as *const libc::c_void,
                buffer_bytes.len(),
                0,
                &self.address as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_in>() as libc::socklen_t,
            )
        };

        if result == -1 {
            Err(Box::new(io::Error::last_os_error()))
        } else {
            Ok(result as usize)
        }
    }

    pub fn recv(&self) -> Result<IcmpPacket> {
        let buffer = [0; ICMP_RECV_BUFFER_SZ];
        let mut address: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut address_len = mem::size_of::<sockaddr_in>() as libc::socklen_t;

        let num_bytes = unsafe {
            libc::recvfrom(
                self.socket,
                buffer.as_ptr() as *mut libc::c_void,
                ICMP_RECV_BUFFER_SZ,
                0,
                &mut address as *mut _ as *mut libc::sockaddr,
                &mut address_len,
            )
        };

        if num_bytes < 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

        let recv_sz = num_bytes as usize;
        let mut packet_buffer = PacketBuffer::from(&buffer[..recv_sz]);

        IcmpPacket::read(&mut packet_buffer)
    }
}
