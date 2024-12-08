use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use pingoc::dns::header::DnsResponseCode;
use pingoc::dns::query::DnsQueryType;
use pingoc::dns::resolve::{  lookup, recursive_lookup};
use pingoc::icmp::packet::IcmpPacket;
use pingoc::icmp::socket::IcmpSocket;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(8, 8, 8, 8), 53);

pub fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    // First, try resolving the hostname using the system's DNS resolver.
    if let Ok(mut resolved) = (hostname, 0).to_socket_addrs() {
        if let Some(socket_addr) = resolved.next() {
            return Some(socket_addr.ip());
        }
    }

    // Fallback: Use a custom lookup function with Google's public DNS server.
    if let Ok(response) = lookup(hostname, DnsQueryType::A, SERVER) {
        if response.header.response_code == DnsResponseCode::NoError {
            if let Some(a_record) = response.get_a_record() {
                return Some(IpAddr::V4(a_record));
            }
        }
    }

    // Final fallback: Use a recursive lookup if the above methods fail.
    if let Ok(response) = recursive_lookup(hostname, DnsQueryType::A) {
        if let Some(a_record) = response.get_a_record() {
            return Some(IpAddr::V4(a_record));
        }
    }

    None
}

fn main() -> Result<()> {
    let hostname = "google.com";
    let ip = match resolve_hostname(hostname).unwrap() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    };
    let ip = ip.unwrap();

    let mut packet = IcmpPacket::default();
    let socket = IcmpSocket::new()?;
    socket.connect(ip)?;
    socket.send(&mut packet)?;

    Ok(())
}
