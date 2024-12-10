use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use crate::dns::{
    header::DnsResponseCode,
    query::DnsQueryType,
    resolve::{lookup, recursive_lookup},
};

const SERVER: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

pub fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    // First, try resolving the hostname using the system's DNS resolver.
    if let Ok(mut resolved) = (hostname, 0).to_socket_addrs() {
        if let Some(socket_addr) = resolved.next() {
            return Some(socket_addr.ip());
        }
    }

    // Attempt to resolve the hostname to an IPv4 address.
    if let Some(ipv4_addr) = resolve_hostname_to_v4(hostname) {
        return Some(IpAddr::V4(ipv4_addr));
    }

    // If IPv4 resolution fails, attempt to resolve it to an IPv6 address.
    if let Some(ipv6_addr) = resolve_hostname_to_v6(hostname) {
        return Some(IpAddr::V6(ipv6_addr));
    }

    // If both attempts fail, return None.
    None
}

pub fn resolve_hostname_to_v4(hostname: &str) -> Option<Ipv4Addr> {
    if let Ok(response) = lookup(hostname, DnsQueryType::A, SERVER) {
        if response.header.response_code == DnsResponseCode::NoError {
            if let Some(IpAddr::V4(record)) = response.get_record(DnsQueryType::A) {
                return Some(record);
            }
        }
    }

    if let Ok(response) = recursive_lookup(hostname, DnsQueryType::A) {
        if let Some(IpAddr::V4(record)) = response.get_record(DnsQueryType::A) {
            return Some(record);
        }
    }

    None
}

pub fn resolve_hostname_to_v6(hostname: &str) -> Option<Ipv6Addr> {
    if let Ok(response) = lookup(hostname, DnsQueryType::AAAA, SERVER) {
        if response.header.response_code == DnsResponseCode::NoError {
            if let Some(IpAddr::V6(record)) = response.get_record(DnsQueryType::AAAA) {
                return Some(record);
            }
        }
    }

    if let Ok(response) = recursive_lookup(hostname, DnsQueryType::AAAA) {
        if let Some(IpAddr::V6(record)) = response.get_record(DnsQueryType::AAAA) {
            return Some(record);
        }
    }

    None
}
