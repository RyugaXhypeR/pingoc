mod dns;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use dns::header::ResponseCode;
use dns::query::QueryType;
use dns::resolve::{lookup, recursive_lookup};

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
    if let Ok(response) = lookup(hostname, QueryType::A, SERVER) {
        if response.header.response_code == ResponseCode::NoError {
            if let Some(a_record) = response.get_a_record() {
                return Some(IpAddr::V4(a_record));
            }
        }
    }

    // Final fallback: Use a recursive lookup if the above methods fail.
    if let Ok(response) = recursive_lookup(hostname, QueryType::A) {
        if let Some(a_record) = response.get_a_record() {
            return Some(IpAddr::V4(a_record));
        }
    }

    None
}

fn main() -> Result<()> {
    let hostnames = [
        "192.168.1.1",
        "2345.12.12.1",
        "ryuga.com",
        "google.com",
        "ww.example.com",
        "something.com",
    ];

    for hostname in hostnames {
        if let Some(ip) = resolve_hostname(hostname) {
            println!("Resolved {hostname}: {ip}");
        } else {
            println!("Unable to resolve {hostname}");
        }
    }

    Ok(())
}
