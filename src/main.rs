use clap::Parser;
use ctrlc::set_handler;
use pingoc::icmp::types::IcmpContentType;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pingoc::dns::header::DnsResponseCode;
use pingoc::dns::query::DnsQueryType;
use pingoc::dns::resolve::{lookup, recursive_lookup};
use pingoc::icmp::packet::IcmpPacket;
use pingoc::icmp::socket::IcmpSocket;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(8, 8, 8, 8), 53);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Ping destination
    #[arg(short, long)]
    destination: String,

    /// Number of ping requests to send
    #[arg(short, long, default_value_t = usize::MAX)]
    count: usize,

    /// Suppress output, only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Set the timeout for each ping request in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout: u64,

    /// Ping with a specific packet size (in bytes)
    #[arg(short, long, default_value_t = 56)]
    packet_size: usize,

    /// Set the interval between pings in seconds
    #[arg(short, long, default_value_t = 1)]
    interval: u64,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

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

fn ping_handler(args: Args) -> Result<()> {
    let hostname = &args.destination;
    let ip = match resolve_hostname(hostname) {
        Some(IpAddr::V4(v4)) => v4,
        _ => return Err("Failed to resolve hostname".into()),
    };

    let mut socket = IcmpSocket::new()?;
    socket.connect(ip)?;

    let mut id = 1;
    let mut count = args.count;

    println!(
        "Pingoc: {hostname} ({ip}) with {}({}) bytes of data.",
        args.packet_size,
        args.packet_size + 28
    );

    let mut num_packets_sent = 0;
    let mut num_packets_recv = 0;

    let mut num_bytes_sent = 0f32;
    let mut num_bytes_recv = 0f32;

    let intr = Arc::new(Mutex::new(false));
    let intr_lock = Arc::clone(&intr);
    set_handler(move || {
        let mut intr = intr_lock.lock().unwrap();
        *intr = true;
    })?;

    loop {
        if *intr.lock().unwrap() {
            break;
        }

        let mut packet = IcmpPacket::echo_request(id, 0, args.packet_size);
        socket.send(&mut packet)?;
        num_packets_sent += 1;
        num_bytes_sent += args.packet_size as f32;

        match socket.recv() {
            Ok(received_packet) => {
                num_packets_recv += 1;

                let num_bytes = received_packet.payload.len();
                num_bytes_recv += num_bytes as f32;

                let icmp_seq = match received_packet.content {
                    IcmpContentType::Echo { id: _, sequence_no } => sequence_no,
                    _ => 1,
                };

                if !args.quiet {
                    println!("{num_bytes} bytes from {ip}: icmp_seq={icmp_seq} ttl= time=");
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {e}");
            }
        }

        id += 1;
        if count != usize::MAX {
            count -= 1;
            if count == 0 {
                break;
            }
        }

        // Sleep for the specified interval before sending the next request
        thread::sleep(Duration::from_secs(args.interval));
    }

    println!("--- {hostname} ping statistics ---");
    println!(
        "{num_packets_sent} bytes transmitted, {num_packets_recv} received, {:.1}% packet loss",
        100f32 - (num_bytes_recv / num_bytes_sent * 100f32)
    );

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    ping_handler(args)
}
