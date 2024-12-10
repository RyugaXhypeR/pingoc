use clap::Parser;
use pingoc::resolve::resolve_hostname;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pingoc::icmp::packet::IcmpPacket;
use pingoc::icmp::socket::IcmpSocket;
use pingoc::icmp::types::IcmpContentType;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct PingStats {
    packets_sent: usize,
    packets_recv: usize,
    bytes_sent: f32,
    bytes_recv: f32,
}

/// Command-line arguments for pingoc
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct PingArgs {
    /// Ping destination (hostname or IP)
    #[arg(short, long)]
    destination: String,

    /// Number of ping requests to send
    #[arg(short, long)]
    count: Option<usize>,

    /// Suppress output, only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Set the timeout for each ping request in seconds
    #[arg(short, long, default_value_t = 1)]
    timeout: usize,

    /// Ping with a specific packet size (in bytes)
    #[arg(short, long, default_value_t = 56)]
    packet_size: usize,

    /// Set the interval between pings in seconds
    #[arg(short, long, default_value_t = 0.5)]
    interval: f64,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Configure keyboard interrupt handling
fn setup_interrupt_handler() -> Arc<AtomicBool> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let handler_interrupt = Arc::clone(&interrupt);

    ctrlc::set_handler(move || {
        handler_interrupt.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    interrupt
}

fn send_ping(
    socket: &mut IcmpSocket,
    ip: Ipv4Addr,
    id: u16,
    packet_size: usize,
    quiet: bool,
) -> Result<Option<usize>> {
    let mut packet = IcmpPacket::echo_request(id, 0, packet_size);
    socket.send(&mut packet)?;

    match socket.recv() {
        Ok(received_packet) => {
            let num_bytes = received_packet.payload.len();
            let icmp_seq = match received_packet.content {
                IcmpContentType::Echo { id: _, sequence_no } => sequence_no,
                _ => 1,
            };

            if !quiet {
                println!("{num_bytes} bytes from {ip}: icmp_seq={icmp_seq} ttl=");
            }

            Ok(Some(num_bytes))
        }
        Err(e) => {
            eprintln!("Error receiving packet: {e}");
            Ok(None)
        }
    }
}

fn ping_handler(args: PingArgs) -> Result<()> {
    let ip = match resolve_hostname(&args.destination) {
        Some(IpAddr::V4(v4)) => v4,
        _ => return Err("Failed to resolve hostname".into()),
    };

    let mut socket = IcmpSocket::new(args.timeout)?;
    socket.connect(ip)?;
    let interrupt = setup_interrupt_handler();

    let mut stats = PingStats {
        packets_sent: 0,
        packets_recv: 0,
        bytes_sent: 0.0,
        bytes_recv: 0.0,
    };

    println!(
        "Pingoc: {} ({}) with {}({}) bytes of data.",
        args.destination,
        ip,
        args.packet_size,
        args.packet_size + 28
    );

    let mut id = 1;
    let mut remaining_count = args.count;

    // Ping loop
    while !interrupt.load(Ordering::SeqCst)
        && match remaining_count {
            Some(cnt) => cnt > 0,
            None => true,
        }
    {
        stats.packets_sent += 1;
        stats.bytes_sent += args.packet_size as f32;

        if let Some(recv_bytes) = send_ping(&mut socket, ip, id, args.packet_size, args.quiet)? {
            stats.packets_recv += 1;
            stats.bytes_recv += recv_bytes as f32;
        }

        id += 1;

        remaining_count = remaining_count.map(|cnt| cnt - 1);
        thread::sleep(Duration::from_secs_f64(args.interval));
    }

    print_ping_stats(&args.destination, &stats);

    Ok(())
}

fn print_ping_stats(hostname: &str, stats: &PingStats) {
    println!("--- {hostname} ping statistics ---");
    let packet_loss = if stats.bytes_sent > 0.0 {
        100.0 - (stats.bytes_recv / stats.bytes_sent * 100.0)
    } else {
        0.0
    };

    println!(
        "{} bytes transmitted, {} received, {:.1}% packet loss",
        stats.bytes_sent as usize, stats.bytes_recv as usize, packet_loss
    );
}

fn main() -> Result<()> {
    let args = PingArgs::parse();
    ping_handler(args)
}
