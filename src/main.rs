use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;

#[derive(Default)]
struct Counts {
    packets: u64,
    bytes: u64,
}

#[derive(Default)]
struct Summary {
    packets: u64,
    bytes: u64,
    truncated_packets: u64,
    protocols: BTreeMap<&'static str, Counts>,
    endpoints: BTreeMap<String, u64>,
}

impl Summary {
    fn add_packet(&mut self, data: &[u8], truncated: bool) {
        self.packets += 1;
        self.bytes += data.len() as u64;
        self.truncated_packets += u64::from(truncated);

        match SlicedPacket::from_ethernet(data) {
            Ok(packet) => {
                let protocol = protocol_name(&packet);
                let counts = self.protocols.entry(protocol).or_default();
                counts.packets += 1;
                counts.bytes += data.len() as u64;

                if let Some((source, destination)) = ip_endpoints(&packet) {
                    *self.endpoints.entry(source).or_default() += 1;
                    *self.endpoints.entry(destination).or_default() += 1;
                }
            }
            Err(_) => {
                let category = if truncated { "TRUNCATED" } else { "MALFORMED" };
                let counts = self.protocols.entry(category).or_default();
                counts.packets += 1;
                counts.bytes += data.len() as u64;
            }
        }
    }

    fn print(&self) {
        println!("Packets: {}", self.packets);
        println!("Captured bytes: {}", self.bytes);
        println!("Truncated packets: {}", self.truncated_packets);

        println!("\nProtocols:");
        print_counts(&self.protocols);

        println!("\nTop IP endpoints:");
        let mut endpoints: Vec<_> = self.endpoints.iter().collect();
        endpoints.sort_by(|(address_a, count_a), (address_b, count_b)| {
            count_b.cmp(count_a).then_with(|| address_a.cmp(address_b))
        });

        if endpoints.is_empty() {
            println!("  (none)");
        } else {
            for (address, count) in endpoints.into_iter().take(10) {
                println!("  {address:<40} {count}");
            }
        }
    }
}

fn print_counts(counts: &BTreeMap<&'static str, Counts>) {
    let mut rows: Vec<_> = counts.iter().collect();
    rows.sort_by(|(name_a, counts_a), (name_b, counts_b)| {
        counts_b
            .packets
            .cmp(&counts_a.packets)
            .then_with(|| name_a.cmp(name_b))
    });

    if rows.is_empty() {
        println!("  (none)");
    } else {
        for (name, counts) in rows {
            println!(
                "  {name:<12} {:>8} packets  {:>12} bytes",
                counts.packets, counts.bytes
            );
        }
    }
}

fn protocol_name(packet: &SlicedPacket<'_>) -> &'static str {
    match packet.transport {
        Some(TransportSlice::Tcp(_)) => "TCP",
        Some(TransportSlice::Udp(_)) => "UDP",
        Some(TransportSlice::Icmpv4(_)) => "ICMPv4",
        Some(TransportSlice::Icmpv6(_)) => "ICMPv6",
        None => match packet.net {
            Some(NetSlice::Ipv4(_)) => "IPv4",
            Some(NetSlice::Ipv6(_)) => "IPv6",
            None => "OTHER",
        },
    }
}

fn ip_endpoints(packet: &SlicedPacket<'_>) -> Option<(String, String)> {
    match packet.net.as_ref()? {
        NetSlice::Ipv4(ip) => Some((
            Ipv4Addr::from(ip.header().source()).to_string(),
            Ipv4Addr::from(ip.header().destination()).to_string(),
        )),
        NetSlice::Ipv6(ip) => Some((
            Ipv6Addr::from(ip.header().source()).to_string(),
            Ipv6Addr::from(ip.header().destination()).to_string(),
        )),
    }
}

fn analyze_reader<R: Read>(source: R) -> Result<Summary, Box<dyn Error>> {
    let mut reader = PcapReader::new(source)?;
    let header = reader.header();

    if header.datalink != DataLink::ETHERNET {
        return Err(format!(
            "unsupported link type {:?}; this prototype expects Ethernet PCAP files",
            header.datalink
        )
        .into());
    }

    let mut summary = Summary::default();
    while let Some(raw_packet) = reader.next_raw_packet() {
        let raw_packet = raw_packet?;
        if raw_packet.incl_len > header.snaplen {
            return Err("invalid PCAP packet: captured length exceeds snap length".into());
        }
        if raw_packet.incl_len > raw_packet.orig_len {
            return Err("invalid PCAP packet: captured length exceeds original length".into());
        }

        let truncated = raw_packet.orig_len > raw_packet.incl_len;
        let validation_snaplen = header.snaplen.max(raw_packet.orig_len);
        let packet = raw_packet.try_into_pcap_packet(header.ts_resolution, validation_snaplen)?;
        summary.add_packet(&packet.data, truncated);
    }
    Ok(summary)
}

fn analyze(path: &Path) -> Result<Summary, Box<dyn Error>> {
    analyze_reader(File::open(path)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(path) = args.next() else {
        eprintln!("Usage: {} <capture.pcap>", Path::new(&program).display());
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("Usage: {} <capture.pcap>", Path::new(&program).display());
        std::process::exit(2);
    }

    let summary = analyze(Path::new(&path))?;
    summary.print();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn udp_ipv4_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28_u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);

        let udp = &mut frame[34..];
        udp[0..2].copy_from_slice(&12345_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8_u16.to_be_bytes());
        frame
    }

    #[test]
    fn counts_udp_packets_bytes_and_ip_endpoints() {
        let frame = udp_ipv4_frame();
        let mut summary = Summary::default();

        summary.add_packet(&frame, false);

        assert_eq!(summary.packets, 1);
        assert_eq!(summary.bytes, frame.len() as u64);
        assert_eq!(summary.protocols["UDP"].packets, 1);
        assert_eq!(summary.protocols["UDP"].bytes, frame.len() as u64);
        assert_eq!(summary.endpoints["192.0.2.1"], 1);
        assert_eq!(summary.endpoints["198.51.100.2"], 1);
    }

    #[test]
    fn counts_truncated_frames_as_malformed() {
        let mut summary = Summary::default();

        summary.add_packet(&[0; 5], false);

        assert_eq!(summary.packets, 1);
        assert_eq!(summary.protocols["MALFORMED"].packets, 1);
    }

    #[test]
    fn accepts_and_reports_packets_truncated_to_capture_snaplen() {
        let mut frame = udp_ipv4_frame();
        frame.extend_from_slice(&[0; 10]);
        frame[16..18].copy_from_slice(&38_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&18_u16.to_be_bytes());
        let captured_len = 42_u32;
        let snaplen = captured_len;
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        pcap.extend_from_slice(&2_u16.to_le_bytes());
        pcap.extend_from_slice(&4_u16.to_le_bytes());
        pcap.extend_from_slice(&0_i32.to_le_bytes());
        pcap.extend_from_slice(&0_u32.to_le_bytes());
        pcap.extend_from_slice(&snaplen.to_le_bytes());
        pcap.extend_from_slice(&1_u32.to_le_bytes());
        pcap.extend_from_slice(&1_u32.to_le_bytes());
        pcap.extend_from_slice(&0_u32.to_le_bytes());
        pcap.extend_from_slice(&captured_len.to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&frame[..captured_len as usize]);

        let summary = analyze_reader(Cursor::new(pcap)).unwrap();

        assert_eq!(summary.packets, 1);
        assert_eq!(summary.bytes, u64::from(captured_len));
        assert_eq!(summary.truncated_packets, 1);
        assert_eq!(summary.protocols["TRUNCATED"].packets, 1);
    }
}
