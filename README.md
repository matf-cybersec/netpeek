# netpeek

A lightweight command-line network capture analyzer written in Rust. netpeek reads offline PCAP files, summarizes packet and byte counts, identifies network protocols, and highlights the most frequently observed IP addresses.

The project focuses on packet header inspection and network traffic analysis without exposing packet payload contents.

## Features

- PCAP Parsing
- Protocol Identification
- Traffic Statistics
- IP Endpoint Analysis
- Truncation Detection
- Malformed Packet Handling

## Current limitations:

- PCAP-NG (.pcapng) is not supported.
- Non-Ethernet link types are not supported.
- Live packet capture is not implemented.
- TCP stream reconstruction is not implemented.
- Packet payload contents and hostname resolution are not supported.

## Requirements

- Rust and Cargo
- A classic `.pcap` capture containing Ethernet frames

PCAP-NG files (often `.pcapng`) and non-Ethernet link types are not supported
yet.

## Build and run

From the project directory:

```sh
cargo run -- /path/to/capture.pcap
```

For example, if the capture is in Downloads:

```sh
cargo run -- ~/Downloads/sample-full.pcap
```

Cargo compiles the program the first time and reuses the build on later runs.
The `--` separates Cargo's own options from arguments passed to `netpeek`.

## Make a capture

Capturing may require administrator privileges. Choose an interface connected
to the network you want to observe. The examples capture 50 packets with a
large snapshot length to reduce truncation.

### macOS

```sh
sudo tcpdump -D
```

Choose the active interface from the list (often `en0` for Wi-Fi), then run:

```sh
sudo tcpdump -i en0 -s 65535 -c 50 -w ~/Downloads/sample-full.pcap
```

### Linux

List interfaces:

```sh
sudo tcpdump -D
```

Choose the active interface (for example, `wlan0` for Wi-Fi or `eth0` for
Ethernet), then capture:

```sh
sudo tcpdump -i wlan0 -s 65535 -c 50 -w ~/Downloads/sample-full.pcap
```

Replace `wlan0` with the interface name shown on your system. If you do not
have `tcpdump`, install it using your distribution's package manager.

### Windows

Install Wireshark, which includes `dumpcap`, and allow its installer to
configure packet-capture permissions. In PowerShell, list capture interfaces:

```powershell
dumpcap -D
```

Use the interface number shown by that command (for example, `1`) to capture:

```powershell
dumpcap -i 1 -s 65535 -c 50 -w "$env:USERPROFILE\Downloads\sample-full.pcap"
```

If PowerShell cannot find `dumpcap`, run the command from Wireshark's
installation folder or add that folder to `PATH`. Replace `1` with the
interface number for the network connection you want to capture.

On all platforms, `-s 65535` asks the capture tool to save a large portion of
each packet, reducing the chance that headers are cut off. Once the requested
packets have been captured, analyze the resulting file from the project
directory, for example:

```sh
cargo run -- ~/Downloads/sample-full.pcap
```

Captures can contain sensitive information; only capture traffic you are
authorized to access and keep the file private.

## How it works

1. `netpeek` opens the path supplied on the command line and reads the PCAP
   file header. It checks that the capture uses Ethernet frames.
2. It reads each packet record, including both the captured length and the
   original on-the-wire length.
3. It parses the captured bytes as an Ethernet frame, then examines available
   IP and transport headers. TCP, UDP, ICMPv4, and ICMPv6 are reported when
   recognized. IP packets without a recognized transport header are reported
   as IPv4 or IPv6; other successfully parsed frames are reported as OTHER.
4. It adds packet and captured-byte counts, and records the IP source and
   destination addresses when available. It then prints protocol totals and
   the ten most frequent IP endpoints.

The parser uses the `pcap-file` crate to read classic PCAP records and
`etherparse` to decode packet headers.

## Understanding the output

For example:

```text
Packets: 50
Captured bytes: 4346
Truncated packets: 33

Protocols:
  TRUNCATED          33 packets          3168 bytes
  UDP                14 packets           980 bytes
  TCP                 3 packets           198 bytes

Top IP endpoints:
  192.168.15.10                            17
  206.247.42.14                            17
```

- **Packets** is the number of packet records in the capture.
- **Captured bytes** sums only the packet bytes saved in the file; it excludes
  PCAP record headers and any bytes that were not captured.
- **Truncated packets** counts records where the original packet was longer
  than the captured packet. These packets are still included in the totals.
- **Protocols** counts packets the parser could classify. A truncated packet
  can still be classified if its captured portion includes enough headers.
  When parsing fails for a truncated packet, it is listed as `TRUNCATED`;
  when parsing fails for a non-truncated packet, it is listed as `MALFORMED`.
- **Top IP endpoints** counts address appearances in decoded packets: each
  decoded source and destination adds one. Packets without decodable IP
  headers do not contribute endpoints.

Truncated packets can have enough bytes for IP addresses but not enough for a
transport protocol, or enough for neither. Therefore, a truncated capture may
show fewer protocol and endpoint details than a full-length capture.

## Tests

Run the unit tests with:

```sh
cargo test
```
