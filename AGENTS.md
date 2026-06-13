# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

A Rust-based network tools project implementing low-level network protocols (ICMP, IPv4) from scratch, used as coursework for information/media/communications engineering. The current branch (`feature-IPv4PacketHeader`) is working on IPv4 packet header parsing.

## Crate Structure

This repo uses **independent Cargo workspaces** (no top-level `Cargo.toml`). Each subdirectory is a standalone crate:

- **`utility/`** — shared library (`utility` crate) used by all network tools. Contains packet builders, checksum functions, and socket utilities.
- **`ping/`** — ping implementation using `pnet` for transport-layer raw sockets
- **`traceroute/`** — traceroute implementation using `libpcap` on interface `en0`
- **`search-mtu/`** — Path MTU Discovery tool using `libpcap` on interface `en0`
- **`test-libpcap/`** — sandbox for libpcap experiments
- **`test-parallel/`** — sandbox for Rust threading/channel experiments
- **`raw_icmp_recv.c`** — C reference for raw ICMP packet receiving

## Build & Run

All tools use raw sockets or libpcap and **require root/sudo**.

```bash
# Build a specific crate
cd ping && cargo build
cd traceroute && cargo build
cd search-mtu && cargo build

# Run (all tools take an IPv4 address as argument)
sudo ./ping/target/debug/ping 8.8.8.8
sudo ./traceroute/target/debug/traceroute 8.8.8.8
sudo ./search-mtu/target/debug/search-mtu 8.8.8.8

# Build and run in one step
cd ping && cargo build && sudo ./target/debug/ping 8.8.8.8

# C reference implementation
gcc raw_icmp_recv.c -o raw_icmp_recv && sudo ./raw_icmp_recv
```

## Architecture: `utility` Crate

`utility/src/lib.rs` is the core shared library. Key public API:

| Function / Type | Purpose |
|---|---|
| `check_ipv4_address(input)` | Validates and parses IPv4 string into `Ipv4Addr` |
| `get_source_ipv4(dst)` | Determines outbound source IP by connecting a UDP socket |
| `CreateIcmpPacketArgs` + `create_icmp_packet(args)` | Builds a raw ICMP packet (`Vec<u8>`) with checksum |
| `CreateIpv4PacketArgs` + `create_ipv4_packet(args)` | Builds a raw IPv4 packet with ICMP payload and checksum |
| `create_checksum(vec)` | Internet checksum (one's complement sum, then bitwise NOT) |
| `check_checksum(bytes)` | Verifies an existing checksum; valid result is `0xffff` |
| `create_socket()` | Opens a Layer 3 raw socket via `pnet` (`TransportChannelType::Layer3`) |
| `send_ipv4_packet(sender, dst, bytes)` | Sends an assembled IPv4 packet |
| `calc_stats(rtts)` | Returns `(min, avg, max, stddev)` for RTT measurements |

The `CreateIpv4PacketArgs` and `CreateIcmpPacketArgs` structs implement `Default` — only override fields you need.

## Key Implementation Details

**Packet reception split by tool:**
- `ping` uses `pnet::transport::ipv4_packet_iter` — simpler API, no Ethernet header
- `traceroute` / `search-mtu` use `libpcap` directly on `en0` — raw Ethernet frames, so packet parsing starts at byte 0 (Ethernet) → byte 14 (IPv4) → byte 34 (ICMP)

**IPv4 total-length quirk:** The kernel may report `ip_total_length` as 0 for locally received packets. `ping/src/main.rs` works around this by patching bytes `[2..4]` of the received IPv4 header with the actual received length before checksum verification.

**Thread model in `traceroute`/`search-mtu`:** A dedicated `libpcap` receive thread starts first and signals `pcap_ready` (AtomicBool) before the send loop begins. Sent packet metadata is shared via `Arc<Mutex<Vec<SentPacketInfo>>>` to correlate received ICMP replies by `identification` + `icmp_seq`.

**ICMP error payload parsing:** For ICMP type 11 (TTL exceeded) and type 3 code 4 (fragmentation needed), the error payload contains the original IPv4 header + first 8 bytes of original ICMP. `analyze_err_icmp_payload()` in `traceroute` and `search-mtu` extracts these to match sent packets.

**Network interface:** `traceroute` and `search-mtu` hardcode `"en0"` as the capture interface. Change this if running on a non-macOS machine or different interface.

## Dependencies

- `pnet = "0.35"` — raw socket transport, IPv4/ICMP packet types (`ping`, `utility`)
- `libpcap = "0.1.7"` — raw packet capture at Ethernet level (`traceroute`, `search-mtu`)
- `rand = "0.9.2"` — random ICMP identification numbers
- `regex = "1.8"` — IPv4 address validation (`utility`)
- `bytes = "1"` — bit/byte manipulation (`utility`)
