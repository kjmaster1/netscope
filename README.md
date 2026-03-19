# netscope

A lightweight network packet analyser written in C. Captures raw packets at the driver level using libpcap, parses TCP/IP headers in C, and streams live traffic data to a self-hosted web dashboard over a WebSocket server — also implemented from scratch in C.

```
netscope v0.1
libpcap: Npcap version 1.87, based on libpcap version 1.10.6

Filter applied: not port 5353
Capturing... (Ctrl+C to stop)

[   1] TCP     162.159.135.234:443  ->  192.168.1.200:60753  (144 bytes)
[   2] UDP     192.168.1.200:52068  ->  104.29.135.84:19333  (255 bytes)
```

---

## What makes this novel

Most network analysis tools exist at one of two extremes — heavyweight GUI applications like Wireshark, or raw terminal output like tcpdump. There is no well-maintained open source tool that combines packet capture at the C level with a lightweight, self-contained web dashboard served from the same binary. netscope fills that gap.

The entire stack — packet capture, protocol parsing, WebSocket server, HTTP server, DNS resolution — is implemented in C with no external dependencies beyond libpcap/Npcap. The dashboard HTML is embedded directly in the binary at compile time.

---

## Features

- **Raw packet capture** via libpcap/Npcap at the network driver level
- **Protocol parsing** — manually parses Ethernet, IPv4, TCP, and UDP headers by casting raw byte pointers to packed structs
- **Live web dashboard** at `http://localhost:7681` — bandwidth chart, protocol breakdown, top connections, live packet feed
- **WebSocket server** implemented from scratch — including the SHA-1 + base64 handshake, binary frame encoding, and HTTP upgrade protocol
- **HTTP server** on the same port — serves the dashboard HTML embedded in the binary
- **Async DNS resolution** — background thread resolves IP addresses to hostnames with TTL-based cache expiry, non-blocking
- **BPF filter support** — driver-level packet filtering via Berkeley Packet Filter expressions
- **Capture summary** on exit — total packets, bytes, protocol breakdown, top 5 talkers by bytes

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  netscope                                        │
│                                                  │
│  Thread 1 — Capture                              │
│  ┌──────────────┐     ┌────────────────────────┐ │
│  │  capture.c   │───> │  analyser.c            │ │
│  │  libpcap     │     │                        │ │
│  │  raw packets │     │  Parse Ethernet        │ │
│  └──────────────┘     │  Parse IPv4            │ │
│                       │  Parse TCP/UDP         │ │
│                       └──────────┬─────────────┘ │
│                                  │               │
│                    ┌─────────────▼────────────┐  │
│                    │  Thread-safe ring buffer │  │
│                    │  (CRITICAL_SECTION mutex)│  │
│                    └─────────────┬────────────┘  │
│                                  │               │
│  Thread 2 — Server               │               │
│                       ┌──────────▼─────────────┐ │
│                       │  server.c              │ │
│                       │  HTTP server           │ │
│                       │  WebSocket server      │ │
│                       │  JSON serialiser       │ │
│                       └──────────┬─────────────┘ │
│                                  │               │
│  Thread 3 — DNS                  │               │
│  ┌──────────────┐                │               │
│  │  dns_cache.c │                │               │
│  │  getnameinfo │                │               │
│  │  TTL cache   │                │               │
│  └──────────────┘                │               │
└──────────────────────────────────┼───────────────┘
                                   │ WebSocket
                         ┌─────────▼──────────┐
                         │  dashboard         │
                         │  Bandwidth chart   │
                         │  Protocol bars     │
                         │  Top connections   │
                         │  Live packet feed  │
                         └────────────────────┘
```

### Key design decisions

**Packed structs for header parsing** — Ethernet, IPv4, TCP, and UDP headers are parsed by casting raw byte pointers directly to `#pragma pack(1)` structs. The struct fields line up exactly with the wire format. This is only possible in C — in Java or Python there is always an abstraction layer.

**Boundary tags for the WebSocket handshake** — The WebSocket upgrade requires computing SHA-1 of the client's key concatenated with a magic string, then base64-encoding the result. This is implemented using Windows CryptoAPI (`CryptCreateHash`, `CryptHashData`) rather than a third-party library.

**Thread-safe ring buffer** — Parsed packets are pushed into a fixed-size circular queue protected by a `CRITICAL_SECTION` mutex. The capture thread writes; the server thread reads. Dropped packets (queue full) are silently discarded — the dashboard shows live data, not a complete record.

**Async DNS with TTL expiry** — DNS lookups via `getnameinfo()` can take 100-500ms. Doing them synchronously in the packet callback would block the capture thread and drop packets. The DNS cache uses a background thread to resolve IPs and a 300-second TTL to re-resolve changed entries.

**BPF filtering at the driver level** — `pcap_compile()` and `pcap_setfilter()` install a Berkeley Packet Filter program at the driver level. Filtered packets are dropped before being copied from kernel space to user space — no CPU cost for traffic you don't care about.

**Self-hosted dashboard** — The HTTP and WebSocket server share the same TCP port. The server distinguishes between them by checking for the `Upgrade: websocket` header. The dashboard HTML is embedded as a C string constant generated at build time by `tools/embed_html.py`.

---

## Protocol parsing — how it works

libpcap delivers each packet as a raw byte array. We parse it by reading fixed offsets:

```
Bytes 0-13:    Ethernet header (14 bytes, always)
  0-5:         Destination MAC
  6-11:        Source MAC
  12-13:       EtherType (0x0800 = IPv4)

Bytes 14+:     IPv4 header (variable, minimum 20 bytes)
  14:          Version (top 4 bits) + IHL (bottom 4 bits)
  23:          Protocol (6=TCP, 17=UDP, 1=ICMP)
  26-29:       Source IP
  30-33:       Destination IP

Bytes 14+(IHL×4)+:  TCP or UDP header
  TCP 0-1:     Source port
  TCP 2-3:     Destination port
  UDP 0-1:     Source port
  UDP 2-3:     Destination port
```

IHL (Internet Header Length) is stored in the lower 4 bits of byte 14, in 32-bit word units. A standard IPv4 header has IHL=5, meaning 20 bytes. Options extend it up to 60 bytes. We always multiply IHL by 4 to get the byte offset of the transport layer.

---

## Building

**Prerequisites:** Windows, MSVC (Visual Studio 2019+), Npcap SDK

1. Install [Npcap](https://npcap.com) with WinPcap API-compatible mode
2. Download the [Npcap SDK](https://npcap.com#download) and extract to `C:\npcap-sdk-1.16`
3. Open an **x64 Native Tools Command Prompt for VS**

```cmd
git clone https://github.com/kjmaster1/netscope
cd netscope
python tools\embed_html.py
nmake
```

If your Npcap SDK is at a different path, update the `/I` and `/LIBPATH` entries in `Makefile`.

---

## Running

Must be run as Administrator — Npcap requires elevated privileges for packet capture.

```cmd
netscope.exe
netscope.exe "not port 5353"
netscope.exe "tcp port 443"
netscope.exe "host 8.8.8.8"
netscope.exe "udp and not port 5353"
```

Open `http://localhost:7681` in your browser for the live dashboard.

Press **Ctrl+C** to stop — prints a capture summary on exit.

### BPF filter examples

| Filter | Description |
|---|---|
| `tcp port 443` | HTTPS traffic only |
| `not port 5353` | Exclude mDNS noise |
| `host 8.8.8.8` | Traffic to/from specific host |
| `tcp and port 80` | Plain HTTP only |
| `udp` | UDP only |
| `not broadcast` | Exclude broadcast traffic |

---

## Capture summary

```
========================================
  netscope — capture summary
========================================
  Total packets : 781
  IPv4 parsed   : 221
  Total bytes   : 50541
  TCP           : 170
  UDP           : 51
  ICMP          : 0

  Top 5 talkers by bytes:
    192.168.1.200         18006 bytes  130 pkts
    104.26.10.65          12832 bytes  17 pkts
    51.132.193.104         7712 bytes  12 pkts
    162.159.135.234        4025 bytes  14 pkts
    162.247.243.29         2689 bytes   9 pkts
========================================
```

---

## Project structure

```
netscope/
├── src/
│   ├── main.c          # Entry point, stats tracking, signal handler
│   ├── capture.c       # libpcap interface and BPF filter support
│   ├── analyser.c      # Ethernet/IPv4/TCP/UDP header parser
│   ├── server.c        # WebSocket + HTTP server, JSON serialiser
│   └── dns_cache.c     # Async DNS resolution with TTL cache
├── include/
│   ├── capture.h
│   ├── analyser.h
│   ├── server.h
│   └── dns_cache.h
├── dashboard/
│   └── index.html      # Live dashboard (embedded into binary at build time)
├── tools/
│   └── embed_html.py   # Converts dashboard HTML to C string header
└── Makefile
```

---

## Limitations and future work

- **Windows only** — uses Npcap and Windows CryptoAPI. Linux support requires replacing these with POSIX equivalents (`mmap`, OpenSSL SHA-1 or a single-file implementation)
- **IPv4 only** — IPv6 parsing not yet implemented
- **No packet reassembly** — TCP streams are shown as individual segments, not reassembled application-layer data
- **Single interface** — captures one interface at a time
- **No PCAP file export** — capture sessions cannot be saved for offline analysis
