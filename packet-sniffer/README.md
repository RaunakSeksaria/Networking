# Packet Sniffer

A terminal packet sniffer built on libpcap. It captures live traffic on a chosen interface and
decodes each frame layer by layer, from the Ethernet header through the network layer, the transport
layer, and finally a guess at the application protocol based on port numbers. Captured packets are
kept in memory so a session can be inspected in detail after the fact.

The tool is a passive observer. It never sends, injects, or crafts packets.

## Building and running

```bash
make            # produces ./cshark
sudo ./cshark   # packet capture requires root
```

Requires the libpcap headers: `libpcap-dev` on Debian or Ubuntu, `libpcap-devel` on Fedora.

## Usage

On startup the tool lists the available capture interfaces and asks you to pick one. The main menu
then offers:

1. **Start sniffing, all packets.** Live decode of everything on the interface.
2. **Start sniffing, with filters.** Same, restricted to one protocol.
3. **Inspect last session.** Browse and drill into packets captured by the most recent run.
4. **Exit.**

**Ctrl+C** stops an active capture and returns to the menu rather than killing the program.
**Ctrl+D** exits cleanly from anywhere, including mid capture.

### Filters

Menu choices map to BPF expressions compiled by libpcap:

| Choice | Filter |
| --- | --- |
| HTTP | `tcp port 80` |
| HTTPS | `tcp port 443` |
| DNS | `udp port 53 or tcp port 53` |
| ARP | `arp` |
| TCP | `tcp` |
| UDP | `udp` |

### Inspecting a session

Each capture replaces the previous session, freeing the old packets. Up to `MAX_PACKETS` (10000)
frames are stored, with the bytes deep copied so they survive after libpcap reuses its buffers.

Inspection lists the stored packets with ID, timestamp, length, and basic addressing, then lets you
select one for a full breakdown: every header field with both its raw hexadecimal value and its
decoded meaning, followed by a hex dump of the entire frame.

## What gets decoded

**Link layer.** Source and destination MAC, EtherType, with IPv4, IPv6, and ARP identified by name.

**Network layer.** For IPv4: addresses, protocol, TTL, identification, total length, header length,
and decoded fragmentation flags. For IPv6: addresses, next header, hop limit, traffic class, flow
label, and payload length. For ARP: decoded operation, sender and target addresses at both layers,
and the hardware and protocol type fields.

**Transport layer.** For TCP: ports, sequence and acknowledgement numbers, decoded flag list, window
size, checksum, and data offset. For UDP: ports, length, and checksum.

**Application layer.** HTTP, HTTPS, and DNS are recognised by port number, anything else is reported
as unknown. The first 64 payload bytes are shown as a combined hexadecimal and ASCII dump.

## Traffic generators

The scripts under `tests/` generate traffic to observe. They are generators, not assertions: run one
in a second terminal while a capture is active, then compare what the sniffer prints against
Wireshark watching the same interface.

```bash
make test              # list the available generators
make test-basic        # ping and HTTP HEAD
make test-l2-l3        # IPv4, IPv6, and ARP
make test-l4           # TCP and UDP
make test-payload      # HTTP, HTTPS, and DNS payloads
make test-mixed        # combined traffic for session inspection
make test-filters      # one burst per supported filter
make test-robustness   # edge cases
```

Two optional environment variables gate the steps that need real network access:

```bash
IFACE=wlan0 GATEWAY=192.168.1.1 make test-l2-l3
```

Without `IFACE` the scripts fall back to loopback traffic only, and without `GATEWAY` the ARP steps
are skipped.

## Design notes

TCP and UDP headers are read by explicit byte offset through small `read_u16` and `read_u32` helpers
rather than by casting to `struct tcphdr` or `struct udphdr`. This sidesteps the BSD versus Linux
field naming split entirely and makes the unaligned reads safe. Ethernet, IPv4, IPv6, and ARP still
use the kernel structs, where the layouts are unambiguous.

Capture runs in non blocking mode, driven by a `select()` over both the pcap file descriptor and
stdin. Watching stdin is what makes Ctrl+D work during a capture, since EOF arrives as a readable
event rather than a signal. `SIGINT` sets a flag and calls `pcap_breakloop`, which is how Ctrl+C
returns to the menu instead of terminating the process.

Decoding exists in two parallel renderers over the same bytes: a compact one for the live feed and a
detailed one for session inspection. Adding a protocol means updating both.

## Known limitations

- **Ethernet link layer only.** Interfaces that are not Ethernet framed, such as `bluetooth-monitor`,
  will produce filter or parse errors.
- **IPv6 extension headers are not followed.** The transport header is read directly after the
  40 byte base header, so a packet carrying extension headers will be misparsed at layer 4.
- **Application protocols are inferred from port numbers alone.** There is no payload inspection, so
  a service on a nonstandard port is reported as unknown.
- **The application layer line only prints when a payload is present.** A packet with no payload,
  such as a bare SYN, shows no protocol name.
- **Sessions live in memory only.** Nothing is written to disk, and captures do not survive exit.
