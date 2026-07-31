# Networking

Two independent C networking projects: a reliable transport protocol built on top of UDP, and a
terminal packet sniffer built on libpcap. Each is self contained, with its own Makefile and README.

| Project | What it is |
| --- | --- |
| [reliable-udp-transport](reliable-udp-transport/) | A reliable, connection oriented byte stream layered over UDP datagrams. Three way handshake, four way teardown, sliding window with per packet retransmission timers, cumulative acknowledgements, and receiver driven flow control. Supports file transfer and an interactive chat mode. |
| [packet-sniffer](packet-sniffer/) | A live packet capture tool that decodes each frame layer by layer, from Ethernet through IPv4, IPv6, and ARP, then TCP and UDP, then an application guess from the port. Supports BPF protocol filters and offline inspection of the last capture session. |

## What these demonstrate

Socket programming with `sendto` and `recvfrom` over `AF_INET`/`SOCK_DGRAM`, multiplexed I/O with
`select()` over sockets and stdin without threads, sliding window flow and congestion style control,
retransmission timers and cumulative acknowledgement handling, out of order packet buffering, raw
packet capture with libpcap, BPF filter compilation, and protocol header parsing straight from wire
bytes with explicit attention to network byte order and unaligned reads.

## Building

Both projects need `gcc` and `make`. The packet sniffer additionally needs the libpcap headers.

```bash
# Debian or Ubuntu
sudo apt install build-essential libpcap-dev

# Fedora
sudo dnf install gcc make libpcap-devel
```

Then build whichever you want:

```bash
make -C reliable-udp-transport   # produces ./client and ./server
make -C packet-sniffer           # produces ./cshark
```

Both compile clean under `-Wall -Wextra`.

Packet capture requires root, so the sniffer runs as `sudo ./cshark`. The transport binaries need no
special privileges.

## Layout

```
reliable-udp-transport/
    sham.h        wire header, protocol constants, shared declarations
    sham.c        wire serialization, sliding window, retransmission, flow control
    client.c      connection setup, file sender, chat client
    server.c      connection accept, file receiver, chat server
packet-sniffer/
    main.c        interface selection and menu
    sniff.c       capture lifecycle, signal and EOF handling
    decode.c      protocol dissection, live and detailed renderers
    session.c     in memory storage of the last capture session
    util.c        device listing, hex dumps, MAC formatting
    tests/        traffic generators for manual verification
```
