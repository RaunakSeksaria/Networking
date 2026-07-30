# C-Shark: The Terminal Packet Sniffer

## Build Instructions

```bash
cd project-b-networking
make
```

## Run Instructions

```bash
sudo ./cshark
```

**Note:** Root/sudo privileges are required for packet capture.

## Usage

1. Select a network interface from the displayed list
2. Choose capture mode:
   - Option 1: Capture all packets
   - Option 2: Capture with protocol filter (HTTP, HTTPS, DNS, ARP, TCP, UDP)
3. Press **Ctrl+C** to stop packet capture and return to menu
4. Press **Ctrl+D** to exit the program completely at any time
5. Use **"Inspect Last Session"** to analyze captured packets

## Assumptions

- **Platform:** Linux/Ubuntu environment assumed
- **Dependencies:** libpcap library installed on system
- **IPv6:** Extension headers are not processed (direct L4 access)
- **TCP/UDP:** __FAVOR_BSD macro assumed for struct definitions
- **Session Storage:** In-memory only (not persisted to disk)
- **Packet Limit:** Maximum 10,000 packets per session
- **Interface Support:** Some interfaces (e.g., bluetooth-monitor) may not support all filter types

## Known Limitations

- IPv6 extension headers are skipped (only basic header processed)
- Non-Ethernet link-layer interfaces may produce filter errors
- Session data is lost when program exits
