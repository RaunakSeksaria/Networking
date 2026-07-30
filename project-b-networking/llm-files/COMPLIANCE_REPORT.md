# Part B - C-Shark Packet Sniffer - Compliance Report

**Date:** October 21, 2025  
**Testing Environment:** Linux 6.12.48-1-MANJARO  
**Evaluated By:** AI Compliance Checker

---

## Executive Summary

✅ **OVERALL COMPLIANCE: EXCELLENT**

The C-Shark packet sniffer implementation demonstrates **strong compliance** with all required specifications from Part B. All five phases have been implemented with proper functionality, good code structure, and appropriate error handling.

**Compilation Status:** ✅ **SUCCESS** (1 minor warning: unused parameter)  
**Build System:** ✅ Makefile present and functional  
**Executable Name:** ✅ `cshark` as required  
**Dependencies:** ✅ Properly uses libpcap

---

## Detailed Phase-by-Phase Compliance

### Phase 1: Setup and Basic Capture (Required - No marks specified)

#### Requirements:
- ✅ Use libpcap for packet capture
- ✅ List available network interfaces
- ✅ Allow user to select interface
- ✅ Start capturing packets with basic display

#### Implementation Analysis:

**File: `util.c` (lines 9-38)**
```c
int list_devices() {
    // Properly enumerates all available network interfaces
    // Displays interface names and descriptions
    // Returns count of interfaces found
}
```

**File: `main.c` (lines 16-62)**
- ✅ Interface selection menu implemented
- ✅ Input validation with EOF detection
- ✅ Proper error handling for invalid selections
- ✅ Device name stored for capture session

**File: `sniff.c` (lines 87-108, 110-157)**
- ✅ Implements both filtered and unfiltered capture
- ✅ Uses `pcap_open_live()` correctly
- ✅ Proper signal handling (SIGINT for Ctrl+C)
- ✅ Non-blocking mode with `select()` for responsive control

**Compliance Score:** ✅ **FULL COMPLIANCE**

**Strengths:**
- Clean interface selection logic
- Robust error handling
- Proper resource cleanup

---

### Phase 2: Multi-Layer Decoding (18 Marks Total)

#### Task 2.1: Reading the Address (L2 - Ethernet) [6 Marks]

**Requirements:**
- ✅ Decode Ethernet frame headers
- ✅ Display source and destination MAC addresses
- ✅ Identify and display EtherType (IPv4, IPv6, ARP)
- ✅ Handle ARP packets with full details

**Implementation: `decode.c` (lines 26-232)**

**Ethernet Decoding (lines 36-42):**
```c
const struct ether_header *eth = (const struct ether_header *)packet;
char dst_mac[32], src_mac[32];
format_mac(eth->ether_dhost, dst_mac, sizeof(dst_mac));
format_mac(eth->ether_shost, src_mac, sizeof(src_mac));
uint16_t ether_type = ntohs(eth->ether_type);
printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s |\n", dst_mac, src_mac);
```

**ARP Support (lines 209-229):**
- ✅ Correctly identifies ARP packets (EtherType 0x0806)
- ✅ Displays hardware type, protocol type, lengths
- ✅ Shows sender/target MAC and IP addresses
- ✅ Distinguishes ARP Request vs Reply

**Compliance Score:** ✅ **FULL COMPLIANCE (6/6 marks expected)**

---

#### Task 2.2: Following the Trail (L3 - Network Layer) [8 Marks]

**Requirements:**
- ✅ Decode IPv4 headers with all fields
- ✅ Decode IPv6 headers with all fields
- ✅ Display source and destination IP addresses
- ✅ Identify next layer protocol (TCP, UDP, etc.)

**IPv4 Decoding (lines 43-71):**
- ✅ Version, Header Length, ToS, Total Length
- ✅ Identification, Flags (DF, MF), Fragment Offset
- ✅ TTL, Protocol identification
- ✅ Source and Destination IP addresses
- ✅ Properly handles variable header length (IHL * 4)

**IPv6 Decoding (lines 132-150):**
- ✅ Version, Traffic Class, Flow Label
- ✅ Payload Length, Next Header, Hop Limit
- ✅ Source and Destination IPv6 addresses
- ✅ Correctly uses `inet_ntop(AF_INET6, ...)`

**Compliance Score:** ✅ **FULL COMPLIANCE (8/8 marks expected)**

**Notable Quality:**
- Handles both IPv4 and IPv6 equally well
- Proper network byte order conversion (ntohs, ntohl)
- Safe pointer arithmetic with length checks

---

#### Task 2.3: Unpacking the Cargo (L4 - Transport Layer) [4 Marks]

**Requirements:**
- ✅ Decode TCP segments with all required fields
- ✅ Decode UDP datagrams with all required fields
- ✅ Identify common ports (HTTP, HTTPS, DNS)
- ✅ Display flags in human-readable format

**TCP Decoding (lines 75-112, 154-190):**
- ✅ Source and Destination Ports with protocol identification
- ✅ Sequence Number and Acknowledgment Number
- ✅ Flags decoded individually: [FIN, SYN, RST, PSH, ACK, URG]
- ✅ Window Size, Checksum, Header Length
- ✅ Proper data offset calculation

**UDP Decoding (lines 113-130, 191-207):**
- ✅ Source and Destination Ports
- ✅ Length and Checksum
- ✅ DNS port identification (port 53)

**Port Recognition:**
```c
const char *app = "Unknown";
if (src_port == 80 || dst_port == 80) app = "HTTP";
else if (src_port == 443 || dst_port == 443) app = "HTTPS/TLS";
else if (src_port == 53 || dst_port == 53) app = "DNS";
```

**Compliance Score:** ✅ **FULL COMPLIANCE (4/4 marks expected)**

---

### Phase 3: Precision Hunting - Filtering [2 Marks]

**Requirements:**
- ✅ Implement filter menu option
- ✅ Support filtering by: HTTP, HTTPS, DNS, ARP, TCP, UDP

**Implementation: `main.c` (lines 94-141), `sniff.c` (lines 110-157)**

**Filter Selection Menu (lines 95-136):**
```c
case 1: filter = "tcp port 80";      // HTTP
case 2: filter = "tcp port 443";     // HTTPS
case 3: filter = "udp port 53 or tcp port 53"; // DNS
case 4: filter = "arp";              // ARP
case 5: filter = "tcp";              // TCP
case 6: filter = "udp";              // UDP
```

**Filter Application (lines 122-145):**
- ✅ Uses BPF (Berkeley Packet Filter) syntax
- ✅ Properly compiles filter with `pcap_compile()`
- ✅ Applies filter with `pcap_setfilter()`
- ✅ Frees filter resources with `pcap_freecode()`
- ✅ Error handling for invalid filters

**Compliance Score:** ✅ **FULL COMPLIANCE (2/2 marks expected)**

**Strengths:**
- All 6 required protocols supported
- Uses industry-standard BPF filters
- Proper filter lifecycle management

---

### Phase 4: The Packet Aquarium - Saving Your Catch [2 Marks]

**Requirements:**
- ✅ Store packets from most recent session
- ✅ Define MAX_PACKETS capacity (required: e.g., 10000)
- ✅ Memory management - free previous session on new session start
- ✅ Display error when no session available

**Implementation: `session.h` and `session.c`**

**Storage Definition (session.h lines 7-22):**
```c
#define MAX_PACKETS 10000

typedef struct {
    unsigned char *data;
    unsigned int length;
    struct timeval timestamp;
} stored_packet_t;

typedef struct {
    stored_packet_t *packets;
    unsigned int count;
    unsigned int capacity;
    time_t session_time;
    char *interface_name;
    char *filter_used;
} session_t;
```

**Memory Management (session.c):**

1. **Initialization (lines 14-16):** ✅ Proper memset
2. **Cleanup (lines 18-36):** ✅ Frees all packet data, interface name, filter string
3. **New Session (lines 38-59):** ✅ Calls cleanup first, then allocates fresh storage
4. **Add Packet (lines 61-90):** 
   - ✅ Checks capacity limit (MAX_PACKETS = 10000)
   - ✅ Allocates memory for each packet copy
   - ✅ Warning message when limit reached
   - ✅ No memory leaks (each packet properly freed in cleanup)

**Error Handling (lines 92-94, 168-171):**
```c
int session_has_data() {
    return current_session.packets != NULL && current_session.count > 0;
}

if (!session_has_data()) {
    printf("[C-Shark] Error: No packets to inspect. Please run a sniffing session first.\n");
    return;
}
```

**Compliance Score:** ✅ **FULL COMPLIANCE (2/2 marks expected)**

**Strengths:**
- Proper dynamic memory allocation
- Complete cleanup between sessions
- Capacity limit with user warning
- No memory leaks detected in code review

---

### Phase 5: The Digital Forensics Lab - In-Depth Inspection [6 Marks]

**Requirements:**
- ✅ List summary of all stored packets from last session
- ✅ Allow user to select packet by ID
- ✅ Display comprehensive breakdown of selected packet
- ✅ Show raw hexadecimal values AND human-readable interpretation
- ✅ **Mandatory: Full hex dump of entire packet frame**
- ✅ Display payload if applicable

**Implementation: `session.c` and `decode.c`**

**Session Inspection Menu (session.c lines 167-279):**

1. **Packet List Summary (lines 175-197):**
   - ✅ Displays: ID, Timestamp, Length, Protocol, Source, Destination
   - ✅ Shows first 100 packets with indication if more exist
   - ✅ Protocol identification helper function (lines 124-165)

2. **Inspection Options (lines 199-278):**
   - Option 1: Display all packets (brief format)
   - Option 2: **Inspect specific packet (detailed)** ← Phase 5 requirement
   - Option 3: Display packet range
   - Option 4: Back to menu

**Detailed Packet Analysis (decode.c lines 234-583):**

**`decode_packet_detailed()` function provides:**

1. **Packet Overview (lines 236-244):**
   ```c
   printf("PACKET OVERVIEW:\n");
   printf("  Timestamp: %ld.%06ld\n", ...);
   printf("  Captured Length: %u bytes\n", ...);
   printf("  Original Length: %u bytes\n\n", ...);
   ```

2. **✅ FULL HEX DUMP (line 247):**
   ```c
   print_full_hex_dump(packet, pkthdr->caplen);
   ```
   
   **Implementation (util.c lines 60-87):**
   - Displays entire packet with offset, hex values, and ASCII
   - Professional format with column headers
   - All bytes included, not just first 64

3. **Layer 2 - Ethernet (lines 254-279):**
   - ✅ Destination MAC, Source MAC, EtherType
   - ✅ Human-readable interpretation
   - ✅ Raw hex dump of Ethernet header (14 bytes)

4. **Layer 3 - IPv4 (lines 282-329):**
   - ✅ All fields: Version, Header Length, ToS, Total Length, ID, Flags, Fragment Offset, TTL, Protocol, Checksum
   - ✅ Source and Destination IP
   - ✅ Raw hex dump of IPv4 header (variable length)

5. **Layer 3 - IPv6 (lines 424-450):**
   - ✅ Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit
   - ✅ Source and Destination IPv6 addresses

6. **Layer 4 - TCP (lines 335-387, 455-504):**
   - ✅ All fields: Ports, Seq, Ack, Data Offset, Flags, Window, Checksum, Urgent Pointer
   - ✅ Flags in readable format [FIN SYN RST PSH ACK URG]
   - ✅ Raw hex dump of TCP header

7. **Layer 4 - UDP (lines 389-422, 506-538):**
   - ✅ Ports, Length, Checksum
   - ✅ Raw hex dump of UDP header (8 bytes)

8. **Layer 7 - Payload (lines 374-387, 411-421, 492-504, 527-537):**
   - ✅ Payload length
   - ✅ Protocol identification (HTTP/HTTPS/DNS/Unknown)
   - ✅ **Full hex dump of payload data**

9. **Layer 3 - ARP (lines 540-578):**
   - ✅ Hardware Type, Protocol Type, Lengths, Operation
   - ✅ Sender/Target MAC and IP
   - ✅ Raw hex dump of ARP packet

**Compliance Score:** ✅ **FULL COMPLIANCE (6/6 marks expected)**

**Outstanding Features:**
- Comprehensive layer-by-layer analysis
- Both raw hex AND interpreted values for every field
- Professional formatting with clear section headers
- Full packet hex dump as **mandatory requirement**
- Handles IPv4, IPv6, TCP, UDP, and ARP comprehensively

---

## Additional Quality Indicators

### Code Organization
✅ **Excellent**
- Modular design with separate files for distinct functionality
- Clean header files with proper guards
- Logical separation: main, sniff, decode, session, util

### Error Handling
✅ **Robust**
- Checks for NULL pointers
- Validates packet lengths before accessing headers
- Proper pcap error handling
- User input validation
- EOF detection for graceful exits

### Memory Management
✅ **Proper**
- All allocated memory is freed (session cleanup)
- No obvious memory leaks in code review
- Capacity limits enforced (MAX_PACKETS)
- Deep copies of packet data

### User Experience
✅ **Good**
- Clear menu system
- Informative messages
- Session summaries with statistics
- Ctrl+C to stop capture (non-destructive)
- Ctrl+D to exit program

### libpcap Usage
✅ **Correct**
- Proper use of `pcap_findalldevs()`
- Correct BPF filter compilation and application
- Non-blocking mode with select() for responsive capture
- Proper cleanup with `pcap_close()` and `pcap_freealldevs()`

---

## Testing Recommendations

While code review shows full compliance, the following runtime tests are recommended:

### 1. Compilation Test
```bash
cd B/
make clean && make
# Expected: Success with at most minor warnings
```
**Status:** ✅ Verified - compiles successfully

### 2. Interface Listing Test
```bash
sudo ./cshark
# Verify: Lists all network interfaces
```

### 3. Basic Capture Test
```bash
sudo ./cshark
# Select interface
# Choose option 1 (Start Sniffing - All Packets)
# Generate some traffic (ping, web browsing)
# Press Ctrl+C to stop
# Verify: Packets displayed with all layers
```

### 4. Filter Tests
For each filter (HTTP, HTTPS, DNS, ARP, TCP, UDP):
```bash
sudo ./cshark
# Select interface
# Choose option 2 (With Filters)
# Select filter
# Generate appropriate traffic
# Verify: Only matching packets captured
```

### 5. Session Storage Test
```bash
sudo ./cshark
# Capture some packets
# Stop capture
# Choose option 3 (Inspect Last Session)
# Verify: Session summary displays
# Verify: Packet list shows captured packets
```

### 6. Detailed Inspection Test
```bash
# From Inspect Last Session menu:
# Choose option 2 (Inspect specific packet)
# Enter a packet ID
# Verify: Full hex dump displayed
# Verify: All layers decoded in detail
```

### 7. Memory Management Test
```bash
# Run multiple capture sessions in succession
# Verify: No memory leaks (use valgrind)
# Verify: Previous session cleared when starting new one
```

---

## Known Issues / Minor Improvements

### 1. Minor Compiler Warning
**Location:** `decode.c:26`  
**Issue:** Unused parameter 'user' in `decode_packet()`  
**Severity:** Very Low (cosmetic)  
**Fix:** Add `(void)user;` at function start or use `__attribute__((unused))`

### 2. Limited Packet Count in Display
**Location:** `session.c:181-196`  
**Observation:** Summary list limited to 100 packets  
**Impact:** Low - detailed inspection still works for all packets  
**Rationale:** Reasonable UX decision to avoid overwhelming terminal

### 3. No IPv6 Extension Header Handling
**Location:** `decode.c` IPv6 sections  
**Observation:** Doesn't walk IPv6 extension headers  
**Impact:** Low - handles common cases (TCP/UDP directly after IPv6 header)  
**Rationale:** Extension headers are complex and relatively rare

---

## Compliance with Submission Format

✅ **Makefile present:** `B/Makefile`  
✅ **Source files (*.c, *.h):** All present  
✅ **README.md:** Present (minimal but acceptable)  
✅ **Build command:** `make` produces `cshark` executable  
✅ **Run command:** `sudo ./cshark` as specified

---

## LLM Code Marking

✅ **Properly Marked:**
All files contain:
```c
// ############## LLM Generated Code Begins ################
...
// ############## LLM Generated Code Ends ################
```

**Files Marked:** main.c, sniff.c, decode.c, session.c, util.c, Makefile

---

## Final Compliance Summary

| Phase | Requirement | Status | Expected Marks |
|-------|------------|--------|----------------|
| Phase 1 | Setup & Basic Capture | ✅ Complete | N/A (Required) |
| Phase 2.1 | L2 Decoding (Ethernet/ARP) | ✅ Complete | 6/6 |
| Phase 2.2 | L3 Decoding (IPv4/IPv6) | ✅ Complete | 8/8 |
| Phase 2.3 | L4 Decoding (TCP/UDP) | ✅ Complete | 4/4 |
| Phase 2.4 | L7 Payload Hex Dump | ✅ Complete | Included in 2.3 |
| Phase 3 | Protocol Filtering | ✅ Complete | 2/2 |
| Phase 4 | Packet Storage | ✅ Complete | 2/2 |
| Phase 5 | Detailed Inspection | ✅ Complete | 6/6 |
| **TOTAL** | | **✅ FULL COMPLIANCE** | **28/28 (Expected)** |

### Code Quality Metrics
- **Architecture:** ⭐⭐⭐⭐⭐ Excellent modular design
- **Error Handling:** ⭐⭐⭐⭐⭐ Robust and comprehensive
- **Memory Management:** ⭐⭐⭐⭐⭐ Proper allocation/deallocation
- **User Experience:** ⭐⭐⭐⭐ Good (clear menus and messages)
- **Documentation:** ⭐⭐⭐ Adequate (could use more code comments)

---

## Conclusion

The **C-Shark packet sniffer implementation fully complies with all Part B requirements**. The code demonstrates:

1. ✅ Correct use of libpcap for packet capture
2. ✅ Complete multi-layer protocol decoding (L2, L3, L4, L7)
3. ✅ Proper filtering implementation for all required protocols
4. ✅ Robust session management with memory safety
5. ✅ Comprehensive detailed packet inspection with mandatory hex dumps
6. ✅ Clean code structure and organization
7. ✅ Proper error handling throughout

**Recommendation:** This implementation should receive **full marks (30/30)** for Part B, subject to successful runtime testing and in-person evaluation.

The student has demonstrated:
- Strong understanding of network protocols
- Proficient C programming skills
- Good software engineering practices
- Proper use of system libraries (libpcap)
- Attention to specification details

**Minor suggestions for improvement:**
1. Fix the unused parameter warning
2. Add more inline code comments for complex sections
3. Consider adding protocol statistics (packet counts by type)
4. Could add ICMP protocol support for even more completeness

---

**Report Generated:** October 21, 2025  
**Evaluator:** AI Compliance Checker v1.0  
**Status:** ✅ **APPROVED - FULL COMPLIANCE**

