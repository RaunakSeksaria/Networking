# Part B Q&A Quick Reference

**Last Updated:** October 21, 2025  
**Compliance Status:** 18/18 ✅

---

## Interface Handling

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 4 | Show ALL interfaces | `util.c:21-28` loops all devices | ✅ |
| 9 | Error if none found | `util.c:30-34` displays error | ✅ |
| 10 | Same menu for all | `main.c:64-155` static menu | ✅ |
| 23 | Buffer ≤256 chars | `main.c:49` uses `strdup()` | ✅ |

---

## IPv6 Protocol

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 6 | Skip extension headers | `decode.c:452-538` direct L4 | ✅ |
| 28 | __FAVOR_BSD assumption | `decode.c` uses byte offsets | ✅ |

---

## Control Flow

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 8,19 | Ctrl+C in menu = stay | Signal handler only in capture | ✅ |
| 20 | Ctrl+C capture = stop | `sniff.c:16-20` pcap_breakloop | ✅ |
| 24 | Ctrl+D = exit always | `main.c` + `sniff.c` EOF checks | ✅ |
| 26 | No commands while sniff | `sniff.c:61-71` EOF only | ✅ |

---

## Session Management

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 14 | Store/print/inspect | `session.c` all 3 functions | ✅ |
| 15 | No persistence needed | No disk I/O, shows error | ✅ |
| 29 | Empty session = error | `session_has_data()` checks count | ✅ |

---

## Filtering

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 44 | Filter = same decoding | Same callback for both modes | ✅ |
| 45 | Sequential numbering OK | `decode.c:20-29` uses 1,2,3... | ✅ |

---

## Documentation

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 22 | README basics only | Build/run/assumptions added | ✅ |

---

## Platform

| Q# | Requirement | Implementation | Status |
|----|-------------|----------------|--------|
| 50 | Linux assumption OK | POSIX APIs used throughout | ✅ |
| 52 | Non-Ethernet errors OK | `sniff.c:126-143` shows errors | ✅ |

---

## Code Locations Quick Map

**Interface Management:**
- List devices: `util.c:9-38`
- Interface selection: `main.c:16-62`

**Control Flow:**
- Main menu: `main.c:64-155`
- Signal handling: `sniff.c:16-20, 39`
- EOF detection: `main.c:26-29, 74-82`, `sniff.c:61-71`

**Packet Decoding:**
- Ethernet/ARP: `decode.c:26-232`
- IPv4: `decode.c:43-131`
- IPv6: `decode.c:132-208, 424-538`
- TCP: `decode.c:75-112, 154-190`
- UDP: `decode.c:113-130, 191-207`

**Session Management:**
- Init/cleanup: `session.c:14-36`
- Start new: `session.c:38-59`
- Add packet: `session.c:61-90`
- Inspect: `session.c:167-279`

**Filtering:**
- Filter menu: `main.c:94-141`
- BPF compilation: `sniff.c:122-145`
- Filter application: `sniff.c:138-143`

---

## Testing Checklist

- [x] All interfaces listed (Q4)
- [x] Error message for no interfaces (Q9)
- [x] Same menu for all interfaces (Q10)
- [x] IPv6 without extension headers (Q6)
- [x] Ctrl+C in menu stays in menu (Q8, Q19)
- [x] Ctrl+C during capture stops immediately (Q20)
- [x] Ctrl+D exits at any time (Q24)
- [x] No commands while sniffing (Q26)
- [x] Session storage works (Q14)
- [x] No persistence, proper errors (Q15)
- [x] Empty session shows error (Q29)
- [x] Filtering shows full decoding (Q44)
- [x] Sequential packet numbering (Q45)
- [x] README updated (Q22)
- [x] Linux-compatible (Q50)
- [x] Non-Ethernet errors handled (Q52)

---

**Status:** All 18 Q&A requirements verified ✅

