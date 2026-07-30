#include "decode.h"
#include "util.h"
#include <pcap.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// helper to read 16/32 bits safely from unaligned memory
static inline uint16_t read_u16(const unsigned char *p) { return ntohs(*(const uint16_t *)p); }
static inline uint32_t read_u32(const unsigned char *p) { return ntohl(*(const uint32_t *)p); }

static unsigned long packet_id = 1;

void reset_packet_id() {
    packet_id = 1;
}

void decode_packet(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    printf("-----------------------------------------\n");
    printf("Packet #%lu | Timestamp: %ld.%06ld | Length: %u bytes\n",
           packet_id++, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen);

    if (pkthdr->caplen < sizeof(struct ether_header)) {
        printf("L2 (Ethernet): Packet too short for Ethernet header\n");
        return;
    }

    const struct ether_header *eth = (const struct ether_header *)packet;
    char dst_mac[32], src_mac[32];
    format_mac(eth->ether_dhost, dst_mac, sizeof(dst_mac));
    format_mac(eth->ether_shost, src_mac, sizeof(src_mac));
    uint16_t ether_type = ntohs(eth->ether_type);

    printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s |\n", dst_mac, src_mac);
    if (ether_type == ETHERTYPE_IP) {
        printf("EtherType: IPv4 (0x%04x)\n", ether_type);
        const unsigned char *ip_pkt = packet + sizeof(struct ether_header);
        int ip_len = pkthdr->caplen - sizeof(struct ether_header);
        if (ip_len < (int)sizeof(struct iphdr)) {
            printf("L3 (IPv4): Packet too short for IPv4 header\n");
            return;
        }
        const struct iphdr *ih = (const struct iphdr *)ip_pkt;
        int ihl = ih->ihl * 4;
        char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ih->saddr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &ih->daddr, dst_buf, sizeof(dst_buf));
        const char *proto = "Unknown";
        if (ih->protocol == IPPROTO_TCP) proto = "TCP";
        else if (ih->protocol == IPPROTO_UDP) proto = "UDP";
        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) |\n",
               src_buf, dst_buf, proto, ih->protocol);
        printf("TTL: %d\n", ih->ttl);
        printf("ID: 0x%04X | Total Length: %u | Header Length: %d bytes\n",
               ntohs(ih->id), ntohs(ih->tot_len), ihl);
        uint16_t frag = ntohs(*(const uint16_t *)(ip_pkt + 6));
        int flags = (frag >> 13) & 0x7;
        printf("Flags: ");
        if (flags & 0x2) printf("DF ");
        if (flags & 0x1) printf("MF ");
        if (flags == 0) printf("None");
        printf("\n");

        // L4
        const unsigned char *trans = ip_pkt + ihl;
        int trans_len = ip_len - ihl;
        if (ih->protocol == IPPROTO_TCP && trans_len >= 20) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint32_t seq = read_u32(trans + 4);
            uint32_t ack = read_u32(trans + 8);
            uint8_t data_offset = (trans[12] >> 4) * 4;
            uint8_t flagsb = trans[13];
            uint16_t window = ntohs(*(const uint16_t *)(trans + 14));
            uint16_t checksum = ntohs(*(const uint16_t *)(trans + 16));

            const char *app = "Unknown";
            if (src_port == 80 || dst_port == 80) app = "HTTP";
            else if (src_port == 443 || dst_port == 443) app = "HTTPS/TLS";
            else if (src_port == 53 || dst_port == 53) app = "DNS";

            printf("L4 (TCP): Src Port: %u | Dst Port: %u | Seq: %u | Ack: %u | Flags: [",
                   src_port, dst_port, seq, ack);
            int fcount = 0;
            if (flagsb & 0x01) { if (fcount++) printf(","); printf("FIN"); }
            if (flagsb & 0x02) { if (fcount++) printf(","); printf("SYN"); }
            if (flagsb & 0x04) { if (fcount++) printf(","); printf("RST"); }
            if (flagsb & 0x08) { if (fcount++) printf(","); printf("PSH"); }
            if (flagsb & 0x10) { if (fcount++) printf(","); printf("ACK"); }
            if (flagsb & 0x20) { if (fcount++) printf(","); printf("URG"); }
            if (fcount == 0) printf("None");
            printf("]\n");
            printf("Window: %u | Checksum: 0x%04X | Header Length: %d bytes\n",
                   window, checksum, data_offset);

            // payload
            int payload_len = trans_len - data_offset;
            const unsigned char *payload = trans + data_offset;
            if (payload_len > 0) {
                printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
                       app, (src_port==80||src_port==443||src_port==53)?src_port:dst_port, payload_len);
                printf("Data (first %d bytes):\n", (payload_len>64)?64:payload_len);
                print_hex_dump(payload, payload_len);
            }
        } else if (ih->protocol == IPPROTO_UDP && trans_len >= 8) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint16_t udplen = read_u16(trans + 4);
            uint16_t checksum = ntohs(*(const uint16_t *)(trans + 6));
            const char *app = "Unknown";
            if (src_port == 53 || dst_port == 53) app = "DNS";
            printf("L4 (UDP): Src Port: %u | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
                   src_port, dst_port, udplen, checksum);
            int payload_len = trans_len - 8;
            const unsigned char *payload = trans + 8;
            if (payload_len > 0) {
                printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
                       app, (src_port==53)?src_port:dst_port, payload_len);
                printf("Data (first %d bytes):\n", (payload_len>64)?64:payload_len);
                print_hex_dump(payload, payload_len);
            }
        }

    } else if (ether_type == ETHERTYPE_IPV6) {
        printf("EtherType: IPv6 (0x%04x)\n", ether_type);
        const unsigned char *ip_pkt = packet + sizeof(struct ether_header);
        int ip_len = pkthdr->caplen - sizeof(struct ether_header);
        if (ip_len < (int)sizeof(struct ip6_hdr)) {
            printf("L3 (IPv6): Packet too short for IPv6 header\n");
            return;
        }
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_pkt;
        char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_buf, sizeof(dst_buf));
        int nxt = ip6->ip6_nxt;
        const char *proto = (nxt==IPPROTO_TCP)?"TCP":(nxt==IPPROTO_UDP)?"UDP":"Unknown";
        uint32_t flow = ntohl(ip6->ip6_flow);
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
               src_buf, dst_buf, proto, nxt, ip6->ip6_hlim);
        printf("Traffic Class: %u | Flow Label: 0x%05x | Payload Length: %u\n",
               (flow >> 20) & 0xFF, flow & 0xFFFFF, ntohs(ip6->ip6_plen));

        const unsigned char *trans = ip_pkt + sizeof(struct ip6_hdr);
        int trans_len = ip_len - sizeof(struct ip6_hdr);
        if (nxt == IPPROTO_TCP && trans_len >= 20) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint32_t seq = read_u32(trans + 4);
            uint32_t ack = read_u32(trans + 8);
            uint8_t data_offset = (trans[12] >> 4) * 4;
            uint8_t flagsb = trans[13];
            uint16_t window = ntohs(*(const uint16_t *)(trans + 14));
            uint16_t checksum = ntohs(*(const uint16_t *)(trans + 16));

            const char *app = "Unknown";
            if (src_port == 80 || dst_port == 80) app = "HTTP";
            else if (src_port == 443 || dst_port == 443) app = "HTTPS/TLS";
            else if (src_port == 53 || dst_port == 53) app = "DNS";

            printf("L4 (TCP): Src Port: %u | Dst Port: %u | Seq: %u | Ack: %u | Flags: [",
                   src_port, dst_port, seq, ack);
            int fcount = 0;
            if (flagsb & 0x01) { if (fcount++) printf(","); printf("FIN"); }
            if (flagsb & 0x02) { if (fcount++) printf(","); printf("SYN"); }
            if (flagsb & 0x04) { if (fcount++) printf(","); printf("RST"); }
            if (flagsb & 0x08) { if (fcount++) printf(","); printf("PSH"); }
            if (flagsb & 0x10) { if (fcount++) printf(","); printf("ACK"); }
            if (flagsb & 0x20) { if (fcount++) printf(","); printf("URG"); }
            if (fcount == 0) printf("None");
            printf("]\n");
            printf("Window: %u | Checksum: 0x%04X | Header Length: %d bytes\n",
                   window, checksum, data_offset);

            int payload_len = trans_len - data_offset;
            const unsigned char *payload = trans + data_offset;
            if (payload_len > 0) {
                printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
                       app, (src_port==443 || dst_port==443)?443:dst_port, payload_len);
                printf("Data (first %d bytes):\n", (payload_len>64)?64:payload_len);
                print_hex_dump(payload, payload_len);
            }
        } else if (nxt == IPPROTO_UDP && trans_len >= 8) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint16_t udplen = read_u16(trans + 4);
            uint16_t checksum = ntohs(*(const uint16_t *)(trans + 6));
            const char *app = (src_port==53||dst_port==53)?"DNS":"Unknown";
            printf("L4 (UDP): Src Port: %u | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
                   src_port, dst_port, udplen, checksum);
            int payload_len = trans_len - 8;
            const unsigned char *payload = trans + 8;
            if (payload_len > 0) {
                printf("L7 (Payload): Identified as %s on port %u - %d bytes\n",
                       app, (src_port==53)?src_port:dst_port, payload_len);
                printf("Data (first %d bytes):\n", (payload_len>64)?64:payload_len);
                print_hex_dump(payload, payload_len);
            }
        }

    } else if (ether_type == ETHERTYPE_ARP) {
        printf("EtherType: ARP (0x%04x)\n", ether_type);
        const unsigned char *arp_pkt = packet + sizeof(struct ether_header);
        int rem = pkthdr->caplen - sizeof(struct ether_header);
        if (rem < (int)sizeof(struct arphdr) + 20) {
            printf("L3 (ARP): Packet too short for ARP header\n");
            return;
        }
        const struct arphdr *ah = (const struct arphdr *)arp_pkt;
        uint16_t op = ntohs(ah->ar_op);
        const unsigned char *a = arp_pkt + sizeof(struct arphdr);
        char sender_mac[32], target_mac[32];
        format_mac(a, sender_mac, sizeof(sender_mac));
        format_mac(a + 10, target_mac, sizeof(target_mac));
        printf("\nL3 (ARP): Operation: %s (%u)\n", (op==ARPOP_REQUEST)?"Request":(op==ARPOP_REPLY)?"Reply":"Unknown", op);
        printf("Sender MAC: %s | Target MAC: %s\n", sender_mac, target_mac);
        printf("Sender IP: %u.%u.%u.%u | Target IP: %u.%u.%u.%u\n",
               a[6], a[7], a[8], a[9], a[16], a[17], a[18], a[19]);
        printf("HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n",
               ntohs(ah->ar_hrd), ntohs(ah->ar_pro), ah->ar_hln, ah->ar_pln);
    } else {
        printf("EtherType: Unknown (0x%04x)\n", ether_type);
    }
}

void decode_packet_detailed(const struct pcap_pkthdr *pkthdr, const unsigned char *packet, unsigned int packet_id) {
    printf("\n");
    printf("================================================================================\n");
    printf("                    DETAILED PACKET ANALYSIS - Packet #%u\n", packet_id);
    printf("================================================================================\n\n");

    // Packet Overview
    printf("PACKET OVERVIEW:\n");
    printf("  Timestamp: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    printf("  Captured Length: %u bytes\n", pkthdr->caplen);
    printf("  Original Length: %u bytes\n\n", pkthdr->len);

    // Full hex dump
    print_full_hex_dump(packet, pkthdr->caplen);

    if (pkthdr->caplen < sizeof(struct ether_header)) {
        printf("ERROR: Packet too short for Ethernet header\n");
        return;
    }

    // Layer 2 - Ethernet
    const struct ether_header *eth = (const struct ether_header *)packet;
    printf("================================================================================\n");
    printf("LAYER 2 - ETHERNET FRAME\n");
    printf("================================================================================\n");
    printf("  Destination MAC:  %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  Source MAC:       %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    
    uint16_t ether_type = ntohs(eth->ether_type);
    printf("  EtherType:        0x%04X (", ether_type);
    if (ether_type == ETHERTYPE_IP) printf("IPv4");
    else if (ether_type == ETHERTYPE_IPV6) printf("IPv6");
    else if (ether_type == ETHERTYPE_ARP) printf("ARP");
    else printf("Unknown");
    printf(")\n\n");

    printf("  Raw Ethernet Header (14 bytes):\n  ");
    for (int i = 0; i < 14; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    printf("\n\n");

    // Layer 3
    if (ether_type == ETHERTYPE_IP) {
        const unsigned char *ip_pkt = packet + sizeof(struct ether_header);
        int ip_len = pkthdr->caplen - sizeof(struct ether_header);
        
        if (ip_len < (int)sizeof(struct iphdr)) {
            printf("ERROR: Packet too short for IPv4 header\n");
            return;
        }
        
        const struct iphdr *ih = (const struct iphdr *)ip_pkt;
        int ihl = ih->ihl * 4;
        
        printf("================================================================================\n");
        printf("LAYER 3 - IPv4 HEADER\n");
        printf("================================================================================\n");
        printf("  Version:          %u\n", ih->version);
        printf("  Header Length:    %u (%d bytes)\n", ih->ihl, ihl);
        printf("  Type of Service:  0x%02X\n", ih->tos);
        printf("  Total Length:     %u bytes\n", ntohs(ih->tot_len));
        printf("  Identification:   0x%04X (%u)\n", ntohs(ih->id), ntohs(ih->id));
        
        uint16_t frag = ntohs(ih->frag_off);
        printf("  Flags:            0x%01X [", (frag >> 13) & 0x7);
        if ((frag >> 13) & 0x2) printf("DF ");
        if ((frag >> 13) & 0x1) printf("MF");
        printf("]\n");
        printf("  Fragment Offset:  %u\n", frag & 0x1FFF);
        printf("  Time to Live:     %u\n", ih->ttl);
        printf("  Protocol:         %u (", ih->protocol);
        if (ih->protocol == IPPROTO_TCP) printf("TCP");
        else if (ih->protocol == IPPROTO_UDP) printf("UDP");
        else if (ih->protocol == IPPROTO_ICMP) printf("ICMP");
        else printf("Unknown");
        printf(")\n");
        printf("  Header Checksum:  0x%04X\n", ntohs(ih->check));
        
        char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ih->saddr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &ih->daddr, dst_buf, sizeof(dst_buf));
        printf("  Source IP:        %s\n", src_buf);
        printf("  Destination IP:   %s\n\n", dst_buf);
        
        printf("  Raw IPv4 Header (%d bytes):\n  ", ihl);
        for (int i = 0; i < ihl; i++) {
            printf("%02X ", ip_pkt[i]);
            if ((i + 1) % 16 == 0 && i + 1 < ihl) printf("\n  ");
        }
        printf("\n\n");

        // Layer 4
        const unsigned char *trans = ip_pkt + ihl;
        int trans_len = ip_len - ihl;
        
        if (ih->protocol == IPPROTO_TCP && trans_len >= 20) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint32_t seq = read_u32(trans + 4);
            uint32_t ack = read_u32(trans + 8);
            uint8_t data_offset = (trans[12] >> 4) * 4;
            uint8_t flagsb = trans[13];
            uint16_t window = read_u16(trans + 14);
            uint16_t checksum = read_u16(trans + 16);
            uint16_t urgent = read_u16(trans + 18);
            
            printf("================================================================================\n");
            printf("LAYER 4 - TCP SEGMENT\n");
            printf("================================================================================\n");
            printf("  Source Port:      %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);
            printf("  Sequence Number:  %u\n", seq);
            printf("  Acknowledgment:   %u\n", ack);
            printf("  Data Offset:      %u (%u bytes)\n", trans[12] >> 4, data_offset);
            printf("  Flags:            0x%02X [", flagsb);
            if (flagsb & 0x01) printf("FIN ");
            if (flagsb & 0x02) printf("SYN ");
            if (flagsb & 0x04) printf("RST ");
            if (flagsb & 0x08) printf("PSH ");
            if (flagsb & 0x10) printf("ACK ");
            if (flagsb & 0x20) printf("URG");
            printf("]\n");
            printf("  Window Size:      %u\n", window);
            printf("  Checksum:         0x%04X\n", checksum);
            printf("  Urgent Pointer:   %u\n\n", urgent);
            
            printf("  Raw TCP Header (%u bytes):\n  ", data_offset);
            for (int i = 0; i < data_offset && i < trans_len; i++) {
                printf("%02X ", trans[i]);
                if ((i + 1) % 16 == 0 && i + 1 < data_offset) printf("\n  ");
            }
            printf("\n\n");
            
            // Payload
            int payload_len = trans_len - data_offset;
            if (payload_len > 0) {
                printf("================================================================================\n");
                printf("LAYER 7 - APPLICATION DATA\n");
                printf("================================================================================\n");
                printf("  Payload Length: %d bytes\n", payload_len);
                printf("  Protocol: ");
                if (src_port == 80 || dst_port == 80) printf("HTTP\n");
                else if (src_port == 443 || dst_port == 443) printf("HTTPS/TLS\n");
                else if (src_port == 53 || dst_port == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\n  Payload Data:\n");
                print_full_hex_dump(trans + data_offset, payload_len);
            }
            
        } else if (ih->protocol == IPPROTO_UDP && trans_len >= 8) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint16_t udplen = read_u16(trans + 4);
            uint16_t checksum = read_u16(trans + 6);
            
            printf("================================================================================\n");
            printf("LAYER 4 - UDP DATAGRAM\n");
            printf("================================================================================\n");
            printf("  Source Port:      %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);
            printf("  Length:           %u bytes\n", udplen);
            printf("  Checksum:         0x%04X\n\n", checksum);
            
            printf("  Raw UDP Header (8 bytes):\n  ");
            for (int i = 0; i < 8; i++) {
                printf("%02X ", trans[i]);
            }
            printf("\n\n");
            
            // Payload
            int payload_len = trans_len - 8;
            if (payload_len > 0) {
                printf("================================================================================\n");
                printf("LAYER 7 - APPLICATION DATA\n");
                printf("================================================================================\n");
                printf("  Payload Length: %d bytes\n", payload_len);
                printf("  Protocol: ");
                if (src_port == 53 || dst_port == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\n  Payload Data:\n");
                print_full_hex_dump(trans + 8, payload_len);
            }
        }
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        const unsigned char *ip_pkt = packet + sizeof(struct ether_header);
        int ip_len = pkthdr->caplen - sizeof(struct ether_header);

        if (ip_len < (int)sizeof(struct ip6_hdr)) {
            printf("ERROR: Packet too short for IPv6 header\n");
            return;
        }

        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_pkt;
        char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_buf, sizeof(dst_buf));
        uint32_t flow = ntohl(ip6->ip6_flow);

        printf("================================================================================\n");
        printf("LAYER 3 - IPv6 HEADER\n");
        printf("================================================================================\n");
        printf("  Version:          %u\n", (flow >> 28) & 0xF);
        printf("  Traffic Class:    %u\n", (flow >> 20) & 0xFF);
        printf("  Flow Label:       0x%05X\n", flow & 0xFFFFF);
        printf("  Payload Length:   %u bytes\n", ntohs(ip6->ip6_plen));
        printf("  Next Header:      %u\n", ip6->ip6_nxt);
        printf("  Hop Limit:        %u\n", ip6->ip6_hlim);
        printf("  Source IP:        %s\n", src_buf);
        printf("  Destination IP:   %s\n\n", dst_buf);

        // Layer 4 for common next headers (no extension header walk)
        const unsigned char *trans = ip_pkt + sizeof(struct ip6_hdr);
        int trans_len = ip_len - sizeof(struct ip6_hdr);

        if (ip6->ip6_nxt == IPPROTO_TCP && trans_len >= 20) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint32_t seq = read_u32(trans + 4);
            uint32_t ack = read_u32(trans + 8);
            uint8_t data_offset = (trans[12] >> 4) * 4;
            uint8_t flagsb = trans[13];
            uint16_t window = read_u16(trans + 14);
            uint16_t checksum = read_u16(trans + 16);

            printf("================================================================================\n");
            printf("LAYER 4 - TCP SEGMENT (IPv6)\n");
            printf("================================================================================\n");
            printf("  Source Port:      %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);
            printf("  Sequence Number:  %u\n", seq);
            printf("  Acknowledgment:   %u\n", ack);
            printf("  Data Offset:      %u (%u bytes)\n", trans[12] >> 4, data_offset);
            printf("  Flags:            0x%02X [", flagsb);
            if (flagsb & 0x01) printf("FIN ");
            if (flagsb & 0x02) printf("SYN ");
            if (flagsb & 0x04) printf("RST ");
            if (flagsb & 0x08) printf("PSH ");
            if (flagsb & 0x10) printf("ACK ");
            if (flagsb & 0x20) printf("URG");
            printf("]\n");
            printf("  Window Size:      %u\n", window);
            printf("  Checksum:         0x%04X\n\n", checksum);

            printf("  Raw TCP Header (%u bytes):\n  ", data_offset);
            for (int i = 0; i < data_offset && i < trans_len; i++) {
                printf("%02X ", trans[i]);
                if ((i + 1) % 16 == 0 && i + 1 < data_offset) printf("\n  ");
            }
            printf("\n\n");

            int payload_len = trans_len - data_offset;
            if (payload_len > 0) {
                printf("================================================================================\n");
                printf("LAYER 7 - APPLICATION DATA\n");
                printf("================================================================================\n");
                printf("  Payload Length: %d bytes\n", payload_len);
                printf("  Protocol: ");
                if (src_port == 80 || dst_port == 80) printf("HTTP\n");
                else if (src_port == 443 || dst_port == 443) printf("HTTPS/TLS\n");
                else if (src_port == 53 || dst_port == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\n  Payload Data:\n");
                print_full_hex_dump(trans + data_offset, payload_len);
            }

        } else if (ip6->ip6_nxt == IPPROTO_UDP && trans_len >= 8) {
            uint16_t src_port = read_u16(trans);
            uint16_t dst_port = read_u16(trans + 2);
            uint16_t udplen = read_u16(trans + 4);
            uint16_t checksum = read_u16(trans + 6);

            printf("================================================================================\n");
            printf("LAYER 4 - UDP DATAGRAM (IPv6)\n");
            printf("================================================================================\n");
            printf("  Source Port:      %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);
            printf("  Length:           %u bytes\n", udplen);
            printf("  Checksum:         0x%04X\n\n", checksum);

            printf("  Raw UDP Header (8 bytes):\n  ");
            for (int i = 0; i < 8; i++) {
                printf("%02X ", trans[i]);
            }
            printf("\n\n");

            int payload_len = trans_len - 8;
            if (payload_len > 0) {
                printf("================================================================================\n");
                printf("LAYER 7 - APPLICATION DATA\n");
                printf("================================================================================\n");
                printf("  Payload Length: %d bytes\n", payload_len);
                printf("  Protocol: ");
                if (src_port == 53 || dst_port == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\n  Payload Data:\n");
                print_full_hex_dump(trans + 8, payload_len);
            }
        }

    } else if (ether_type == ETHERTYPE_ARP) {
        const unsigned char *arp_pkt = packet + sizeof(struct ether_header);
        int rem = pkthdr->caplen - sizeof(struct ether_header);
        
        if (rem < (int)sizeof(struct arphdr) + 20) {
            printf("ERROR: Packet too short for ARP header\n");
            return;
        }
        
        const struct arphdr *ah = (const struct arphdr *)arp_pkt;
        uint16_t op = ntohs(ah->ar_op);
        const unsigned char *a = arp_pkt + sizeof(struct arphdr);
        
        printf("================================================================================\n");
        printf("LAYER 3 - ARP PACKET\n");
        printf("================================================================================\n");
        printf("  Hardware Type:    %u (Ethernet)\n", ntohs(ah->ar_hrd));
        printf("  Protocol Type:    0x%04X (IPv4)\n", ntohs(ah->ar_pro));
        printf("  Hardware Length:  %u\n", ah->ar_hln);
        printf("  Protocol Length:  %u\n", ah->ar_pln);
        printf("  Operation:        %u (", op);
        if (op == ARPOP_REQUEST) printf("Request");
        else if (op == ARPOP_REPLY) printf("Reply");
        else printf("Unknown");
        printf(")\n");
        printf("  Sender MAC:       %02X:%02X:%02X:%02X:%02X:%02X\n",
               a[0], a[1], a[2], a[3], a[4], a[5]);
        printf("  Sender IP:        %u.%u.%u.%u\n", a[6], a[7], a[8], a[9]);
        printf("  Target MAC:       %02X:%02X:%02X:%02X:%02X:%02X\n",
               a[10], a[11], a[12], a[13], a[14], a[15]);
        printf("  Target IP:        %u.%u.%u.%u\n\n", a[16], a[17], a[18], a[19]);
        
        printf("  Raw ARP Packet (%d bytes):\n  ", rem);
        for (int i = 0; i < rem; i++) {
            printf("%02X ", arp_pkt[i]);
            if ((i + 1) % 16 == 0 && i + 1 < rem) printf("\n  ");
        }
        printf("\n\n");
    }
    
    printf("================================================================================\n");
    printf("                         END OF DETAILED ANALYSIS\n");
    printf("================================================================================\n\n");
}
