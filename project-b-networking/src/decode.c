#include "../include/decode.h"
#include "../include/util.h"
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

void decode_packet(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static unsigned long packet_id = 1;
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
        if (rem < (int)sizeof(struct arphdr) + 8) {
            printf("L3 (ARP): Packet too short for ARP header\n");
            return;
        }
        const struct arphdr *ah = (const struct arphdr *)arp_pkt;
        uint16_t op = ntohs(*(const uint16_t *)(arp_pkt + sizeof(struct arphdr) - 2)); // safest read
        const unsigned char *a = arp_pkt + sizeof(struct arphdr);
        char sender_mac[32], target_mac[32];
        format_mac(a, sender_mac, sizeof(sender_mac));
        format_mac(a + 6, target_mac, sizeof(target_mac));
        printf("\nL3 (ARP): Operation: %s (%u)\n", (op==ARPOP_REQUEST)?"Request":(op==ARPOP_REPLY)?"Reply":"Unknown", op);
        printf("Sender MAC: %s | Target MAC: %s\n", sender_mac, target_mac);
        printf("Sender IP: %u.%u.%u.%u | Target IP: %u.%u.%u.%u\n",
               a[6], a[7], a[8], a[9], a[12], a[13], a[14], a[15]);
        printf("HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n",
               ntohs(ah->ar_hrd), ntohs(ah->ar_pro), ah->ar_hln, ah->ar_pln);
    } else {
        printf("EtherType: Unknown (0x%04x)\n", ether_type);
    }
}