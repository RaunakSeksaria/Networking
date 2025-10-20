#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// Global variable for the pcap handle to be accessible in the signal handler
pcap_t *handle;
volatile sig_atomic_t stop_sniffing = 0;

// Signal handler for Ctrl+C (SIGINT)
void handle_sigint(int sig) {
    if (handle != NULL) {
        printf("\n[C-Shark] Stopping capture...\n");
        stop_sniffing = 1;
        pcap_breakloop(handle);
    }
}

// Function to print the first 16 bytes of the packet in hex
void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len && i < 16; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Function to print hex dump (16 bytes per line with ASCII representation)
void print_hex_dump(const unsigned char *data, int len) {
    int bytes_to_print = (len > 64) ? 64 : len;
    
    for (int i = 0; i < bytes_to_print; i += 16) {
        // Print hex values
        for (int j = 0; j < 16 && (i + j) < bytes_to_print; j++) {
            printf("%02X ", data[i + j]);
        }
        
        // Pad if less than 16 bytes in this line
        for (int j = bytes_to_print - i; j < 16 && j > 0; j++) {
            printf("   ");
        }
        
        // Print ASCII representation
        for (int j = 0; j < 16 && (i + j) < bytes_to_print; j++) {
            unsigned char c = data[i + j];
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

// Callback function for pcap_loop
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static int packet_id = 1;
    char time_buf[64];
    
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n", 
           packet_id++, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, pkthdr->caplen);
    
    // Decode Ethernet header (Layer 2)
    if (pkthdr->caplen >= sizeof(struct ether_header)) {
        struct ether_header *eth_header = (struct ether_header *)packet;
        
        // Extract MAC addresses
        unsigned char *src_mac = eth_header->ether_shost;
        unsigned char *dst_mac = eth_header->ether_dhost;
        
        // Get EtherType
        uint16_t ether_type = ntohs(eth_header->ether_type);
        
        printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | Src MAC: %02X:%02X:%02X:%02X:%02X:%02X |\n",
               dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        
        // Identify EtherType
        if (ether_type == ETHERTYPE_IP) {
            printf("EtherType: IPv4 (0x%04x)\n", ether_type);

            // Decode IPv4 header (Layer 3)
            const unsigned char *ip_packet = packet + sizeof(struct ether_header);
            int remaining_len = pkthdr->caplen - sizeof(struct ether_header);

            if (remaining_len >= sizeof(struct iphdr)) {
                struct iphdr *ip_header = (struct iphdr *)ip_packet;

                // Extract IP addresses
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, (struct in_addr *)&(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, (struct in_addr *)&(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

                // Protocol identification
                const char *protocol_name;
                if (ip_header->protocol == IPPROTO_TCP) {
                    protocol_name = "TCP";
                } else if (ip_header->protocol == IPPROTO_UDP) {
                    protocol_name = "UDP";
                } else if (ip_header->protocol == IPPROTO_ICMP) {
                    protocol_name = "ICMP";
                } else {
                    protocol_name = "Unknown";
                }

                printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) |\n",
                       src_ip, dst_ip, protocol_name, ip_header->protocol);
                printf("TTL: %d\n", ip_header->ttl);
                printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
                       ntohs(ip_header->id), ntohs(ip_header->tot_len), ip_header->ihl * 4);

                // Decode flags
                uint16_t flags_offset = ntohs(ip_header->frag_off);
                int flags = (flags_offset >> 13) & 0x07;
                printf("Flags: ");
                if (flags & 0x02) printf("DF ");
                if (flags & 0x01) printf("MF ");
                if (flags == 0) printf("None");
                printf("\n");

                // Layer 4 - Transport Layer
                int ip_header_len = ip_header->ihl * 4;
                const unsigned char *transport_packet = ip_packet + ip_header_len;
                int transport_remaining = remaining_len - ip_header_len;

                if (ip_header->protocol == IPPROTO_TCP && transport_remaining >= 20) {
                    // Manual TCP header parsing for portability
                    const unsigned char *tcp_data = transport_packet;

                    uint16_t src_port = ntohs(*(uint16_t *)(tcp_data));
                    uint16_t dst_port = ntohs(*(uint16_t *)(tcp_data + 2));
                    uint32_t seq = ntohl(*(uint32_t *)(tcp_data + 4));
                    uint32_t ack_seq = ntohl(*(uint32_t *)(tcp_data + 8));
                    uint8_t data_offset = (tcp_data[12] >> 4) * 4;
                    uint8_t tcp_flags = tcp_data[13];
                    uint16_t window = ntohs(*(uint16_t *)(tcp_data + 14));
                    uint16_t checksum = ntohs(*(uint16_t *)(tcp_data + 16));

                    // Identify common ports
                    const char *src_service = "";
                    const char *dst_service = "";
                    const char *app_protocol = "Unknown";
                    
                    if (src_port == 80) { src_service = " (HTTP)"; app_protocol = "HTTP"; }
                    else if (src_port == 443) { src_service = " (HTTPS)"; app_protocol = "HTTPS/TLS"; }
                    else if (src_port == 53) { src_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (src_port == 22) { src_service = " (SSH)"; app_protocol = "SSH"; }
                    else if (src_port == 21) { src_service = " (FTP)"; app_protocol = "FTP"; }
                    else if (src_port == 25) { src_service = " (SMTP)"; app_protocol = "SMTP"; }

                    if (dst_port == 80) { dst_service = " (HTTP)"; app_protocol = "HTTP"; }
                    else if (dst_port == 443) { dst_service = " (HTTPS)"; app_protocol = "HTTPS/TLS"; }
                    else if (dst_port == 53) { dst_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (dst_port == 22) { dst_service = " (SSH)"; app_protocol = "SSH"; }
                    else if (dst_port == 21) { dst_service = " (FTP)"; app_protocol = "FTP"; }
                    else if (dst_port == 25) { dst_service = " (SMTP)"; app_protocol = "SMTP"; }

                    printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | Seq: %u | Ack: %u | Flags: [",
                           src_port, src_service, dst_port, dst_service, seq, ack_seq);

                    // Decode TCP flags
                    int flag_count = 0;
                    if (tcp_flags & 0x01) { if (flag_count++) printf(","); printf("FIN"); }
                    if (tcp_flags & 0x02) { if (flag_count++) printf(","); printf("SYN"); }
                    if (tcp_flags & 0x04) { if (flag_count++) printf(","); printf("RST"); }
                    if (tcp_flags & 0x08) { if (flag_count++) printf(","); printf("PSH"); }
                    if (tcp_flags & 0x10) { if (flag_count++) printf(","); printf("ACK"); }
                    if (tcp_flags & 0x20) { if (flag_count++) printf(","); printf("URG"); }
                    if (flag_count == 0) printf("None");
                    printf("]\n");

                    printf("Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
                           window, checksum, data_offset);

                    // Layer 7 - Payload
                    const unsigned char *payload = tcp_data + data_offset;
                    int payload_len = transport_remaining - data_offset;
                    
                    if (payload_len > 0) {
                        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                               app_protocol, (src_port == 80 || src_port == 443 || src_port == 53 || 
                                             src_port == 22 || src_port == 21 || src_port == 25) ? src_port : dst_port,
                               payload_len);
                        printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
                        print_hex_dump(payload, payload_len);
                    }

                } else if (ip_header->protocol == IPPROTO_UDP && transport_remaining >= sizeof(struct udphdr)) {
                    struct udphdr *udp_header = (struct udphdr *)transport_packet;
                    
                    uint16_t src_port = ntohs(udp_header->source);
                    uint16_t dst_port = ntohs(udp_header->dest);
                    
                    // Identify common ports
                    const char *src_service = "";
                    const char *dst_service = "";
                    const char *app_protocol = "Unknown";
                    
                    if (src_port == 53) { src_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (src_port == 67) { src_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (src_port == 68) { src_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (src_port == 123) { src_service = " (NTP)"; app_protocol = "NTP"; }
                    
                    if (dst_port == 53) { dst_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (dst_port == 67) { dst_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (dst_port == 68) { dst_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (dst_port == 123) { dst_service = " (NTP)"; app_protocol = "NTP"; }
                    
                    printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | Length: %d | Checksum: 0x%04X\n",
                           src_port, src_service, dst_port, dst_service,
                           ntohs(udp_header->len), ntohs(udp_header->check));
                    
                    // Layer 7 - Payload
                    const unsigned char *payload = transport_packet + sizeof(struct udphdr);
                    int payload_len = transport_remaining - sizeof(struct udphdr);
                    
                    if (payload_len > 0) {
                        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                               app_protocol, (src_port == 53 || src_port == 67 || 
                                             src_port == 68 || src_port == 123) ? src_port : dst_port,
                               payload_len);
                        printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
                        print_hex_dump(payload, payload_len);
                    }
                }

            } else {
                printf("L3 (IPv4): Packet too short for IPv4 header\n");
            }

        } else if (ether_type == ETHERTYPE_IPV6) {
            printf("EtherType: IPv6 (0x%04x)\n", ether_type);
            
            // Decode IPv6 header (Layer 3)
            const unsigned char *ip_packet = packet + sizeof(struct ether_header);
            int remaining_len = pkthdr->caplen - sizeof(struct ether_header);
            
            if (remaining_len >= sizeof(struct ip6_hdr)) {
                struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip_packet;
                
                // Extract IPv6 addresses
                char src_ip[INET6_ADDRSTRLEN];
                char dst_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
                
                // Protocol identification
                const char *protocol_name;
                if (ip6_header->ip6_nxt == IPPROTO_TCP) {
                    protocol_name = "TCP";
                } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
                    protocol_name = "UDP";
                } else if (ip6_header->ip6_nxt == IPPROTO_ICMPV6) {
                    protocol_name = "ICMPv6";
                } else {
                    protocol_name = "Unknown";
                }
                
                printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
                       src_ip, dst_ip, protocol_name, ip6_header->ip6_nxt, ip6_header->ip6_hlim);
                printf("Traffic Class: %d | Flow Label: 0x%05x | Payload Length: %d\n",
                       (ntohl(ip6_header->ip6_flow) >> 20) & 0xFF,
                       ntohl(ip6_header->ip6_flow) & 0xFFFFF,
                       ntohs(ip6_header->ip6_plen));
                
                // Layer 4 - Transport Layer
                const unsigned char *transport_packet = ip_packet + sizeof(struct ip6_hdr);
                int transport_remaining = remaining_len - sizeof(struct ip6_hdr);

                if (ip6_header->ip6_nxt == IPPROTO_TCP && transport_remaining >= 20) {
                    // Manual TCP header parsing for portability
                    const unsigned char *tcp_data = transport_packet;
                    
                    uint16_t src_port = ntohs(*(uint16_t *)(tcp_data));
                    uint16_t dst_port = ntohs(*(uint16_t *)(tcp_data + 2));
                    uint32_t seq = ntohl(*(uint32_t *)(tcp_data + 4));
                    uint32_t ack_seq = ntohl(*(uint32_t *)(tcp_data + 8));
                    uint8_t data_offset = (tcp_data[12] >> 4) * 4;
                    uint8_t tcp_flags = tcp_data[13];
                    uint16_t window = ntohs(*(uint16_t *)(tcp_data + 14));
                    uint16_t checksum = ntohs(*(uint16_t *)(tcp_data + 16));
                    
                    // Identify common ports
                    const char *src_service = "";
                    const char *dst_service = "";
                    const char *app_protocol = "Unknown";
                    
                    if (src_port == 80) { src_service = " (HTTP)"; app_protocol = "HTTP"; }
                    else if (src_port == 443) { src_service = " (HTTPS)"; app_protocol = "HTTPS/TLS"; }
                    else if (src_port == 53) { src_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (src_port == 22) { src_service = " (SSH)"; app_protocol = "SSH"; }
                    else if (src_port == 21) { src_service = " (FTP)"; app_protocol = "FTP"; }
                    else if (src_port == 25) { src_service = " (SMTP)"; app_protocol = "SMTP"; }
                    
                    if (dst_port == 80) { dst_service = " (HTTP)"; app_protocol = "HTTP"; }
                    else if (dst_port == 443) { dst_service = " (HTTPS)"; app_protocol = "HTTPS/TLS"; }
                    else if (dst_port == 53) { dst_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (dst_port == 22) { dst_service = " (SSH)"; app_protocol = "SSH"; }
                    else if (dst_port == 21) { dst_service = " (FTP)"; app_protocol = "FTP"; }
                    else if (dst_port == 25) { dst_service = " (SMTP)"; app_protocol = "SMTP"; }
                    
                    printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | Seq: %u | Ack: %u | Flags: [",
                           src_port, src_service, dst_port, dst_service, seq, ack_seq);
                    
                    // Decode TCP flags
                    int flag_count = 0;
                    if (tcp_flags & 0x01) { if (flag_count++) printf(","); printf("FIN"); }
                    if (tcp_flags & 0x02) { if (flag_count++) printf(","); printf("SYN"); }
                    if (tcp_flags & 0x04) { if (flag_count++) printf(","); printf("RST"); }
                    if (tcp_flags & 0x08) { if (flag_count++) printf(","); printf("PSH"); }
                    if (tcp_flags & 0x10) { if (flag_count++) printf(","); printf("ACK"); }
                    if (tcp_flags & 0x20) { if (flag_count++) printf(","); printf("URG"); }
                    if (flag_count == 0) printf("None");
                    printf("]\n");
                    
                    printf("Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
                           window, checksum, data_offset);
                    
                    // Layer 7 - Payload
                    const unsigned char *payload = tcp_data + data_offset;
                    int payload_len = transport_remaining - data_offset;
                    
                    if (payload_len > 0) {
                        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                               app_protocol, (src_port == 80 || src_port == 443 || src_port == 53 || 
                                             src_port == 22 || src_port == 21 || src_port == 25) ? src_port : dst_port,
                               payload_len);
                        printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
                        print_hex_dump(payload, payload_len);
                    }
                    
                } else if (ip6_header->ip6_nxt == IPPROTO_UDP && transport_remaining >= sizeof(struct udphdr)) {
                    struct udphdr *udp_header = (struct udphdr *)transport_packet;
                    
                    uint16_t src_port = ntohs(udp_header->source);
                    uint16_t dst_port = ntohs(udp_header->dest);
                    
                    // Identify common ports
                    const char *src_service = "";
                    const char *dst_service = "";
                    const char *app_protocol = "Unknown";
                    
                    if (src_port == 53) { src_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (src_port == 67) { src_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (src_port == 68) { src_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (src_port == 123) { src_service = " (NTP)"; app_protocol = "NTP"; }
                    
                    if (dst_port == 53) { dst_service = " (DNS)"; app_protocol = "DNS"; }
                    else if (dst_port == 67) { dst_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (dst_port == 68) { dst_service = " (DHCP)"; app_protocol = "DHCP"; }
                    else if (dst_port == 123) { dst_service = " (NTP)"; app_protocol = "NTP"; }
                    
                    printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | Length: %d | Checksum: 0x%04X\n",
                           src_port, src_service, dst_port, dst_service,
                           ntohs(udp_header->len), ntohs(udp_header->check));
                    
                    // Layer 7 - Payload
                    const unsigned char *payload = transport_packet + sizeof(struct udphdr);
                    int payload_len = transport_remaining - sizeof(struct udphdr);
                    
                    if (payload_len > 0) {
                        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                               app_protocol, (src_port == 53 || src_port == 67 || 
                                             src_port == 68 || src_port == 123) ? src_port : dst_port,
                               payload_len);
                        printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
                        print_hex_dump(payload, payload_len);
                    }
                }
                
            } else {
                printf("L3 (IPv6): Packet too short for IPv6 header\n");
            }
            
        } else if (ether_type == ETHERTYPE_ARP) {
            printf("EtherType: ARP (0x%04x)\n", ether_type);
            
            // Decode ARP header (Layer 3)
            const unsigned char *arp_packet = packet + sizeof(struct ether_header);
            int remaining_len = pkthdr->caplen - sizeof(struct ether_header);
            
            if (remaining_len >= sizeof(struct arphdr) + 20) { // ARP header + addresses
                struct arphdr *arp_header = (struct arphdr *)arp_packet;
                
                // Operation
                uint16_t arp_op = ntohs(arp_header->ar_op);
                const char *operation;
                if (arp_op == ARPOP_REQUEST) {
                    operation = "Request";
                } else if (arp_op == ARPOP_REPLY) {
                    operation = "Reply";
                } else {
                    operation = "Unknown";
                }
                
                // Extract MAC and IP addresses from ARP payload
                const unsigned char *arp_data = arp_packet + sizeof(struct arphdr);
                unsigned char sender_mac[6];
                unsigned char sender_ip[4];
                unsigned char target_mac[6];
                unsigned char target_ip[4];
                
                memcpy(sender_mac, arp_data, 6);
                memcpy(sender_ip, arp_data + 6, 4);
                memcpy(target_mac, arp_data + 10, 6);
                memcpy(target_ip, arp_data + 16, 4);
                
                printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %d.%d.%d.%d | Target IP: %d.%d.%d.%d\n",
                       operation, arp_op,
                       sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
                       target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
                printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
                       target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
                printf("HW Type: %d | Proto Type: 0x%04x | HW Len: %d | Proto Len: %d\n",
                       ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro),
                       arp_header->ar_hln, arp_header->ar_pln);
                
            } else {
                printf("L3 (ARP): Packet too short for ARP header\n");
            }
            
        } else {
            printf("EtherType: Unknown (0x%04x)\n", ether_type);
        }
    } else {
        printf("L2 (Ethernet): Packet too short for Ethernet header\n");
    }   
    
    // printf("\n");
}

// Function to list all available network interfaces
int list_devices() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    printf("[C-Shark] Searching for available interfaces... ");
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    printf("Found!\n\n");

    for (dev = alldevs; dev; dev = dev->next) {
        printf("%d. %s", ++i, dev->name);
        if (dev->description) {
            printf(" (%s)\n", dev->description);
        } else {
            // Provide better default descriptions based on interface names
            if (strcmp(dev->name, "lo") == 0 || strncmp(dev->name, "lo", 2) == 0) {
                printf(" (Loopback interface)\n");
            } else if (strncmp(dev->name, "wlan", 4) == 0 || 
                       strncmp(dev->name, "wlp", 3) == 0 || 
                       strncmp(dev->name, "wifi", 4) == 0) {
                printf(" (WiFi interface)\n");
            } else if (strncmp(dev->name, "eth", 3) == 0 || 
                       strncmp(dev->name, "enp", 3) == 0 || 
                       strncmp(dev->name, "eno", 3) == 0) {
                printf(" (Ethernet interface)\n");
            } else if (strncmp(dev->name, "docker", 6) == 0 || 
                       strncmp(dev->name, "br-", 3) == 0) {
                printf(" (Docker bridge interface)\n");
            } else if (strncmp(dev->name, "bluetooth", 9) == 0) {
                printf(" (Bluetooth interface)\n");
            } else {
                printf(" (No description available)\n");
            }
        }
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure you have the necessary permissions and libpcap is installed.\n");
        return -1;
    }

    pcap_freealldevs(alldevs);
    return i;
}

int main() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int num_devices, choice;
    char *dev_name = NULL;

    // Set up signal handler for Ctrl+C
    signal(SIGINT, handle_sigint);

    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    num_devices = list_devices();
    if (num_devices <= 0) {
        return 1;
    }

    printf("\nSelect an interface to sniff (1-%d): ", num_devices);
    fflush(stdout);
    if (scanf("%d", &choice) != 1) {
        if (feof(stdin)) {
            printf("\n[C-Shark] Exiting...\n");
            return 0;
        }
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }
    
    if (choice < 1 || choice > num_devices) {
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }

    // Find the chosen device
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    int i = 0;
    for (dev = alldevs; dev && i < choice - 1; dev = dev->next, i++);
    if (dev) {
        dev_name = strdup(dev->name);
    }
    pcap_freealldevs(alldevs);

    if (!dev_name) {
        fprintf(stderr, "Unable to find the selected device.\n");
        return 1;
    }

    int menu_choice;
    while (1) {
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", dev_name);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters) <-- To be implemented later\n");
        printf("3. Inspect Last Session <-- To be implemented later\n");
        printf("4. Exit C-Shark\n");
        printf("Enter your choice: ");
        fflush(stdout);

        if (scanf("%d", &menu_choice) != 1) {
            // Clear input buffer in case of non-integer input
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            
            // Check for EOF (Ctrl+D)
            if (feof(stdin)) {
                printf("\n[C-Shark] Exiting...\n");
                free(dev_name);
                return 0;
            }
            printf("Invalid input. Please enter a number.\n");
            continue;
        }


        switch (menu_choice) {
            case 1:
                printf("\n[C-Shark] Starting capture on '%s'. Press Ctrl+C or Ctrl+D to stop.\n\n", dev_name);
                stop_sniffing = 0;
                handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
                if (handle == NULL) {
                    fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
                    free(dev_name);
                    return 2;
                }
                
                // Set pcap to non-blocking mode
                if (pcap_setnonblock(handle, 1, errbuf) == -1) {
                    fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
                    pcap_close(handle);
                    handle = NULL;
                    break;
                }
                
                int pcap_fd = pcap_get_selectable_fd(handle);
                if (pcap_fd == -1) {
                    fprintf(stderr, "Error: pcap file descriptor not available\n");
                    pcap_close(handle);
                    handle = NULL;
                    break;
                }
                
                // Main sniffing loop using select()
                while (!stop_sniffing) {
                    fd_set readfds;
                    FD_ZERO(&readfds);
                    FD_SET(STDIN_FILENO, &readfds);
                    FD_SET(pcap_fd, &readfds);
                    
                    struct timeval timeout;
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 100000; // 100ms timeout
                    
                    int max_fd = (pcap_fd > STDIN_FILENO) ? pcap_fd : STDIN_FILENO;
                    int ret = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
                    
                    if (ret == -1) {
                        if (!stop_sniffing) {
                            perror("select");
                        }
                        break;
                    }
                    
                    // Check if stdin has input (Ctrl+D will cause EOF)
                    if (FD_ISSET(STDIN_FILENO, &readfds)) {
                        char c;
                        int n = read(STDIN_FILENO, &c, 1);
                        if (n == 0) {
                            // EOF detected (Ctrl+D)
                            printf("\n[C-Shark] EOF detected, stopping capture...\n");
                            stop_sniffing = 1;
                            pcap_close(handle);
                            handle = NULL;
                            free(dev_name);
                            return 0;
                        }
                    }
                    
                    // Check if pcap has packets
                    if (FD_ISSET(pcap_fd, &readfds)) {
                        pcap_dispatch(handle, -1, packet_handler, NULL);
                    }
                }
                
                pcap_close(handle);
                handle = NULL;
                break;
            case 2:
                printf("This feature is not yet implemented.\n");
                break;
            case 3:
                printf("This feature is not yet implemented.\n");
                break;
            case 4:
                printf("[C-Shark] Exiting...\n");
                free(dev_name);
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    free(dev_name);
    return 0;
}