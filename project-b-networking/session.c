#include "session.h"
#include "decode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

static session_t current_session = {0};

void session_init() {
    memset(&current_session, 0, sizeof(session_t));
}

void session_cleanup() {
    if (current_session.packets) {
        for (unsigned int i = 0; i < current_session.count; i++) {
            free(current_session.packets[i].data);
        }
        free(current_session.packets);
        current_session.packets = NULL;
    }
    if (current_session.interface_name) {
        free(current_session.interface_name);
        current_session.interface_name = NULL;
    }
    if (current_session.filter_used) {
        free(current_session.filter_used);
        current_session.filter_used = NULL;
    }
    current_session.count = 0;
    current_session.capacity = 0;
}

void session_start_new(const char *interface, const char *filter) {
    // Clean up previous session
    session_cleanup();
    
    // Reset packet ID counter for new session
    reset_packet_id();
    
    // Initialize new session
    current_session.packets = malloc(MAX_PACKETS * sizeof(stored_packet_t));
    if (!current_session.packets) {
        fprintf(stderr, "Error: Failed to allocate memory for packet storage\n");
        return;
    }
    
    current_session.capacity = MAX_PACKETS;
    current_session.count = 0;
    current_session.session_time = time(NULL);
    current_session.interface_name = strdup(interface);
    current_session.filter_used = filter ? strdup(filter) : strdup("None (All Packets)");
    
    printf("[C-Shark] New session started. Storage allocated for up to %d packets.\n", MAX_PACKETS);
}

int session_add_packet(const unsigned char *data, unsigned int length, struct timeval timestamp) {
    if (!current_session.packets) {
        return -1; // No active session
    }
    
    if (current_session.count >= current_session.capacity) {
        static int warning_shown = 0;
        if (!warning_shown) {
            fprintf(stderr, "[C-Shark] Warning: Maximum packet storage limit (%d) reached. Further packets will be dropped.\n", MAX_PACKETS);
            warning_shown = 1;
        }
        return -1;
    }
    
    // Allocate memory for packet data
    unsigned char *packet_copy = malloc(length);
    if (!packet_copy) {
        fprintf(stderr, "Error: Failed to allocate memory for packet\n");
        return -1;
    }
    
    memcpy(packet_copy, data, length);
    
    current_session.packets[current_session.count].data = packet_copy;
    current_session.packets[current_session.count].length = length;
    current_session.packets[current_session.count].timestamp = timestamp;
    current_session.count++;
    
    return 0;
}

int session_has_data() {
    return current_session.packets != NULL && current_session.count > 0;
}

void session_print_summary() {
    if (!session_has_data()) {
        printf("[C-Shark] No session data available. Run a sniffing session first.\n");
        return;
    }
    
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&current_session.session_time));
    
    printf("\n[C-Shark] ==================== Session Summary ====================\n");
    printf("Session Time: %s\n", time_buf);
    printf("Interface: %s\n", current_session.interface_name);
    printf("Filter Applied: %s\n", current_session.filter_used);
    printf("Packets Captured: %u\n", current_session.count);
    printf("Storage Capacity: %u packets\n", current_session.capacity);
    
    // Calculate actual memory used
    size_t total_memory = 0;
    for (unsigned int i = 0; i < current_session.count; i++) {
        total_memory += current_session.packets[i].length;
    }
    total_memory += current_session.count * sizeof(stored_packet_t);
    
    printf("Memory Used: %.2f KB\n", total_memory / 1024.0);
    printf("============================================================\n\n");
}

// Helper function to get basic packet info
static void get_packet_info(const unsigned char *packet, unsigned int length, 
                            char *proto, char *src, char *dst) {
    if (length < sizeof(struct ether_header)) {
        strcpy(proto, "Unknown");
        strcpy(src, "N/A");
        strcpy(dst, "N/A");
        return;
    }
    
    const struct ether_header *eth = (const struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth->ether_type);
    
    if (ether_type == ETHERTYPE_IP) {
        const struct iphdr *ih = (const struct iphdr *)(packet + sizeof(struct ether_header));
        if (ih->protocol == IPPROTO_TCP) strcpy(proto, "TCP/IPv4");
        else if (ih->protocol == IPPROTO_UDP) strcpy(proto, "UDP/IPv4");
        else strcpy(proto, "IPv4");
        
        inet_ntop(AF_INET, &ih->saddr, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ih->daddr, dst, INET_ADDRSTRLEN);
    } else if (ether_type == ETHERTYPE_IPV6) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + sizeof(struct ether_header));
        if (ip6->ip6_nxt == IPPROTO_TCP) strcpy(proto, "TCP/IPv6");
        else if (ip6->ip6_nxt == IPPROTO_UDP) strcpy(proto, "UDP/IPv6");
        else strcpy(proto, "IPv6");
        
        inet_ntop(AF_INET6, &ip6->ip6_src, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, INET6_ADDRSTRLEN);
    } else if (ether_type == ETHERTYPE_ARP) {
        strcpy(proto, "ARP");
        sprintf(src, "%02X:%02X:%02X:%02X:%02X:%02X", 
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    } else {
        strcpy(proto, "Unknown");
        strcpy(src, "N/A");
        strcpy(dst, "N/A");
    }
}

void session_inspect() {
    if (!session_has_data()) {
        printf("[C-Shark] Error: No packets to inspect. Please run a sniffing session first.\n");
        return;
    }
    
    session_print_summary();
    
    // Display packet list
    printf("[C-Shark] Packet List:\n");
    printf("%-6s %-20s %-10s %-12s %-40s %-40s\n", 
           "ID", "Timestamp", "Length", "Protocol", "Source", "Destination");
    printf("--------------------------------------------------------------------------------\n");
    
    for (unsigned int i = 0; i < current_session.count && i < 100; i++) {
        char proto[20], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        get_packet_info(current_session.packets[i].data, 
                       current_session.packets[i].length,
                       proto, src, dst);
        
        printf("%-6u %ld.%06ld %-10u %-12s %-40s %-40s\n",
               i + 1,
               current_session.packets[i].timestamp.tv_sec,
               current_session.packets[i].timestamp.tv_usec,
               current_session.packets[i].length,
               proto, src, dst);
    }
    
    if (current_session.count > 100) {
        printf("... and %u more packets (showing first 100)\n", current_session.count - 100);
    }
    
    printf("\n[C-Shark] Inspection Options:\n\n");
    printf("1. Display all packets (brief)\n");
    printf("2. Inspect specific packet (detailed)\n");
    printf("3. Display packet range (brief)\n");
    printf("4. Back to main menu\n");
    printf("Enter your choice: ");
    fflush(stdout);
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        printf("Invalid input.\n");
        return;
    }
    
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    switch (choice) {
        case 1: {
            printf("\n[C-Shark] Displaying all %u packets from session:\n\n", current_session.count);
            reset_packet_id(); // Reset counter for display
            for (unsigned int i = 0; i < current_session.count; i++) {
                struct pcap_pkthdr pkthdr;
                pkthdr.ts = current_session.packets[i].timestamp;
                pkthdr.caplen = current_session.packets[i].length;
                pkthdr.len = current_session.packets[i].length;
                
                decode_packet(NULL, &pkthdr, current_session.packets[i].data);
            }
            break;
        }
        case 2: {
            unsigned int packet_id;
            printf("Enter packet ID (1-%u): ", current_session.count);
            if (scanf("%u", &packet_id) != 1 || packet_id < 1 || packet_id > current_session.count) {
                while ((c = getchar()) != '\n' && c != EOF);
                printf("Invalid packet ID.\n");
                return;
            }
            while ((c = getchar()) != '\n' && c != EOF);
            
            packet_id--; // Convert to 0-indexed
            struct pcap_pkthdr pkthdr;
            pkthdr.ts = current_session.packets[packet_id].timestamp;
            pkthdr.caplen = current_session.packets[packet_id].length;
            pkthdr.len = current_session.packets[packet_id].length;
            
            decode_packet_detailed(&pkthdr, current_session.packets[packet_id].data, packet_id + 1);
            break;
        }
        case 3: {
            unsigned int start, end;
            printf("Enter range (start-end): ");
            if (scanf("%u-%u", &start, &end) != 2 || start < 1 || end > current_session.count || start > end) {
                while ((c = getchar()) != '\n' && c != EOF);
                printf("Invalid range.\n");
                return;
            }
            while ((c = getchar()) != '\n' && c != EOF);
            
            printf("\n[C-Shark] Displaying packets %u to %u:\n\n", start, end);
            reset_packet_id(); // Reset counter for display
            for (unsigned int i = start - 1; i < end; i++) {
                struct pcap_pkthdr pkthdr;
                pkthdr.ts = current_session.packets[i].timestamp;
                pkthdr.caplen = current_session.packets[i].length;
                pkthdr.len = current_session.packets[i].length;
                
                decode_packet(NULL, &pkthdr, current_session.packets[i].data);
            }
            break;
        }
        case 4:
            return;
        default:
            printf("Invalid choice.\n");
            break;
    }
}