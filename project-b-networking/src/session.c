#include "../include/session.h"
#include "../include/decode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
        fprintf(stderr, "[C-Shark] Warning: Maximum packet storage limit (%d) reached. Packet dropped.\n", MAX_PACKETS);
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
    printf("Memory Used: %.2f KB\n", 
           (current_session.count * sizeof(stored_packet_t)) / 1024.0);
    printf("============================================================\n\n");
}

void session_inspect() {
    if (!session_has_data()) {
        printf("[C-Shark] Error: No packets to inspect. Please run a sniffing session first.\n");
        return;
    }
    
    session_print_summary();
    
    printf("[C-Shark] Inspection Options:\n\n");
    printf("1. Display all packets\n");
    printf("2. Display specific packet by ID\n");
    printf("3. Display packet range (e.g., 1-50)\n");
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
            
            decode_packet(NULL, &pkthdr, current_session.packets[packet_id].data);
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