#include "../include/util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

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
            printf(" (No description available)\n");
        }
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure you have permissions and libpcap is installed.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);
    return i;
}

void print_hex_dump(const unsigned char *data, int len) {
    int bytes_to_print = (len > 64) ? 64 : len;
    for (int i = 0; i < bytes_to_print; i += 16) {
        // hex
        for (int j = 0; j < 16 && (i + j) < bytes_to_print; j++) {
            printf("%02X ", data[i + j]);
        }
        // padding
        int printed = ((bytes_to_print - i) < 16) ? (bytes_to_print - i) : 16;
        for (int j = printed; j < 16; j++) printf("   ");
        // ascii
        printf(" ");
        for (int j = 0; j < 16 && (i + j) < bytes_to_print; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}

void format_mac(const unsigned char *mac, char *buf, size_t buflen) {
    if (!mac || !buf) return;
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}