#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/util.h"
#include "../include/sniff.h"

int main() {
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    int num = list_devices();
    if (num <= 0) return 1;

    printf("\nSelect an interface to sniff (1-%d): ", num);
    fflush(stdout);
    int choice;
    if (scanf("%d", &choice) != 1) {
        if (feof(stdin)) {
            printf("\n[C-Shark] Exiting...\n");
            return 0;
        }
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }
    // fetch device name
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    int i = 0;
    char *dev_name = NULL;
    for (dev = alldevs; dev; dev = dev->next) {
        i++;
        if (i == choice) {
            dev_name = strdup(dev->name);
            break;
        }
    }
    pcap_freealldevs(alldevs);
    if (!dev_name) { fprintf(stderr, "Invalid device selection\n"); return 1; }

    while (1) {
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", dev_name);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters) <-- To be implemented later\n");
        printf("3. Inspect Last Session <-- To be implemented later\n");
        printf("4. Exit C-Shark\n");
        printf("Enter your choice: ");
        fflush(stdout);

        int menu_choice;
        if (scanf("%d", &menu_choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            if (feof(stdin)) { printf("\n[C-Shark] Exiting...\n"); free(dev_name); return 0; }
            printf("Invalid input. Please enter a number.\n");
            continue;
        }

        switch (menu_choice) {
            case 1:
                start_sniff(dev_name);
                break;
            case 2:
            case 3:
                printf("This feature is not yet implemented.\n");
                break;
            case 4:
                printf("[C-Shark] Exiting...\n");
                free(dev_name);
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    free(dev_name);
    return 0;
}