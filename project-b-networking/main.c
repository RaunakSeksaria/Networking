#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "util.h"
#include "sniff.h"
#include "session.h"

int main() {
    // Initialize session management
    session_init();
    
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    int num = list_devices();
    if (num <= 0) {
        session_cleanup();
        return 1;
    }

    printf("\nSelect an interface to sniff (1-%d): ", num);
    fflush(stdout);
    int choice;
    if (scanf("%d", &choice) != 1) {
        if (feof(stdin)) {
            printf("\n[C-Shark] Exiting...\n");
            session_cleanup();
            return 0;
        }
        fprintf(stderr, "Invalid selection.\n");
        session_cleanup();
        return 1;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    // fetch device name
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        session_cleanup();
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
    if (!dev_name) { 
        fprintf(stderr, "Invalid device selection\n");
        session_cleanup();
        return 1;
    }

    while (1) {
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", dev_name);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n");
        printf("Enter your choice: ");
        fflush(stdout);

        int menu_choice;
        if (scanf("%d", &menu_choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            if (feof(stdin)) { 
                printf("\n[C-Shark] Exiting...\n");
                free(dev_name);
                session_cleanup();
                return 0;
            }
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        
        // Clear input buffer
        while ((c = getchar()) != '\n' && c != EOF);

        switch (menu_choice) {
            case 1:
                start_sniff(dev_name);
                break;
            case 2: {
                printf("\n[C-Shark] Select a protocol to filter:\n\n");
                printf("1. HTTP\n");
                printf("2. HTTPS\n");
                printf("3. DNS\n");
                printf("4. ARP\n");
                printf("5. TCP\n");
                printf("6. UDP\n");
                printf("Enter your choice (1-6): ");
                fflush(stdout);
                
                int filter_choice;
                if (scanf("%d", &filter_choice) != 1) {
                    while ((c = getchar()) != '\n' && c != EOF);
                    printf("Invalid input.\n");
                    break;
                }
                while ((c = getchar()) != '\n' && c != EOF);
                
                const char *filter = NULL;
                switch (filter_choice) {
                    case 1:
                        filter = "tcp port 80";
                        break;
                    case 2:
                        filter = "tcp port 443";
                        break;
                    case 3:
                        filter = "udp port 53 or tcp port 53";
                        break;
                    case 4:
                        filter = "arp";
                        break;
                    case 5:
                        filter = "tcp";
                        break;
                    case 6:
                        filter = "udp";
                        break;
                    default:
                        printf("Invalid filter choice.\n");
                        break;
                }
                
                if (filter) {
                    start_sniff_filtered(dev_name, filter);
                }
                break;
            }
            case 3:
                session_inspect();
                break;
            case 4:
                printf("[C-Shark] Exiting...\n");
                free(dev_name);
                session_cleanup();
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    free(dev_name);
    session_cleanup();
    return 0;
}
// ############## LLM Generated Code Ends ################
