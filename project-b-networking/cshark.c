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

// Callback function for pcap_loop
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static int packet_id = 1;
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));

    printf("Packet ID: %d\n", packet_id++);
    printf("Timestamp: %s.%06ld\n", time_buf, pkthdr->ts.tv_usec);
    printf("Captured Length: %d bytes\n", pkthdr->caplen);
    printf("Raw Bytes (first 16): ");
    print_hex(packet, pkthdr->caplen);
    printf("----------------------------------------------\n");
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