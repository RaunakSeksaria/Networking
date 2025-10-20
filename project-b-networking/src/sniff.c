#include "../include/sniff.h"
#include "../include/decode.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

static volatile sig_atomic_t stop_flag = 0;
static pcap_t *g_handle = NULL;

static void sigint_handler(int sig) {
    (void)sig;
    stop_flag = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

int start_sniff(const char *dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        return -1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
        pcap_close(handle);
        return -1;
    }

    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "pcap_get_selectable_fd failed\n");
        pcap_close(handle);
        return -1;
    }

    // setup signal
    signal(SIGINT, sigint_handler);
    g_handle = handle;
    stop_flag = 0;

    printf("\n[C-Shark] Starting capture on '%s'. Press Ctrl+C to stop, Ctrl+D to exit entire program.\n\n", dev_name);

    // make stdin non-blocking for EOF detection
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);

    while (!stop_flag) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(pcap_fd, &readfds);
        int maxfd = (pcap_fd > STDIN_FILENO) ? pcap_fd : STDIN_FILENO;
        struct timeval tv = { 0, 200000 }; // 200ms
        int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (ret == -1) {
            perror("select");
            break;
        }
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char c;
            ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n == 0) {
                // EOF -> exit entire program
                printf("\n[C-Shark] EOF detected, exiting.\n");
                pcap_close(handle);
                exit(0);
            }
        }
        if (FD_ISSET(pcap_fd, &readfds)) {
            pcap_dispatch(handle, -1, decode_packet, NULL);
        }
    }

    // restore stdin flags
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags);

    pcap_close(handle);
    g_handle = NULL;
    printf("\n[C-Shark] Capture stopped.\n");
    return 0;
}