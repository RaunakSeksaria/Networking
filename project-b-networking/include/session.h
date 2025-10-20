#ifndef SESSION_H
#define SESSION_H

#include <pcap.h>
#include <time.h>

#define MAX_PACKETS 10000

typedef struct {
    unsigned char *data;
    unsigned int length;
    struct timeval timestamp;
} stored_packet_t;

typedef struct {
    stored_packet_t *packets;
    unsigned int count;
    unsigned int capacity;
    time_t session_time;
    char *interface_name;
    char *filter_used;
} session_t;

// Global session management
void session_init();
void session_cleanup();
void session_start_new(const char *interface, const char *filter);
int session_add_packet(const unsigned char *data, unsigned int length, struct timeval timestamp);
int session_has_data();
void session_print_summary();
void session_inspect();

#endif // SESSION_H