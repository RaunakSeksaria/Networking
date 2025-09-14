#ifndef SHAM_H
#define SHAM_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stddef.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>

// S.H.A.M. Header Structure as specified
struct sham_header {
    uint32_t seq_num;      // Sequence Number
    uint32_t ack_num;      // Acknowledgment Number
    uint16_t flags;        // Control flags (SYN, ACK, FIN)
    uint16_t window_size;  // Flow control window size
};

// Flag definitions
#define SYN_FLAG 0x1
#define ACK_FLAG 0x2
#define FIN_FLAG 0x4

// Protocol constants
#define DATA_CHUNK_SIZE 1024
#define MAX_PACKET_SIZE (sizeof(struct sham_header) + DATA_CHUNK_SIZE)
#define RECEIVE_BUFFER_SIZE 4096  // Receiver buffer size for flow control
#define MAX_WINDOW_SIZE 2048      // Maximum advertised window size
#define SLIDING_WINDOW_SIZE 10    // Maximum unacked packets in flight
#define RTO_TIMEOUT_MS 500        // Retransmission timeout in milliseconds
#define MAX_RETRIES 5             // Maximum retransmission attempts

// Packet information for retransmission
typedef struct {
    uint32_t seq_num;
    size_t data_len;
    char data[DATA_CHUNK_SIZE];
    struct timeval send_time;
    int retry_count;
    int acked;
} packet_info_t;

// Out-of-order packet buffer for receiver
typedef struct {
    uint32_t seq_num;
    size_t data_len;
    char data[DATA_CHUNK_SIZE];
} buffered_packet_t;

// Flow control structures with retransmission support
typedef struct {
    uint32_t last_byte_sent;
    uint32_t last_byte_acked;
    uint32_t advertised_window;
    packet_info_t sliding_window[SLIDING_WINDOW_SIZE];
    int window_base;
    int next_seq_num;
    char send_buffer[RECEIVE_BUFFER_SIZE];
} sender_state_t;

typedef struct {
    uint32_t next_expected_seq;
    uint32_t last_byte_received;
    uint32_t available_buffer_space;
    char receive_buffer[RECEIVE_BUFFER_SIZE];
    size_t buffer_used;
    buffered_packet_t out_of_order_buffer[SLIDING_WINDOW_SIZE];
    int buffered_count;
} receiver_state_t;

// Function declarations
void print_sham_header(const char* prefix, const struct sham_header* header);
int send_sham_packet(int sock_fd, const struct sockaddr_in* dest_addr,
                     const struct sham_header* header, const void* data, size_t data_len);
int recv_sham_packet(int sock_fd, struct sockaddr_in* src_addr, socklen_t* src_addr_len,
                     struct sham_header* header, void* data_buffer, size_t data_buffer_size);

// Flow control functions
void init_sender_state(sender_state_t* state, uint32_t initial_seq);
void init_receiver_state(receiver_state_t* state, uint32_t initial_seq);
int can_send_data(const sender_state_t* state, size_t data_size);
void update_sender_on_ack(sender_state_t* state, uint32_t ack_num, uint16_t window_size);
uint16_t calculate_advertised_window(const receiver_state_t* state);
int process_received_data(receiver_state_t* state, uint32_t seq_num, const void* data, size_t data_len);

// Retransmission functions
int send_data_with_retransmission(int sock_fd, const struct sockaddr_in* dest_addr,
                                 sender_state_t* state, uint32_t seq_num, const void* data, size_t data_len);
void check_timeouts_and_retransmit(int sock_fd, const struct sockaddr_in* dest_addr, sender_state_t* state);
int has_unacked_packets(const sender_state_t* state);
void process_cumulative_ack(sender_state_t* state, uint32_t ack_num);
int buffer_out_of_order_packet(receiver_state_t* state, uint32_t seq_num, const void* data, size_t data_len);
int process_buffered_packets(receiver_state_t* state);
long get_time_diff_ms(const struct timeval* start, const struct timeval* end);

// Logging functions
void init_logging(const char* program_name);
void close_logging(void);
void log_event(const char* format, ...);
void log_snd_syn(uint32_t seq_num);
void log_rcv_syn(uint32_t seq_num);
void log_snd_syn_ack(uint32_t seq_num, uint32_t ack_num);
void log_rcv_ack_for_syn(void);
void log_snd_data(uint32_t seq_num, size_t len);
void log_rcv_data(uint32_t seq_num, size_t len);
void log_snd_ack(uint32_t ack_num, uint16_t window_size);
void log_rcv_ack(uint32_t ack_num);
void log_timeout(uint32_t seq_num);
void log_retx_data(uint32_t seq_num, size_t len);
void log_flow_win_update(uint16_t new_window_size);
void log_drop_data(uint32_t seq_num);
void log_snd_fin(uint32_t seq_num);
void log_rcv_fin(uint32_t seq_num);
void log_snd_ack_for_fin(void);

// Global logging state
extern FILE* log_file;
extern int logging_enabled;

#endif