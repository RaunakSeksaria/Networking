#include "sham.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

// Global logging state
FILE* log_file = NULL;
int logging_enabled = 0;

// Flow control function implementations
void init_sender_state(sender_state_t* state, uint32_t initial_seq) {
    state->last_byte_sent = initial_seq;
    state->last_byte_acked = initial_seq;
    state->advertised_window = MAX_WINDOW_SIZE;
    state->window_base = 0;
    state->next_seq_num = 0;
    memset(state->send_buffer, 0, sizeof(state->send_buffer));
    memset(state->sliding_window, 0, sizeof(state->sliding_window));
}

void init_receiver_state(receiver_state_t* state, uint32_t initial_seq) {
    state->next_expected_seq = initial_seq;
    state->last_byte_received = initial_seq - 1;
    state->available_buffer_space = RECEIVE_BUFFER_SIZE;
    state->buffer_used = 0;
    state->buffered_count = 0;
    memset(state->receive_buffer, 0, sizeof(state->receive_buffer));
    memset(state->out_of_order_buffer, 0, sizeof(state->out_of_order_buffer));
}

int can_send_data(const sender_state_t* state, size_t data_size) {
    uint32_t unacked_data = state->last_byte_sent - state->last_byte_acked;
    return (unacked_data + data_size <= state->advertised_window);
}

void update_sender_on_ack(sender_state_t* state, uint32_t ack_num, uint16_t window_size) {
    if (ack_num > state->last_byte_acked) {
        state->last_byte_acked = ack_num;
    }
    state->advertised_window = window_size;
    printf("Flow Control: LastByteAcked=%u, AdvertisedWindow=%u, Unacked=%u\n", 
           state->last_byte_acked, state->advertised_window, 
           state->last_byte_sent - state->last_byte_acked);
}

uint16_t calculate_advertised_window(const receiver_state_t* state) {
    uint16_t available = (uint16_t)(RECEIVE_BUFFER_SIZE - state->buffer_used);
    return (available > MAX_WINDOW_SIZE) ? MAX_WINDOW_SIZE : available;
}

int process_received_data(receiver_state_t* state, uint32_t seq_num, const void* data, size_t data_len) {
    if (seq_num != state->next_expected_seq) {
        printf("Out of order packet: expected %u, got %u\n", state->next_expected_seq, seq_num);
        return 0; // Out of order, don't process
    }
    
    if (state->buffer_used + data_len > RECEIVE_BUFFER_SIZE) {
        printf("Receive buffer full, dropping packet\n");
        return 0; // Buffer full
    }
    
    memcpy(state->receive_buffer + state->buffer_used, data, data_len);
    state->buffer_used += data_len;
    state->next_expected_seq += data_len;
    state->last_byte_received += data_len;
    
    printf("Flow Control: Received %zu bytes, buffer used: %zu/%d\n", 
           data_len, state->buffer_used, RECEIVE_BUFFER_SIZE);
    
    return 1; // Successfully processed
}

// Logging function implementations
void init_logging(const char* program_name) {
    const char* rudp_log = getenv("RUDP_LOG");
    if (rudp_log && strcmp(rudp_log, "1") == 0) {
        logging_enabled = 1;
        char log_filename[256];
        snprintf(log_filename, sizeof(log_filename), "%s_log.txt", program_name);
        log_file = fopen(log_filename, "w");
        if (!log_file) {
            perror("Failed to open log file");
            logging_enabled = 0;
        }
    }
}

void close_logging(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    logging_enabled = 0;
}

void log_event(const char* format, ...) {
    if (!logging_enabled || !log_file) return;
    
    char time_buffer[30];
    struct timeval tv;
    time_t curtime;
    
    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;
    
    strftime(time_buffer, 30, "%Y-%m-%d %H:%M:%S", localtime(&curtime));
    fprintf(log_file, "[%s.%06ld] [LOG] ", time_buffer, tv.tv_usec);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}

void log_snd_syn(uint32_t seq_num) {
    log_event("SND SYN SEQ=%u", seq_num);
}

void log_rcv_syn(uint32_t seq_num) {
    log_event("RCV SYN SEQ=%u", seq_num);
}

void log_snd_syn_ack(uint32_t seq_num, uint32_t ack_num) {
    log_event("SND SYN-ACK SEQ=%u ACK=%u", seq_num, ack_num);
}

void log_rcv_ack_for_syn(void) {
    log_event("RCV ACK FOR SYN");
}

void log_snd_data(uint32_t seq_num, size_t len) {
    log_event("SND DATA SEQ=%u LEN=%zu", seq_num, len);
}

void log_rcv_data(uint32_t seq_num, size_t len) {
    log_event("RCV DATA SEQ=%u LEN=%zu", seq_num, len);
}

void log_snd_ack(uint32_t ack_num, uint16_t window_size) {
    log_event("SND ACK=%u WIN=%u", ack_num, window_size);
}

void log_rcv_ack(uint32_t ack_num) {
    log_event("RCV ACK=%u", ack_num);
}

void log_timeout(uint32_t seq_num) {
    log_event("TIMEOUT SEQ=%u", seq_num);
}

void log_retx_data(uint32_t seq_num, size_t len) {
    log_event("RETX DATA SEQ=%u LEN=%zu", seq_num, len);
}

void log_flow_win_update(uint16_t new_window_size) {
    log_event("FLOW WIN UPDATE=%u", new_window_size);
}

void log_drop_data(uint32_t seq_num) {
    log_event("DROP DATA SEQ=%u", seq_num);
}

void log_snd_fin(uint32_t seq_num) {
    log_event("SND FIN SEQ=%u", seq_num);
}

void log_rcv_fin(uint32_t seq_num) {
    log_event("RCV FIN SEQ=%u", seq_num);
}

void log_snd_ack_for_fin(void) {
    log_event("SND ACK FOR FIN");
}

// Retransmission function implementations
long get_time_diff_ms(const struct timeval* start, const struct timeval* end) {
    return (end->tv_sec - start->tv_sec) * 1000 + (end->tv_usec - start->tv_usec) / 1000;
}

int send_data_with_retransmission(int sock_fd, const struct sockaddr_in* dest_addr,
                                 sender_state_t* state, uint32_t seq_num, const void* data, size_t data_len) {
    // Check if sliding window is full
    if (state->next_seq_num - state->window_base >= SLIDING_WINDOW_SIZE) {
        return 0; // Window full, cannot send
    }
    
    // Find slot in sliding window
    int slot = state->next_seq_num % SLIDING_WINDOW_SIZE;
    packet_info_t* packet = &state->sliding_window[slot];
    
    // Store packet information
    packet->seq_num = seq_num;
    packet->data_len = data_len;
    memcpy(packet->data, data, data_len);
    gettimeofday(&packet->send_time, NULL);
    packet->retry_count = 0;
    packet->acked = 0;
    
    // Send the packet
    struct sham_header header = {
        .seq_num = seq_num,
        .ack_num = 0,
        .flags = 0,
        .window_size = DATA_CHUNK_SIZE
    };
    
    // Simulate packet loss by not sending certain packets
    const char* loss_env = getenv("PACKET_LOSS");
    int should_drop = 0;
    if (loss_env && strcmp(loss_env, "1") == 0) {
        // Force loss of specific packets for testing
        static int packet_count = 0;
        packet_count++;
        if (packet_count == 2 || packet_count == 4) { // Drop 2nd and 4th data packets
            should_drop = 1;
            log_drop_data(seq_num);
            printf("Simulated packet loss: SEQ=%u (packet #%d) - not sending\n", seq_num, packet_count);
        }
    }
    
    int result;
    if (should_drop) {
        result = data_len; // Pretend it was sent successfully
    } else {
        result = send_sham_packet(sock_fd, dest_addr, &header, data, data_len);
        if (result > 0) {
            log_snd_data(seq_num, data_len);
        }
    }
    
    if (result > 0) {
        state->last_byte_sent += data_len;
        state->next_seq_num++;
    }
    
    return result;
}

void check_timeouts_and_retransmit(int sock_fd, const struct sockaddr_in* dest_addr, sender_state_t* state) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    for (int i = state->window_base; i < state->next_seq_num; i++) {
        int slot = i % SLIDING_WINDOW_SIZE;
        packet_info_t* packet = &state->sliding_window[slot];
        
        if (!packet->acked && packet->retry_count < MAX_RETRIES) {
            long elapsed = get_time_diff_ms(&packet->send_time, &current_time);
            
            if (elapsed >= RTO_TIMEOUT_MS) {
                // Timeout occurred, retransmit
                log_timeout(packet->seq_num);
                
                struct sham_header header = {
                    .seq_num = packet->seq_num,
                    .ack_num = 0,
                    .flags = 0,
                    .window_size = DATA_CHUNK_SIZE
                };
                
                send_sham_packet(sock_fd, dest_addr, &header, packet->data, packet->data_len);
                log_retx_data(packet->seq_num, packet->data_len);
                
                packet->send_time = current_time;
                packet->retry_count++;
            }
        }
    }
}

int has_unacked_packets(const sender_state_t* state) {
    return state->window_base < state->next_seq_num;
}

void process_cumulative_ack(sender_state_t* state, uint32_t ack_num) {
    // Mark packets as acknowledged up to ack_num
    while (state->window_base < state->next_seq_num) {
        int slot = state->window_base % SLIDING_WINDOW_SIZE;
        packet_info_t* packet = &state->sliding_window[slot];
        
        if (packet->seq_num + packet->data_len <= ack_num) {
            packet->acked = 1;
            state->window_base++;
        } else {
            break;
        }
    }
    
    if (ack_num > state->last_byte_acked) {
        state->last_byte_acked = ack_num;
    }
}

int buffer_out_of_order_packet(receiver_state_t* state, uint32_t seq_num, const void* data, size_t data_len) {
    // Check if we have space in buffer
    if (state->buffered_count >= SLIDING_WINDOW_SIZE) {
        return 0; // Buffer full
    }
    
    // Check if packet is already buffered
    for (int i = 0; i < state->buffered_count; i++) {
        if (state->out_of_order_buffer[i].seq_num == seq_num) {
            return 0; // Already buffered
        }
    }
    
    // Add to buffer
    buffered_packet_t* buffered = &state->out_of_order_buffer[state->buffered_count];
    buffered->seq_num = seq_num;
    buffered->data_len = data_len;
    memcpy(buffered->data, data, data_len);
    state->buffered_count++;
    
    return 1;
}

int process_buffered_packets(receiver_state_t* state) {
    int processed = 0;
    int found = 1;
    
    while (found && state->buffered_count > 0) {
        found = 0;
        
        for (int i = 0; i < state->buffered_count; i++) {
            if (state->out_of_order_buffer[i].seq_num == state->next_expected_seq) {
                // Found next expected packet in buffer
                buffered_packet_t* packet = &state->out_of_order_buffer[i];
                
                // Process the packet (copy to receive buffer)
                if (state->buffer_used + packet->data_len <= RECEIVE_BUFFER_SIZE) {
                    memcpy(state->receive_buffer + state->buffer_used, packet->data, packet->data_len);
                    state->buffer_used += packet->data_len;
                    state->next_expected_seq += packet->data_len;
                    processed++;
                    
                    // Remove from buffer by moving last element to this position
                    if (i < state->buffered_count - 1) {
                        state->out_of_order_buffer[i] = state->out_of_order_buffer[state->buffered_count - 1];
                    }
                    state->buffered_count--;
                    
                    found = 1;
                    break;
                }
            }
        }
    }
    
    return processed;
}
