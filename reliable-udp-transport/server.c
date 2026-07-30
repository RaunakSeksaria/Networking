#include "sham.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>


// Global variables for signal handling
static int server_running = 1;

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nShutting down server...\n");
        server_running = 0;
    }
}

// Helper function to print header details
void print_sham_header(const char* prefix, const struct sham_header* header) {
    printf("%s SEQ=%u, ACK=%u, Flags=[%s%s%s], Win=%u\n",
           prefix,
           header->seq_num,
           header->ack_num,
           (header->flags & SYN_FLAG) ? "SYN " : "",
           (header->flags & ACK_FLAG) ? "ACK " : "",
           (header->flags & FIN_FLAG) ? "FIN " : "",
           header->window_size);
}

// Function to send a S.H.A.M. packet
int send_sham_packet(int sock_fd, const struct sockaddr_in* dest_addr,
                     const struct sham_header* header, const void* data, size_t data_len) {
    char packet_buffer[MAX_PACKET_SIZE];
    struct sham_header net_header;
    
    // Convert to network byte order
    net_header.seq_num = htonl(header->seq_num);
    net_header.ack_num = htonl(header->ack_num);
    net_header.flags = htons(header->flags);
    net_header.window_size = htons(header->window_size);

    memcpy(packet_buffer, &net_header, sizeof(struct sham_header));
    
    if (data != NULL && data_len > 0) {
        if (data_len > DATA_CHUNK_SIZE) {
            data_len = DATA_CHUNK_SIZE;
        }
        memcpy(packet_buffer + sizeof(struct sham_header), data, data_len);
    }
    
    ssize_t sent_bytes = sendto(sock_fd, packet_buffer, sizeof(struct sham_header) + data_len, 0,
                                (const struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));
    return (sent_bytes < 0) ? -1 : (int)sent_bytes;
}

// Function to receive a S.H.A.M. packet
int recv_sham_packet(int sock_fd, struct sockaddr_in* src_addr, socklen_t* src_addr_len,
                     struct sham_header* header, void* data_buffer, size_t data_buffer_size) {
    char packet_buffer[MAX_PACKET_SIZE];
    ssize_t received_bytes = recvfrom(sock_fd, packet_buffer, MAX_PACKET_SIZE, 0,
                                      (struct sockaddr*)src_addr, src_addr_len);
    
    if (received_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; // Timeout
        return -1;
    }
    
    if (received_bytes < (ssize_t)sizeof(struct sham_header)) {
        return -1;
    }
    
    struct sham_header net_header;
    memcpy(&net_header, packet_buffer, sizeof(struct sham_header));
    
    // Convert from network byte order
    header->seq_num = ntohl(net_header.seq_num);
    header->ack_num = ntohl(net_header.ack_num);
    header->flags = ntohs(net_header.flags);
    header->window_size = ntohs(net_header.window_size);

    size_t data_len = received_bytes - sizeof(struct sham_header);
    if (data_len > 0 && data_buffer != NULL) {
        if (data_len > data_buffer_size) data_len = data_buffer_size;
        memcpy(data_buffer, packet_buffer + sizeof(struct sham_header), data_len);
    }
    
    return (int)data_len;
}

// Server configuration
typedef struct {
    int port;
    int chat_mode;
    float loss_rate;
} server_config;

// Parse command line arguments
server_config parse_arguments(int argc, char *argv[]) {
    server_config cfg = {0};

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port> [--chat] [loss_rate]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    cfg.port = atoi(argv[1]);
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--chat") == 0) {
            cfg.chat_mode = 1;
        } else {
            cfg.loss_rate = atof(argv[i]);
        }
    }
    return cfg;
}

// Setup server socket
int setup_server_socket(int port) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    return sock_fd;
}

// Perform three-way handshake
int perform_handshake(int sock_fd, struct sockaddr_in *client_addr, socklen_t *client_addr_len,
                     uint32_t *server_seq, uint32_t *client_seq) {
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];

    printf("Waiting for SYN...\n");
    
    // Step 1: Wait for SYN
    while (server_running) {
        int len = recv_sham_packet(sock_fd, client_addr, client_addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);

        if (header.flags & SYN_FLAG) {
            *client_seq = header.seq_num;
            *server_seq = 1000; // Our initial sequence number
            log_rcv_syn(*client_seq);
            
            // Step 2: Send SYN-ACK
            struct sham_header syn_ack = {
                .seq_num = *server_seq,
                .ack_num = *client_seq + 1,
                .flags = SYN_FLAG | ACK_FLAG,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, client_addr, &syn_ack, NULL, 0);
            print_sham_header("SND", &syn_ack);
            log_snd_syn_ack(*server_seq, *client_seq + 1);
            break;
        }
    }
    
    if (!server_running) return -1;

    // Step 3: Wait for ACK
    printf("Waiting for ACK...\n");
    while (server_running) {
        int len = recv_sham_packet(sock_fd, client_addr, client_addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);

        if ((header.flags & ACK_FLAG) && header.ack_num == *server_seq + 1) {
            log_rcv_ack_for_syn();
            printf("Connection established!\n");
            *client_seq = header.seq_num;
            *server_seq = *server_seq + 1;
            return 0;
        }
    }
    
    return -1;
}

// Handle four-way FIN handshake
void handle_fin_handshake(int sock_fd, struct sockaddr_in *client_addr, 
                         struct sham_header *fin_header, uint32_t server_seq) {
    printf("Received FIN. Starting termination handshake...\n");
    
    // Step 2: Send ACK for client's FIN
    struct sham_header fin_ack = {
        .seq_num = server_seq,
        .ack_num = fin_header->seq_num + 1,
        .flags = ACK_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, client_addr, &fin_ack, NULL, 0);
    print_sham_header("SND", &fin_ack);

    // Step 3: Send our own FIN
    struct sham_header server_fin = {
        .seq_num = server_seq,
        .ack_num = fin_header->seq_num + 1,
        .flags = FIN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, client_addr, &server_fin, NULL, 0);
    print_sham_header("SND", &server_fin);

    // Step 4: Wait for final ACK
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];
    socklen_t addr_len = sizeof(*client_addr);
    
    while (server_running) {
        int len = recv_sham_packet(sock_fd, client_addr, &addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);
        if ((header.flags & ACK_FLAG) && header.ack_num == server_seq + 1) {
            printf("Connection terminated gracefully.\n");
            break;
        }
    }
}

// Chat mode implementation
void chat_mode(int sock_fd, struct sockaddr_in *client_addr, socklen_t client_addr_len,
               uint32_t server_seq, uint32_t client_seq) {
    (void)client_seq; // Suppress unused parameter warning
    fd_set fds;
    char data_buffer[DATA_CHUNK_SIZE];
    struct sham_header header;
    socklen_t addr_len = client_addr_len;

    printf("Chat mode enabled. Type messages to send. Type '/quit' to exit.\n");

    while (server_running) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock_fd, &fds);
        int max_fd = (sock_fd > STDIN_FILENO ? sock_fd : STDIN_FILENO) + 1;

        struct timeval timeout = {1, 0}; // 1 second timeout
        int result = select(max_fd, &fds, NULL, NULL, &timeout);
        if (result < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (result == 0) continue; // Timeout

        // User typed something
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (!fgets(data_buffer, sizeof(data_buffer), stdin)) break;
            data_buffer[strcspn(data_buffer, "\n")] = 0; // strip newline

            if (strncmp(data_buffer, "/quit", 5) == 0) {
                // Send FIN to initiate termination
                struct sham_header fin = {
                    .seq_num = server_seq,
                    .ack_num = 0,
                    .flags = FIN_FLAG,
                    .window_size = DATA_CHUNK_SIZE
                };
                send_sham_packet(sock_fd, client_addr, &fin, NULL, 0);
                print_sham_header("SND", &fin);
                break;
            }

            // Send message
            struct sham_header msg_hdr = {
                .seq_num = server_seq,
                .ack_num = 0,
                .flags = 0,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, client_addr, &msg_hdr, data_buffer, strlen(data_buffer));
            print_sham_header("SND", &msg_hdr);
            server_seq += strlen(data_buffer);
        }

        // Incoming message from client
        if (FD_ISSET(sock_fd, &fds)) {
            int msg_len = recv_sham_packet(sock_fd, client_addr, &addr_len, &header, 
                                         data_buffer, sizeof(data_buffer));
            if (msg_len > 0) {
                data_buffer[msg_len] = '\0';
                printf("Client: %s\n", data_buffer);
            } else if (msg_len < 0) {
                continue;
            }

            if (header.flags & FIN_FLAG) {
                handle_fin_handshake(sock_fd, client_addr, &header, server_seq);
                break;
            }
        }
    }
}

// File transfer mode implementation with flow control
void file_transfer_mode(int sock_fd, struct sockaddr_in *client_addr, socklen_t client_addr_len,
                       uint32_t server_seq, uint32_t expected_seq) {
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];
    char filename[DATA_CHUNK_SIZE];
    socklen_t addr_len = client_addr_len;
    receiver_state_t receiver_state;
    
    // Initialize flow control state
    init_receiver_state(&receiver_state, expected_seq);

    printf("File transfer mode with flow control. Receiving file...\n");

    // First, receive the filename
    int filename_len = recv_sham_packet(sock_fd, client_addr, &addr_len, &header, 
                                      filename, sizeof(filename));
    if (filename_len <= 0) {
        printf("Failed to receive filename\n");
        return;
    }
    
    filename[filename_len] = '\0';
    print_sham_header("RCV", &header);
    log_rcv_data(header.seq_num, filename_len);
    printf("Receiving file as: %s\n", filename);
    
    // Process filename with flow control
    if (process_received_data(&receiver_state, header.seq_num, filename, filename_len)) {
        expected_seq += filename_len;
    }
    
    // Send ACK for filename with current window size
    uint16_t current_window = calculate_advertised_window(&receiver_state);
    struct sham_header ack = {
        .seq_num = server_seq,
        .ack_num = expected_seq,
        .flags = ACK_FLAG,
        .window_size = current_window
    };
    send_sham_packet(sock_fd, client_addr, &ack, NULL, 0);
    print_sham_header("SND", &ack);
    log_snd_ack(expected_seq, current_window);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen failed");
        return;
    }

    while (server_running) {
        int data_len = recv_sham_packet(sock_fd, client_addr, &addr_len, &header, 
                                      buffer, sizeof(buffer));
        if (data_len < 0) continue;
        
        print_sham_header("RCV", &header);

        if (header.flags & FIN_FLAG) {
            handle_fin_handshake(sock_fd, client_addr, &header, server_seq);
            break;
        }

        if (data_len > 0) {
            log_rcv_data(header.seq_num, data_len);
            
            // Check if this is the next expected packet
            if (header.seq_num == receiver_state.next_expected_seq) {
                // In-order packet - process immediately
                if (process_received_data(&receiver_state, header.seq_num, buffer, data_len)) {
                    fwrite(buffer, 1, data_len, fp);
                    fflush(fp);
                    expected_seq = receiver_state.next_expected_seq;
                    printf("Received in-order packet: SEQ=%u, LEN=%d\n", header.seq_num, data_len);
                    
                    // Try to process any buffered out-of-order packets
                    size_t old_buffer_used = receiver_state.buffer_used;
                    int processed = process_buffered_packets(&receiver_state);
                    if (processed > 0) {
                        printf("Processed %d buffered packets\n", processed);
                        // Write the newly processed buffered data to file
                        size_t new_data_len = receiver_state.buffer_used - old_buffer_used;
                        if (new_data_len > 0) {
                            fwrite(receiver_state.receive_buffer + old_buffer_used, 1, new_data_len, fp);
                            fflush(fp);
                            printf("Wrote %zu bytes of buffered data to file\n", new_data_len);
                        }
                        expected_seq = receiver_state.next_expected_seq;
                    }
                    
                    // Everything in the buffer has already been written to the
                    // file above, so the application has consumed it. Release
                    // the whole buffer, otherwise the advertised window shrinks
                    // below one chunk and the sender blocks permanently.
                    if (receiver_state.buffer_used > 0) {
                        size_t consumed = receiver_state.buffer_used;
                        receiver_state.buffer_used = 0;
                        printf("Flow Control: Consumed %zu bytes, buffer now %zu/%d\n",
                               consumed, receiver_state.buffer_used, RECEIVE_BUFFER_SIZE);
                    }
                }
            } else if (header.seq_num > receiver_state.next_expected_seq) {
                // Out-of-order packet - buffer it
                if (buffer_out_of_order_packet(&receiver_state, header.seq_num, buffer, data_len)) {
                    printf("Buffered out-of-order packet: SEQ=%u (expecting %u), buffered_count=%d\n", 
                           header.seq_num, receiver_state.next_expected_seq, receiver_state.buffered_count);
                } else {
                    printf("Failed to buffer out-of-order packet: SEQ=%u (buffer full or duplicate)\n", 
                           header.seq_num);
                }
            } else {
                printf("Received duplicate packet: SEQ=%u (already processed)\n", header.seq_num);
            }
        }

        // Send ACK with updated window size
        current_window = calculate_advertised_window(&receiver_state);
        struct sham_header flow_ack = {
            .seq_num = server_seq,
            .ack_num = expected_seq,
            .flags = ACK_FLAG,
            .window_size = current_window
        };
        send_sham_packet(sock_fd, client_addr, &flow_ack, NULL, 0);
        print_sham_header("SND", &flow_ack);
        printf("Flow Control: Advertised window size: %u\n", current_window);
    }

    fclose(fp);
    printf("File transfer completed. Saved as '%s'\n", filename);
}

// Main function
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logging
    init_logging("server");
    
    server_config cfg = parse_arguments(argc, argv);
    int sock_fd = setup_server_socket(cfg.port);
    
    printf("Server listening on port %d... Chat mode: %s, Loss rate: %.2f\n", 
           cfg.port, cfg.chat_mode ? "ON" : "OFF", cfg.loss_rate);

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    uint32_t server_seq, client_seq;

    if (perform_handshake(sock_fd, &client_addr, &client_addr_len, &server_seq, &client_seq) < 0) {
        printf("Handshake failed\n");
        close(sock_fd);
        return 1;
    }

    if (cfg.chat_mode) {
        chat_mode(sock_fd, &client_addr, client_addr_len, server_seq, client_seq);
    } else {
        file_transfer_mode(sock_fd, &client_addr, client_addr_len, server_seq, client_seq);
    }

    close(sock_fd);
    close_logging();
    return 0;
}
