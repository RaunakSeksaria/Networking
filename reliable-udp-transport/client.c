#define _GNU_SOURCE
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
static int client_running = 1;

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nShutting down client...\n");
        client_running = 0;
    }
}

// Client configuration
typedef struct {
    char *server_ip;
    int server_port;
    char *input_file;
    char *output_file;
    int chat_mode;
    float loss_rate;
} client_config;

// Parse command line arguments
client_config parse_arguments(int argc, char *argv[]) {
    client_config cfg = {0};

    if (argc < 4) {
        fprintf(stderr,
            "Usage:\n"
            "File Transfer: %s <server_ip> <server_port> <input_file> <output_file_name> [loss_rate]\n"
            "Chat Mode:     %s <server_ip> <server_port> --chat [loss_rate]\n",
            argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    cfg.server_ip = argv[1];
    cfg.server_port = atoi(argv[2]);

    if (strcmp(argv[3], "--chat") == 0) {
        cfg.chat_mode = 1;
        if (argc == 5) cfg.loss_rate = atof(argv[4]);
    } else {
        cfg.input_file = argv[3];
        cfg.output_file = argv[4];
        if (argc == 6) cfg.loss_rate = atof(argv[5]);
    }

    return cfg;
}

// Setup client socket
int setup_socket(struct sockaddr_in *server_addr, client_config cfg) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(cfg.server_port);
    server_addr->sin_addr.s_addr = inet_addr(cfg.server_ip);

    return sock_fd;
}

// Perform three-way handshake
int perform_handshake(int sock_fd, struct sockaddr_in *server_addr, socklen_t *addr_len,
                     uint32_t *client_seq, uint32_t *server_seq) {
    *client_seq = 500; // Our initial sequence number
    
    // Step 1: Send SYN
    struct sham_header syn = {
        .seq_num = *client_seq,
        .ack_num = 0,
        .flags = SYN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, server_addr, &syn, NULL, 0);
    print_sham_header("SND", &syn);
    log_snd_syn(*client_seq);

    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];

    // Step 2: Wait for SYN-ACK
    printf("Waiting for SYN-ACK...\n");
    while (client_running) {
        int len = recv_sham_packet(sock_fd, server_addr, addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);
        
        if ((header.flags & SYN_FLAG) && (header.flags & ACK_FLAG) && header.ack_num == *client_seq + 1) {
            *server_seq = header.seq_num;
            *client_seq = *client_seq + 1;
            log_rcv_syn(*server_seq);
            
            // Step 3: Send ACK
            struct sham_header ack = {
                .seq_num = *client_seq,
                .ack_num = *server_seq + 1,
                .flags = ACK_FLAG,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, server_addr, &ack, NULL, 0);
            print_sham_header("SND", &ack);
            log_snd_ack(*server_seq + 1, DATA_CHUNK_SIZE);
            printf("Connection established!\n");
            return 0;
        }
    }
    
    return -1;
}

// Perform four-way FIN handshake as initiator
void perform_fin_handshake(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, uint32_t seq_num) {
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];
    
    // Step 1: Send FIN
    struct sham_header fin = {
        .seq_num = seq_num,
        .ack_num = 0,
        .flags = FIN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, server_addr, &fin, NULL, 0);
    print_sham_header("SND", &fin);
    log_snd_fin(seq_num);
    printf("Initiating connection termination...\n");

    // Step 2: Wait for ACK of our FIN
    while (client_running) {
        int len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);
        if ((header.flags & ACK_FLAG) && header.ack_num == seq_num + 1) {
            printf("Server acknowledged FIN.\n");
            break;
        }
    }

    // Step 3: Wait for server's FIN
    while (client_running) {
        int len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);
        if (header.flags & FIN_FLAG) {
            printf("Received FIN from server.\n");
            // Step 4: Send final ACK
            struct sham_header final_ack = {
                .seq_num = seq_num + 1,
                .ack_num = header.seq_num + 1,
                .flags = ACK_FLAG,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, server_addr, &final_ack, NULL, 0);
            print_sham_header("SND", &final_ack);
            printf("Connection terminated gracefully.\n");
            break;
        }
    }
}

// Chat mode implementation
void chat_mode(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, uint32_t seq_num) {
    fd_set fds;
    char data_buffer[DATA_CHUNK_SIZE];
    struct sham_header header;

    printf("Chat mode enabled. Type messages to send. Type '/quit' to exit.\n");

    while (client_running) {
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
                perform_fin_handshake(sock_fd, server_addr, addr_len, seq_num);
                break;
            }

            // Send message
            struct sham_header msg_hdr = {
                .seq_num = seq_num,
                .ack_num = 0,
                .flags = 0,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, server_addr, &msg_hdr, data_buffer, strlen(data_buffer));
            print_sham_header("SND", &msg_hdr);
            seq_num += strlen(data_buffer);
        }

        // Incoming message from server
        if (FD_ISSET(sock_fd, &fds)) {
            int msg_len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, 
                                         data_buffer, sizeof(data_buffer));
            if (msg_len > 0) {
                data_buffer[msg_len] = '\0';
                printf("Server: %s\n", data_buffer);
            } else if (msg_len < 0) {
                continue;
            }

            if (header.flags & FIN_FLAG) {
                printf("Server initiated connection termination.\n");
                // Send ACK for server's FIN
                struct sham_header ack = {
                    .seq_num = seq_num,
                    .ack_num = header.seq_num + 1,
                    .flags = ACK_FLAG,
                    .window_size = DATA_CHUNK_SIZE
                };
                send_sham_packet(sock_fd, server_addr, &ack, NULL, 0);
                print_sham_header("SND", &ack);
                
                // Send our FIN
                struct sham_header fin = {
                    .seq_num = seq_num,
                    .ack_num = header.seq_num + 1,
                    .flags = FIN_FLAG,
                    .window_size = DATA_CHUNK_SIZE
                };
                send_sham_packet(sock_fd, server_addr, &fin, NULL, 0);
                print_sham_header("SND", &fin);
                
                // Wait for final ACK
                while (client_running) {
                    int len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, 
                                             data_buffer, sizeof(data_buffer));
                    if (len < 0) continue;
                    print_sham_header("RCV", &header);
                    if ((header.flags & ACK_FLAG) && header.ack_num == seq_num + 1) {
                        printf("Connection terminated gracefully.\n");
                        break;
                    }
                }
                break;
            }
        }
    }
}

// File transfer mode implementation with flow control
void file_transfer_mode(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, 
                       const char* input_file, const char* output_file, uint32_t seq_num) {
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        perror("fopen failed");
        return;
    }

    char buffer[DATA_CHUNK_SIZE];
    struct sham_header header;
    size_t total_sent = 0;
    sender_state_t sender_state;
    
    // Initialize flow control state
    init_sender_state(&sender_state, seq_num);

    printf("File transfer mode with flow control. Sending file '%s' as '%s'...\n", input_file, output_file);

    // First, send the output filename
    if (!can_send_data(&sender_state, strlen(output_file))) {
        printf("Cannot send filename: window full\n");
        fclose(fp);
        return;
    }
    
    struct sham_header filename_hdr = {
        .seq_num = seq_num,
        .ack_num = 0,
        .flags = 0,
        .window_size = DATA_CHUNK_SIZE
    };
    
    send_sham_packet(sock_fd, server_addr, &filename_hdr, output_file, strlen(output_file));
    print_sham_header("SND", &filename_hdr);
    log_snd_data(seq_num, strlen(output_file));
    sender_state.last_byte_sent += strlen(output_file);
    
    // Wait for ACK
    int len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, buffer, sizeof(buffer));
        if (len >= 0) {
        print_sham_header("RCV", &header);
        if (header.flags & ACK_FLAG) {
            log_rcv_ack(header.ack_num);
            update_sender_on_ack(&sender_state, header.ack_num, header.window_size);
        }
    }
    
    seq_num += strlen(output_file);

    // New sliding window file transfer with retransmission
    int eof_reached = 0;
    char file_buffer[DATA_CHUNK_SIZE];
    
    while (client_running && (!eof_reached || has_unacked_packets(&sender_state))) {
        // Try to send new data if we haven't reached EOF and window has space
        if (!eof_reached && sender_state.next_seq_num - sender_state.window_base < SLIDING_WINDOW_SIZE) {
            size_t bytes_read = fread(file_buffer, 1, DATA_CHUNK_SIZE, fp);
            if (bytes_read > 0) {
                // Check flow control
                if (can_send_data(&sender_state, bytes_read)) {
                    int result = send_data_with_retransmission(sock_fd, server_addr, &sender_state, 
                                                             seq_num, file_buffer, bytes_read);
                    if (result > 0) {
                        total_sent += bytes_read;
                        seq_num += bytes_read;
                        printf("Sent %zu bytes, total: %zu, unacked: %d\n", 
                               bytes_read, total_sent, sender_state.next_seq_num - sender_state.window_base);
                    }
                } else {
                    printf("Flow control: Window full, waiting for ACKs...\n");
                    // Put data back in file stream (rewind)
                    fseek(fp, -bytes_read, SEEK_CUR);
                }
            } else {
                eof_reached = 1;
                printf("End of file reached, waiting for remaining ACKs...\n");
            }
        }
        
        // Check for timeouts and retransmit
        check_timeouts_and_retransmit(sock_fd, server_addr, &sender_state);
        
        // Try to receive ACKs (non-blocking)
        struct timeval timeout = {0, 10000}; // 10ms timeout
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        
        int result = select(sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(sock_fd, &read_fds)) {
            int ack_len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, 
                                         buffer, sizeof(buffer));
            if (ack_len >= 0) {
                print_sham_header("RCV", &header);
                if (header.flags & ACK_FLAG) {
                    log_rcv_ack(header.ack_num);
                    process_cumulative_ack(&sender_state, header.ack_num);
                    update_sender_on_ack(&sender_state, header.ack_num, header.window_size);
                    printf("Received ACK=%u, window_base=%d, next_seq=%d\n", 
                           header.ack_num, sender_state.window_base, sender_state.next_seq_num);
                }
            }
        }
        
        // Small delay to prevent busy waiting
        usleep(1000); // 1ms
    }
    
    // Send FIN after all data is acknowledged
    perform_fin_handshake(sock_fd, server_addr, addr_len, seq_num);

    fclose(fp);
    printf("File transfer completed. Total bytes sent: %zu\n", total_sent);
}

// Main function
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logging
    init_logging("client");
    
    client_config cfg = parse_arguments(argc, argv);
    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    int sock_fd = setup_socket(&server_addr, cfg);

    printf("Client connecting to %s:%d... Chat mode: %s, Loss rate: %.2f\n",
           cfg.server_ip, cfg.server_port, cfg.chat_mode ? "ON" : "OFF", cfg.loss_rate);

    uint32_t client_seq, server_seq;
    if (perform_handshake(sock_fd, &server_addr, &server_addr_len, &client_seq, &server_seq) < 0) {
        printf("Handshake failed\n");
        close(sock_fd);
        return 1;
    }

    if (cfg.chat_mode) {
        chat_mode(sock_fd, &server_addr, server_addr_len, client_seq);
    } else {
        file_transfer_mode(sock_fd, &server_addr, server_addr_len, cfg.input_file, cfg.output_file, client_seq);
    }

    close(sock_fd);
    close_logging();
    return 0;
}
