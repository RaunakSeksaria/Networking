#include "sham.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

// --- Helper function to print header details ---
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

// --- Function to send a S.H.A.M. packet ---
int send_sham_packet(int sock_fd, const struct sockaddr_in* dest_addr,
                     const struct sham_header* header, const void* data, size_t data_len) {
    char packet_buffer[MAX_PACKET_SIZE];
    struct sham_header net_header;
    net_header.seq_num = htonl(header->seq_num);
    net_header.ack_num = htonl(header->ack_num);
    net_header.flags = htons(header->flags);
    net_header.window_size = htons(header->window_size);

    memcpy(packet_buffer, &net_header, sizeof(struct sham_header));
    if (data != NULL && data_len > 0) {
        if (data_len > DATA_CHUNK_SIZE) {
            fprintf(stderr, "Warning: Data length exceeds DATA_CHUNK_SIZE. Truncating.\n");
            data_len = DATA_CHUNK_SIZE;
        }
        memcpy(packet_buffer + sizeof(struct sham_header), data, data_len);
    }
    ssize_t sent_bytes = sendto(sock_fd, packet_buffer, sizeof(struct sham_header) + data_len, 0,
                                (const struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));
    if (sent_bytes < 0) {
        perror("sendto failed");
        return -1;
    }
    return (int)sent_bytes;
}

// --- Function to receive a S.H.A.M. packet ---
int recv_sham_packet(int sock_fd, struct sockaddr_in* src_addr, socklen_t* src_addr_len,
                     struct sham_header* header, void* data_buffer, size_t data_buffer_size) {
    char packet_buffer[MAX_PACKET_SIZE];
    ssize_t received_bytes = recvfrom(sock_fd, packet_buffer, MAX_PACKET_SIZE, 0,
                                      (struct sockaddr*)src_addr, src_addr_len);
    if (received_bytes < 0) {
        perror("recvfrom failed");
        return -1;
    }
    if (received_bytes < sizeof(struct sham_header)) {
        fprintf(stderr, "Received packet too small to contain S.H.A.M. header.\n");
        return -1;
    }
    struct sham_header net_header;
    memcpy(&net_header, packet_buffer, sizeof(struct sham_header));
    header->seq_num = ntohl(net_header.seq_num);
    header->ack_num = ntohl(net_header.ack_num);
    header->flags = ntohs(net_header.flags);
    header->window_size = ntohs(net_header.window_size);

    size_t data_len = received_bytes - sizeof(struct sham_header);
    if (data_len > 0 && data_buffer != NULL) {
        if (data_len > data_buffer_size) {
            fprintf(stderr, "Warning: Received data truncated to fit buffer.\n");
            data_len = data_buffer_size;
        }
        memcpy(data_buffer, packet_buffer + sizeof(struct sham_header), data_len);
    }
    return (int)data_len;
}

// --- Function to handle four-way FIN handshake as responder ---
void handle_fin_handshake(int sock_fd, struct sockaddr_in* client_addr, struct sham_header* fin_header, uint32_t server_seq) {
    struct sham_header header;
    char data_buffer[DATA_CHUNK_SIZE];
    socklen_t client_addr_len = sizeof(*client_addr);
    
    printf("Received FIN from client. Starting termination handshake...\n");
    
    // Step 2: Send ACK for client's FIN
    struct sham_header fin_ack = {
        .seq_num = server_seq,
        .ack_num = fin_header->seq_num + 1,
        .flags = ACK_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, client_addr, &fin_ack, NULL, 0);
    print_sham_header("SND", &fin_ack);
    printf("Acknowledged client FIN.\n");

    // Step 3: Send our own FIN
    struct sham_header server_fin = {
        .seq_num = server_seq,
        .ack_num = fin_header->seq_num + 1,
        .flags = FIN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, client_addr, &server_fin, NULL, 0);
    print_sham_header("SND", &server_fin);
    printf("Sent server FIN.\n");

    // Step 4: Wait for final ACK from client
    while (1) {
        int ack_len = recv_sham_packet(sock_fd, client_addr, &client_addr_len, &header, data_buffer, sizeof(data_buffer));
        if (ack_len < 0) continue;
        print_sham_header("RCV", &header);
        if ((header.flags & ACK_FLAG) && header.ack_num == server_seq + 1) {
            printf("Received final ACK. Connection terminated gracefully.\n");
            break;
        }
    }
}
// --- Structures for configuration ---
typedef struct {
    int port;
    int chat_mode;
    float loss_rate;
} server_config;

// --- Function Declarations ---
server_config parse_arguments(int argc, char *argv[]);
int setup_server_socket(int port, struct sockaddr_in *server_addr);
void perform_handshake(int sock_fd, struct sockaddr_in *client_addr, socklen_t *client_addr_len, uint32_t *expected_seq, uint32_t *server_seq);
void chat_mode_loop(int sock_fd, struct sockaddr_in *client_addr, socklen_t client_addr_len, uint32_t *server_seq, uint32_t *expected_seq);
void file_transfer_mode(int sock_fd, struct sockaddr_in *client_addr, socklen_t client_addr_len, uint32_t *server_seq, uint32_t *expected_seq);

// --- Argument Parsing ---
server_config parse_arguments(int argc, char *argv[]) {
    server_config cfg = {0};

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port> [--chat] [loss_rate]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    cfg.port = atoi(argv[1]);
    cfg.chat_mode = 0;
    cfg.loss_rate = 0.0;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--chat") == 0) {
            cfg.chat_mode = 1;
        } else {
            cfg.loss_rate = atof(argv[i]);
        }
    }

    return cfg;
}

// --- Server Socket Setup ---
int setup_server_socket(int port, struct sockaddr_in *server_addr) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("bind failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    return sock_fd;
}

// --- Handshake ---
void perform_handshake(int sock_fd, struct sockaddr_in *client_addr, socklen_t *client_addr_len, uint32_t *expected_seq, uint32_t *server_seq) {
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];

    // Wait for SYN
    while (1) {
        int len = recv_sham_packet(sock_fd, client_addr, client_addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);

        if (header.flags & SYN_FLAG) {
            struct sham_header syn_ack = {
                .seq_num = 1000,
                .ack_num = header.seq_num + 1,
                .flags = SYN_FLAG | ACK_FLAG,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, client_addr, &syn_ack, NULL, 0);
            print_sham_header("SND", &syn_ack);
            break;
        }
    }

    // Wait for ACK
    while (1) {
        int len = recv_sham_packet(sock_fd, client_addr, client_addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);

        if ((header.flags & ACK_FLAG) && header.ack_num == 1001) {
            *expected_seq = header.seq_num;
            *server_seq = 1001;
            return;
        }
    }
}

void chat_loop(int sock_fd, struct sockaddr_in *peer_addr, socklen_t peer_len,
               uint32_t *seq_num) {
    fd_set fds;
    char data_buffer[DATA_CHUNK_SIZE];
    struct sham_header header;

    printf("Chat mode enabled. Type messages to send. Type '/quit' to exit.\n");

    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock_fd, &fds);
        int max_fd = (sock_fd > STDIN_FILENO ? sock_fd : STDIN_FILENO) + 1;

        if (select(max_fd, &fds, NULL, NULL, NULL) < 0) {
            perror("select failed");
            break;
        }

        // ---- User typed something ----
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (!fgets(data_buffer, sizeof(data_buffer), stdin)) break;
            data_buffer[strcspn(data_buffer, "\n")] = 0; // strip newline

            if (strncmp(data_buffer, "/quit", 5) == 0) {
                perform_fin_handshake(sock_fd, peer_addr, peer_len, *seq_num);
                break;
            }

            strcat(data_buffer, "\n"); // restore newline for sending

            struct sham_header chat_hdr = {
                .seq_num = *seq_num,
                .ack_num = 0,
                .flags = 0,
                .window_size = DATA_CHUNK_SIZE
            };

            send_sham_packet(sock_fd, peer_addr, &chat_hdr,
                             data_buffer, strlen(data_buffer));
            print_sham_header("SND", &chat_hdr);
            *seq_num += strlen(data_buffer);
        }

        // ---- Incoming message from peer ----
        if (FD_ISSET(sock_fd, &fds)) {
            int msg_len = recv_sham_packet(sock_fd, peer_addr, &peer_len,
                                           &header, data_buffer, sizeof(data_buffer));
            if (msg_len > 0) {
                data_buffer[msg_len] = '\0';

                if (header.flags & FIN_FLAG) {
                    handle_fin_handshake(sock_fd, peer_addr, &header, *seq_num);
                    break;
                }

                printf("Peer: %s", data_buffer);
            }
        }
    }
}


// --- File Transfer Mode ---
void file_transfer_mode(int sock_fd, struct sockaddr_in *client_addr, socklen_t client_addr_len, uint32_t *server_seq, uint32_t *expected_seq) {
    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];
    int connection_open = 1;

    FILE *fp = fopen("received_file.bin", "wb");
    if (!fp) {
        perror("fopen failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    while (connection_open) {
        int data_len = recv_sham_packet(sock_fd, client_addr, &client_addr_len, &header, buffer, sizeof(buffer));
        if (data_len < 0) continue;
        print_sham_header("RCV", &header);

        if (header.flags & FIN_FLAG) {
            handle_fin_handshake(sock_fd, client_addr, &header, *server_seq);
            connection_open = 0;
            break;
        }

        if (header.seq_num == *expected_seq && data_len > 0) {
            fwrite(buffer, 1, data_len, fp);
            *expected_seq += data_len;
            (*server_seq)++;
        }

        struct sham_header ack = {
            .seq_num = *server_seq,
            .ack_num = *expected_seq,
            .flags = ACK_FLAG,
            .window_size = DATA_CHUNK_SIZE
        };
        send_sham_packet(sock_fd, client_addr, &ack, NULL, 0);
        print_sham_header("SND", &ack);
    }

    fclose(fp);
}

// --- Main Function ---
int main(int argc, char *argv[]) {
    server_config cfg = parse_arguments(argc, argv);

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    int sock_fd = setup_server_socket(cfg.port, &server_addr);
    printf("Server listening on port %d... Chat mode: %s, Loss rate: %.2f\n", cfg.port, cfg.chat_mode ? "ON" : "OFF", cfg.loss_rate);

    uint32_t expected_seq = 0, server_seq = 0;
    perform_handshake(sock_fd, &client_addr, &client_addr_len, &expected_seq, &server_seq);
    printf("Connection established!\n");

    if (cfg.chat_mode)
        chat_mode_loop(sock_fd, &client_addr, client_addr_len, &server_seq, &expected_seq);
    else
        file_transfer_mode(sock_fd, &client_addr, client_addr_len, &server_seq, &expected_seq);

    close(sock_fd);
    return 0;
}
