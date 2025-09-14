#include "sham.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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

// --- Function to perform four-way FIN handshake ---
void perform_fin_handshake(int sock_fd, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint32_t seq_num) {
    struct sham_header header;
    char data_buffer[DATA_CHUNK_SIZE];
    
    // Step 1: Send FIN
    struct sham_header fin_hdr = {
        .seq_num = seq_num,
        .ack_num = 0,
        .flags = FIN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, server_addr, &fin_hdr, NULL, 0);
    print_sham_header("SND", &fin_hdr);
    printf("Initiating connection termination...\n");

    // Step 2: Wait for ACK of our FIN
    while (1) {
        int ack_len = recv_sham_packet(sock_fd, server_addr, &server_addr_len, &header, data_buffer, sizeof(data_buffer));
        if (ack_len < 0) continue;
        print_sham_header("RCV", &header);
        if ((header.flags & ACK_FLAG) && header.ack_num == seq_num + 1) {
            printf("Server acknowledged FIN.\n");
            break;
        }
    }

    // Step 3: Wait for server's FIN
    while (1) {
        int fin_len = recv_sham_packet(sock_fd, server_addr, &server_addr_len, &header, data_buffer, sizeof(data_buffer));
        if (fin_len < 0) continue;
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

// --- Structures for configuration ---
typedef struct {
    char *server_ip;
    int server_port;
    char *input_file;
    char *output_file;
    int chat_mode;
    float loss_rate;
} client_config;

// --- Function Declarations ---
client_config parse_arguments(int argc, char *argv[]);
int setup_socket(struct sockaddr_in *server_addr, client_config cfg);
uint32_t perform_handshake(int sock_fd, struct sockaddr_in *server_addr, socklen_t *addr_len);
void chat_mode_loop(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, uint32_t seq_num);
void file_transfer_mode(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, client_config cfg, uint32_t seq_num);


// --- Argument Parsing ---
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

// --- Socket Setup ---
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

// --- Handshake ---
uint32_t perform_handshake(int sock_fd, struct sockaddr_in *server_addr, socklen_t *addr_len) {
    struct sham_header syn = {
        .seq_num = 500,
        .ack_num = 0,
        .flags = SYN_FLAG,
        .window_size = DATA_CHUNK_SIZE
    };
    send_sham_packet(sock_fd, server_addr, &syn, NULL, 0);
    print_sham_header("SND", &syn);

    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];

    while (1) {
        int len = recv_sham_packet(sock_fd, server_addr, addr_len, &header, buffer, sizeof(buffer));
        if (len < 0) continue;
        print_sham_header("RCV", &header);
        if ((header.flags & SYN_FLAG) && (header.flags & ACK_FLAG)) {
            struct sham_header ack = {
                .seq_num = syn.seq_num + 1,
                .ack_num = header.seq_num + 1,
                .flags = ACK_FLAG,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, server_addr, &ack, NULL, 0);
            print_sham_header("SND", &ack);
            return syn.seq_num + 1;
        }
    }
}

// --- Chat Mode ---
void chat_mode_loop(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, uint32_t seq_num) {
    char buffer[DATA_CHUNK_SIZE];
    struct sham_header header;

    printf("Chat mode enabled. Type messages to send. Type '/quit' to exit.\n");

    while (1) {
        printf("You: ");
        fflush(stdout);
        if (!fgets(buffer, DATA_CHUNK_SIZE, stdin)) break;

        buffer[strcspn(buffer, "\n")] = 0;
        if (strncmp(buffer, "/quit", 5) == 0) {
            perform_fin_handshake(sock_fd, server_addr, addr_len, seq_num);
            break;
        }

        strcat(buffer, "\n");
        struct sham_header chat_hdr = {
            .seq_num = seq_num,
            .ack_num = 0,
            .flags = 0,
            .window_size = DATA_CHUNK_SIZE
        };
        send_sham_packet(sock_fd, server_addr, &chat_hdr, buffer, strlen(buffer));
        print_sham_header("SND", &chat_hdr);
        seq_num += strlen(buffer);

        int reply_len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, buffer, sizeof(buffer));
        if (reply_len > 0) {
            buffer[reply_len] = '\0';
            printf("Server: %s", buffer);
        }
    }
}

// --- File Transfer Mode ---
void file_transfer_mode(int sock_fd, struct sockaddr_in *server_addr, socklen_t addr_len, client_config cfg, uint32_t seq_num) {
    FILE *fp = fopen(cfg.input_file, "rb");
    if (!fp) {
        perror("fopen failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    struct sham_header header;
    char buffer[DATA_CHUNK_SIZE];
    int connection_open = 1;

    while (connection_open) {
        size_t bytes_read = fread(buffer, 1, DATA_CHUNK_SIZE, fp);
        if (bytes_read > 0) {
            struct sham_header data_hdr = {
                .seq_num = seq_num,
                .ack_num = 0,
                .flags = 0,
                .window_size = DATA_CHUNK_SIZE
            };
            send_sham_packet(sock_fd, server_addr, &data_hdr, buffer, bytes_read);
            print_sham_header("SND", &data_hdr);

            while (1) {
                int ack_len = recv_sham_packet(sock_fd, server_addr, &addr_len, &header, buffer, sizeof(buffer));
                if (ack_len < 0) continue;
                print_sham_header("RCV", &header);
                if ((header.flags & ACK_FLAG) && header.ack_num >= seq_num + bytes_read) {
                    seq_num = header.ack_num;
                    break;
                }
            }
        } else {
            perform_fin_handshake(sock_fd, server_addr, addr_len, seq_num);
            connection_open = 0;
        }
    }

    fclose(fp);
}



// --- Main Function ---
int main(int argc, char *argv[]) {
    client_config cfg = parse_arguments(argc, argv);

    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    int sock_fd = setup_socket(&server_addr, cfg);

    printf("Client connecting to %s:%d... Chat mode: %s, Loss rate: %.2f\n",
           cfg.server_ip, cfg.server_port, cfg.chat_mode ? "ON" : "OFF", cfg.loss_rate);

    // Perform 3-way handshake
    uint32_t seq_num = perform_handshake(sock_fd, &server_addr, &server_addr_len);
    printf("Connection established!\n");

    // Run mode
    if (cfg.chat_mode) {
        chat_mode_loop(sock_fd, &server_addr, server_addr_len, seq_num);
    } else {
        file_transfer_mode(sock_fd, &server_addr, server_addr_len, cfg, seq_num);
    }

    close(sock_fd);
    return 0;
}