#ifndef SHAM_H
#define SHAM_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stddef.h>

struct sham_header {
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window_size;
};

#define SYN_FLAG 0x1
#define ACK_FLAG 0x2
#define FIN_FLAG 0x4

#define PORT 12345
#define MAX_PACKET_SIZE (sizeof(struct sham_header) + 1024)
#define DATA_CHUNK_SIZE 1024

void print_sham_header(const char* prefix, const struct sham_header* header);

int send_sham_packet(int sock_fd, const struct sockaddr_in* dest_addr,
                     const struct sham_header* header, const void* data, size_t data_len);

int recv_sham_packet(int sock_fd, struct sockaddr_in* src_addr, socklen_t* src_addr_len,
                     struct sham_header* header, void* data_buffer, size_t data_buffer_size);

#endif // SHAM_H