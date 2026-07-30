#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

// Structure to hold port service information
typedef struct {
    const char *service_name;
    const char *app_protocol;
} PortInfo;

// Function to print hex dump
void print_hex_dump(const unsigned char *data, int len);

// Function to identify port service
PortInfo identify_port(uint16_t port);

#endif // UTILS_H
