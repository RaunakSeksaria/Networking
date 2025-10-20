#ifndef UTIL_H
#define UTIL_H

#include <pcap.h>

int list_devices();
void print_hex_dump(const unsigned char *data, int len);
void format_mac(const unsigned char *mac, char *buf, size_t buflen);

#endif // UTIL_H