#ifndef DECODE_H
#define DECODE_H

#include <pcap.h>

void decode_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif // DECODE_H