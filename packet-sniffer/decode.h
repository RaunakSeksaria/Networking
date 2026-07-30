#ifndef DECODE_H
#define DECODE_H

#include <pcap.h>

void decode_packet(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void decode_packet_detailed(const struct pcap_pkthdr *pkthdr, const unsigned char *packet, unsigned int packet_id);
void reset_packet_id();

#endif // DECODE_H
