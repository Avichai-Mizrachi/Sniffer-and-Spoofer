#include "sniffer.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int send_reply(char *reply, int length, struct sockaddr_in dest);
void printmsg(char *ip_address);
void printerror();
char *my_device(char *errbuf, pcap_t *handle);
unsigned short calculate_checksum(unsigned short *paddress, int len);
void iphcopy(struct iphdr *ip_to_copy, struct iphdr *ip_copy_from);
void icmpcopy(struct icmphdr *icmp_to_copy, struct icmphdr *icmp_copy_from);