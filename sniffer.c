#include "sniffer.h"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define FIRST_PART "tcp and host 127.0.0.1 and dst port 9999"
#define THIRD_PART "icmp"

FILE *file;

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char *filter_exp;
  char *devname = my_device(errbuf, handle);
  bpf_u_int32 net;

  // Open the device for sniffing
  printf("Opening device %s for sniffing ...\n", devname);
  handle = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL)
  {
    printerror();
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  int part;
  printf("Enter 1 for sniffing task2 or 2 for sniffing task4.\n");
  scanf("%d", &part);
  switch (part)
  {
  case 1:
    filter_exp = FIRST_PART;
    break;
  case 2:
    filter_exp = THIRD_PART;
    break;
  default:
    printerror();
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
  {
    printerror();
  }
  if (pcap_setfilter(handle, &fp) == -1)
  {
    printerror();
  }

  file = fopen("208465872_323968859.txt", "w");

  if (file == NULL)
  {
    printerror();
  }

  // Step 3: Capture packets
  printf("We are starting to sniff.\n");
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle
  fclose(file);
  return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  fprintf(file, "Packet Size: %d\n", header->len);
  seperator();

  int eth_length = sizeof(struct ethhdr) + 2;
  struct iphdr *iph = (struct iphdr *)(packet + eth_length);
  int size_of_ip = iph->ihl * 4;

  fprintf(file, "IP\n");
  seperator();

  struct sockaddr_in source;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;

  fprintf(file, "Source IP: %s \n", inet_ntoa(source.sin_addr));
  fprintf(file, "Dest ip: %s\n", inet_ntoa(dest.sin_addr));
  seperator();

  if (iph->protocol == IPPROTO_TCP)
  {
    fprintf(file, "TCP\n");
    seperator();
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr) + eth_length);
    int size_of_tcp = tcph->doff * 4;
    fprintf(file, "Source port: %u\n", ntohs(tcph->source));
    fprintf(file, "Dest port: %u\n", ntohs(tcph->dest));
    seperator();
    fprintf(file, "PROTOCOL\n");
    struct myHeader *myhdr = (struct myHeader *)(packet + eth_length + sizeof(struct iphdr) + sizeof(struct tcphdr));
    time_t t = ntohl(myhdr->timestamp);
    seperator();
    fprintf(file, "timestamp: %u\ntotal_lenght: %u\ncache_flag: %d\nsteps_flag: %d\ntype_flag: %d\nstatus_code: %u\ncache_control: %u\n", ntohl(myhdr->timestamp), ntohs(myhdr->total_lenght), myhdr->cache_flag, myhdr->steps_flag, myhdr->type_flag, ntohs(myhdr->status_code), ntohs(myhdr->cache_control));
    double_seperator();
    int dataSize = header->len - eth_length - sizeof(struct iphdr) - sizeof(struct tcphdr) - sizeof(struct myHeader);
    if (dataSize > 0)
    {
      fprintf(file, "data\n");
      seperator();
      char *data = (char *)(packet + eth_length + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct myHeader));
      print_data(data, dataSize);
    }
    double_seperator();
  }
  else if (iph->protocol == IPPROTO_ICMP)
  {
    fprintf(file, "ICMP\n");
    seperator();
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct iphdr) + eth_length);
    fprintf(file, "Type : %d", (unsigned int)(icmph->type));
    if ((unsigned int)(icmph->type) == 11)
    {
      fprintf(file, "  (TTL Expired)\n");
    }
    else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
      fprintf(file, "  (ICMP Echo Reply)\n");
    }

    // need to be checked
    uint16_t cksum = ntohs(icmph->checksum);
    unsigned int code = (unsigned int)(icmph->code);
    fprintf(file, "Code : %d\n", code);
    fprintf(file, "Checksum : %d\n", cksum);
    double_seperator();

    int dataSize = header->len - eth_length - sizeof(struct iphdr) - sizeof(struct icmphdr);
    if (dataSize > 0)
    {
      fprintf(file, "DATA\n");
      char *data = (char *)(packet + eth_length + sizeof(struct iphdr) + sizeof(struct icmphdr));
      print_data(data, dataSize);
      printf("size of data: %d\n", dataSize);
      fprintf(file, "\n\n");
    }
    double_seperator();
  }
  else
  {
    printf("Not tcp or icmp\n");
  }
};

void print_data(const u_char *payload, int len)
{
  // Exit if payload length is less than or equal to zero
  if (len <= 0)
  {
    return;
  }

  int line_width = 16;
  int line_len;
  int bytes_num = 0;
  const u_char *ch = payload;
  int len_rem = len;

  // If the payload length is less than or equal to the line width, print it in one line
  if (len <= line_width)
  {
    print_line(ch, len, bytes_num);
    return;
  }

  // Print the payload in multiple lines
  while (len_rem > 0)
  {
    // Determine the length of the current line
    line_len = (len_rem > line_width) ? line_width : len_rem;
    print_line(ch, line_len, bytes_num);
    len_rem -= line_len;
    ch += line_len;
    bytes_num += line_width;
  }
  return;
}

// Printing the data lines in a 16 bytes length

void print_line(const u_char *payload, int len, int bytes_num)
{
  int i = 0, remspace;
  const u_char *c;
  fprintf(file, "%05d   ", bytes_num);
  c = payload;
  while (i < len)
  {
    fprintf(file, "%02x ", *c);
    c++;
    if (i == 7)
    {
      extraspace();
    }
    i++;
  }

  if (len < 16)
  {
    remspace = 16 - len;
    for (i = 0; i < remspace; i++)
    {
      extraspace();
    }
  }
  fprintf(file, "\n");
  return;
}

char *my_device(char *errbuf, pcap_t *handle)
{

  int count = 1, n;
  pcap_if_t *alldevsp, *device;
  char *devs[10][70];
  // First get the list of available devices
  printf("Searching for devices:\n");
  if (pcap_findalldevs(&alldevsp, errbuf))
  {
    printerror();
  }

  // Print the available devices
  printf("\nAvailable Devices are :\n");
  for (device = alldevsp; device != NULL; device = device->next)
  {
    printf("%d. %s - %s\n", count, device->name, device->description);
    if (device->name != NULL)
    {
      strcpy(devs[count], device->name);
    }
    count++;
  }

  // Ask user which device to sniff
  printf("Enter the number of the device you want to sniff : ");
  scanf("%d", &n);
  printf("Succeed\n");
  char *devName = devs[n];
  return devName;
}
void printerror()
{
  printf("Error");
  exit(1);
}
void seperator()
{
  fprintf(file, "_____________________________________\n");
}
void extraspace()
{
  fprintf(file, " ");
}
void double_seperator()
{
  fprintf(file, "\n#####################################\n");
}