#include "spoofer.h"

#define THIRD_PART "icmp"

FILE *file;

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = THIRD_PART;
    char *devname = my_device(errbuf, handle);
    bpf_u_int32 net;

    // Open the device for sniffing
    printf("Opening device %s for sniffing ...\n", devname);
    handle = pcap_open_live(devname, 65536, 1, 1, errbuf);

    if (handle == NULL)
    {
        printerror();
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printerror();
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printerror();
    }

    file = fopen("208465872_323968859.txt", "w");

    // Step 3: Capture packets
    printf("We are starting to sniff.\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    fclose(file);
    return 0;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header->len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
    {
        int eth_length = sizeof(struct ethhdr) + 2;
        struct iphdr *ip_header = (struct iphdr *)(packet + eth_length);
        if (ip_header->protocol == 1)
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

            fprintf(file, "Code : %d\n", (unsigned int)(icmph->code));
            fprintf(file, "Checksum : %d\n", ntohs(icmph->checksum));
            double_seperator();

            int dataSize = header->len - eth_length - sizeof(struct iphdr) - sizeof(struct icmphdr);
            if (dataSize > 0)
            {
            fprintf(file, "DATA\n");
            char *data = (char *)(packet + eth_length + sizeof(struct iphdr) + sizeof(struct icmphdr));
            print_data(data, dataSize);
            fprintf(file, "\n\n");
            }
            double_seperator();
            struct iphdr *iph2 = (struct iphdr *)(packet + eth_length);
            struct icmphdr *icmph2 = (struct icmphdr *)(packet + eth_length + sizeof(struct iphdr));
            if (icmph->type == 8)
            {
                struct sockaddr_in dest;
                dest.sin_addr.s_addr = iph->daddr;
                char *ip_address = inet_ntoa(dest.sin_addr);
                printmsg(ip_address);
                // char *reply = create_reply_packet(packet, eth_length, header->len);
                char *reply = malloc(header->len - eth_length);
                struct iphdr *ip_header = (struct iphdr *)(packet + eth_length);
                struct icmphdr *icmp_header = (struct icmphdr *)(packet + eth_length + sizeof(struct iphdr));
                char *data = (char *)(packet + eth_length + sizeof(struct iphdr) + sizeof(struct icmphdr));
                int dataLen = header->len - eth_length - sizeof(struct iphdr) - sizeof(struct icmphdr);

                struct iphdr *ip_header_reply = (struct iphdr *)(reply);
                struct icmphdr *icmp_header_reply = (struct icmphdr *)(reply + sizeof(struct iphdr));
                char *data_reply = (char *)(reply + sizeof(struct iphdr) + sizeof(struct icmphdr));

                iphcopy(ip_header_reply,ip_header);
                icmpcopy(icmp_header_reply, icmp_header);
                memcpy(data_reply, data, dataLen);
                icmp_header_reply->checksum = calculate_checksum((unsigned short *)icmp_header_reply, sizeof(struct icmphdr) + dataLen);
                dest.sin_family = AF_INET;

                if (send_reply(reply, header->len - eth_length, dest) < 0)
                {
                    printerror();
                }
                else
                {
                    printf("Reply sent.\n");
                }
            }
        }
        else
        {
            printf("Not ICMP\n");
            printerror();
        }
    }
}
void icmpcopy(struct icmphdr *icmp_to_copy, struct icmphdr *icmp_copy_from){
    // icmp header
    icmp_to_copy->type = 0;
    icmp_to_copy->code = 0;
    icmp_to_copy->checksum = 0;
    icmp_to_copy->un.echo.id = icmp_copy_from->un.echo.id;
    icmp_to_copy->un.echo.sequence = icmp_copy_from->un.echo.sequence;
}
void iphcopy(struct iphdr *ip_to_copy, struct iphdr *ip_copy_from){
    // ip header
    ip_to_copy->ihl = ip_copy_from->ihl;
    ip_to_copy->version = ip_copy_from->version;
    ip_to_copy->tos = ip_copy_from->tos;
    ip_to_copy->tot_len = ip_copy_from->tot_len;
    ip_to_copy->id = ip_copy_from->id;
    ip_to_copy->frag_off = ip_copy_from->frag_off;
    ip_to_copy->ttl = ip_copy_from->ttl;
    ip_to_copy->protocol = ip_copy_from->protocol;
    ip_to_copy->check = ip_copy_from->check;
    ip_to_copy->saddr = ip_copy_from->daddr;
    ip_to_copy->daddr = ip_copy_from->saddr;
}
int send_reply(char *reply, int length, struct sockaddr_in dest)
{
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        printerror();
    }
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    int i = sendto(sock, reply, length, 0, (struct sockaddr *)&dest, sizeof(dest));
    close(sock);
    return i;
};



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
void printmsg(char *ip_address)
{
    printf("Catched ICMP echo request to %s\n", ip_address);
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
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