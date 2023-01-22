#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h> // gettimeofday()
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

// IPv4 header len without options
#define IP4_HDRLEN 20 
// ICMP header len for echo req
#define ICMP_HDRLEN 8  

unsigned short calculate_checksum(unsigned short *paddress, int len);
int icmppack(char *packet, int seq);

int main(int argc, char *argv[])
{

    if (argc != 2)
    {
        fprintf(stderr, "Invalid command.\n");
        exit(1);
    }

    // packet to send
    char packet[IP_MAXPACKET];    
    // Holds IPv4 string
    char IP[INET_ADDRSTRLEN];      
    // Copy the ip to the string
    strcpy(IP, argv[1]);                     
    // IPv4 address
    struct in_addr addr;                     
    // Convert IPv4 addresses from text to binary
    if (inet_pton(AF_INET, IP, &addr) != 1)  
    {
        printf("Invalid ip-address\n");
        exit(1);
    }

    printf("Ping %s:\n", IP);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(IP);
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1; 
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        exit(1);
    }

    // number of packets to send
    int num = 0;      

    while (true)
    {
        // create icmp packet
        int lenOfPacket= icmppack(packet, num); 
        struct timeval start, end;
        gettimeofday(&start, 0);

        int bytes_sent = sendto(sock, packet, lenOfPacket, 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
        if (bytes_sent == -1)
        {
            fprintf(stderr, "sendto() failed with error: %d", errno);
            return -1;
        }

        // Get the ping response

        // clear packet
        bzero(packet, IP_MAXPACKET); 
        socklen_t len = sizeof(dest_in);
        ssize_t bytes_received = -1;
        struct iphdr *iphdr;
        struct icmphdr *icmphdr;
        while ((bytes_received = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_in, &len)))
        {
            if (bytes_received > 0)
            {

                iphdr = (struct iphdr *)packet;
                icmphdr = (struct icmphdr *)(packet + (iphdr->ihl * 4));
                inet_ntop(AF_INET, &(iphdr->saddr), IP, INET_ADDRSTRLEN);
                break;
            }
        }

        gettimeofday(&end, 0);
        char reply[IP_MAXPACKET];
        // get reply data from packet
        memcpy(reply, packet + ICMP_HDRLEN + IP4_HDRLEN, lenOfPacket - ICMP_HDRLEN); 
        float time = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
        printf("%s sent %ld bytes, ICMP sequence: %d, Time: %.5f ms\n", IP, bytes_received, icmphdr->un.echo.sequence, time);
        num++;
        bzero(packet, IP_MAXPACKET);
        //  There is 2 seconds delay between each package.
        sleep(2);    
    }
    close(sock);
    return 0;
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
}

int icmppack(char *packet, int seq)
{
    // ICMP-header
    struct icmp icmphdr; 
    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO; 
    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;         
    // Identifier (16 bits): some number to trace the response.
    icmphdr.icmp_id = 18;          
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = seq;       
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;        
    // add ICMP header to packet
    memcpy((packet), &icmphdr, ICMP_HDRLEN); 
    // add ICMP data to packet
    memcpy(packet + ICMP_HDRLEN, data, datalen); 
    // calculate checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen); 
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    return ICMP_HDRLEN + datalen;
}