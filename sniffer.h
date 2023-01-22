#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>


char *my_device(char *errbuf, pcap_t *handle);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_line(const u_char *payload, int len, int bytes_num);
void print_data(const u_char *payload, int len);
void printerror();
void seperator();
void extraspace();
void double_seperator();


//The header that we got from task 2.

struct myHeader
{
  u_int32_t timestamp;       
  u_int16_t total_lenght;    
  u_char saved : 3;           
  u_char cache_flag : 1;      
  u_char steps_flag : 1;      
  u_char type_flag : 1;       
  u_int16_t status_code : 10; 
  u_int16_t cache_control;   
  u_int16_t padding;          
};