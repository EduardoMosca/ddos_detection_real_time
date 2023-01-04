#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

FILE *file = NULL;

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet);

void fill_file(FILE *file, char *timestamp, char *src_ip, char *dst_ip, int src_port, int totfwd);

int main(int argc, char *argv[])
{
    file = fopen("pcap.csv", "w+");
    fprintf(file, "Timestamp,Src IP,Dst IP,Src Port,Tot Fwd Pkts\n");
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 1000; /* In milliseconds */

    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(
        device,
        BUFSIZ,
        0,
        timeout_limit,
        error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);
    fclose(file);

    return 0;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;

    int source_address_1 = *(ip_header + 12);
    int source_address_2 = *(ip_header + 13);
    int source_address_3 = *(ip_header + 14);
    int source_address_4 = *(ip_header + 15);

    int destination_address_1 = *(ip_header + 16);
    int destination_address_2 = *(ip_header + 17);
    int destination_address_3 = *(ip_header + 18);
    int destination_address_4 = *(ip_header + 19);

    /* Now that we know where the IP header is, we can
       inspect the IP header for a protocol number to
       make sure it is TCP before going any further.
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (!(protocol != IPPROTO_TCP || protocol != IPPROTO_UDP))
    {
        return;
    }
    // puts("pegou");

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    // printf("tdp_port = %d\n", tcp_port);
    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;

    payload_length = header->caplen -
                     (ethernet_header_length + ip_header_length + tcp_header_length);

    payload = packet + total_headers_size;

    char source_address_char[16];
    snprintf(source_address_char, sizeof(source_address_char), "%d.%d.%d.%d", source_address_1, source_address_2, source_address_3, source_address_4);
    char destination_address_char[16];
    snprintf(destination_address_char, sizeof(destination_address_char), "%d.%d.%d.%d", destination_address_1, destination_address_2, destination_address_3, destination_address_4);
    time_t mytime = time(NULL);
    char *time_str = ctime(&mytime);
    time_str[strlen(time_str) - 1] = '\0';
    int tcp_port = *(tcp_header) + *(tcp_header + 1);
    int total_packet_lenght = header->caplen;
    fill_file(file, time_str, source_address_char, destination_address_char, tcp_port, total_packet_lenght);

    return;
}

void fill_file(FILE *file, char *timestamp, char *src_ip, char *dst_ip, int src_port, int totfwd)
{
    fprintf(file, "%s,%s,%s,%d,%d\n", timestamp, src_ip, dst_ip, src_port, totfwd);
}