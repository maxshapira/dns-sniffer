#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// dig command examples:
// IPV4: dig @8.8.8.8 openai.com
// IPV6: dig @8.8.8.8 www.google.com AAAA
// CNAME: dig @8.8.8.8 www.youtube.com
// CNAME recursive: dig @8.8.8.8 www.gov.uk
// CNAME compressed:  dig @8.8.8.8 www.microsoft.com

#define ETHERNET_HEADER_LEN 14
#define DNS_PORT 53
#define MAX_NAME_LEN 256

// Extract the domain name from the question section and print it
void printDomain(const u_char *packet, const u_char *ptr)
{
    char domain[MAX_NAME_LEN];
    int domain_i = 0;
    while (*ptr)
    {
        int len = *ptr++;
        if (len == 0)
            break;
        if (domain_i != 0)
            domain[domain_i++] = '.';
        memcpy(domain + domain_i, ptr, len);
        ptr += len;
        domain_i += len;
    }
    domain[domain_i] = '\0';
    printf("\nDomain: %s\n", domain);
}

void readCname(const u_char *packet,
               int captured_packet_length,
               const u_char *dns, 
               const u_char *ptr, 
               char* out)
{
    const u_char *r = ptr;
   
    int out_i = 0;

    while ((r - packet) < captured_packet_length && out_i < MAX_NAME_LEN - 1)
    {
        // Handle compression
        if ((*r & 0xC0) == 0xC0)
        {
            uint16_t offset = ntohs(*(uint16_t *)r) & 0x3FFF; // Extract offset
            r = dns + offset;                                 // Jump to the compressed name
        }
        else
        {
            int len = *r++;
            if (len == 0)
                break; // End of name
            if (out_i != 0 && out_i < MAX_NAME_LEN - 1)
                out[out_i++] = '.';
            if ((r - packet + len) > captured_packet_length)
                break; // Prevent overflow
            memcpy(out + out_i, r, len);
            r += len;
            out_i += len;
        }
    }
    out[out_i] = '\0';
}

// Skip the question section of the DNS packet
// This function moves the pointer to the start of the answer section
const u_char *skip_questions(const u_char *ptr, int questions_count, const u_char *packet, int captured_packet_length) {
    for (int i = 0; i < questions_count; i++) {
        while (*ptr && (ptr - packet) < captured_packet_length)
            ptr += (*ptr) + 1;
        ptr += 5;
    }
    return ptr;
}

struct udphdr *get_udp_header(const u_char *packet) {
    const u_char *ip_packet = packet + ETHERNET_HEADER_LEN;
    struct ip *ip_hdr = (struct ip *)ip_packet;

    if (ip_hdr->ip_p != IPPROTO_UDP)
        return NULL;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct udphdr *udp_hdr = (struct udphdr *)(ip_packet + ip_hdr_len);

    return udp_hdr;
}

const u_char* get_dns_response(const u_char *packet) {
    struct udphdr *udp_hdr = get_udp_header(packet);
    if (!udp_hdr)
        return NULL;

    // Ensure it's DNS traffic (port 53)
    if (ntohs(udp_hdr->uh_dport) != DNS_PORT && ntohs(udp_hdr->uh_sport) != DNS_PORT)
        return NULL;

    const u_char *dns = (u_char *)(udp_hdr + 1);
    int dns_flags = (dns[2] << 8) | dns[3];
    if (dns_flags & 0x8000 == 0) // Check if it's a DNS response
    {
        dns = NULL;
    }

    return dns;
}

void print_dns_record(uint16_t type, const u_char *ptr, int record_len, const u_char *packet, int captured_packet_length, const u_char *dns)
{
    if (type == 1 && record_len == 4) // A (IPv4 Address)
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ptr, ip_str, INET_ADDRSTRLEN);
        printf("IPv4 Address: %s\n", ip_str);
    }
    else if (type == 28 && record_len == 16) // AAAA (IPv6 Address)
    {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ptr, ip_str, INET6_ADDRSTRLEN);
        printf("IPv6 Address: %s\n", ip_str);
    }
    else if (type == 5) // CNAME
    {
        char cname[MAX_NAME_LEN];
        readCname(packet, captured_packet_length, dns, ptr, cname);
        printf("CNAME: %s\n", cname);
    }
}

const u_char *skip_name(const u_char *ptr, const u_char *packet, int captured_packet_length) {
    if ((*ptr & 0xC0) == 0xC0) {
        return ptr + 2; // Compressed name
    } else {
        while (*ptr && (ptr - packet) < captured_packet_length)
            ptr += (*ptr) + 1;
        return ptr + 1; // Fully written name
    }
}

const u_char *extract_record_metadata(const u_char *ptr, uint16_t *type, uint16_t *record_len) {
    *type = ntohs(*(uint16_t *)ptr);
    ptr += 2; // Skip type
    ptr += 2; // Skip class
    ptr += 4; // Skip TTL
    *record_len = ntohs(*(uint16_t *)ptr);
    return ptr + 2; // Move past rdlen
}

void print_dns_answers(const u_char *dns,
                       const u_char *ptr,
                       const u_char *packet,
                       int captured_packet_length)
{
    int answers_count = (dns[6] << 8) | dns[7];

    for (int i = 0; i < answers_count; i++)
    {
        if ((ptr - packet) >= captured_packet_length)
            break;

        // Skip the name field
        ptr = skip_name(ptr, packet, captured_packet_length);
        if ((ptr - packet + 10) >= captured_packet_length)
            break;

        // Extract metadata
        uint16_t type, record_len;
        ptr = extract_record_metadata(ptr, &type, &record_len);

        // Validate record length
        if ((ptr + record_len - packet) > captured_packet_length)
            break;

        print_dns_record(type, ptr, record_len, packet, captured_packet_length, dns);

        ptr += record_len;
    }
}

// Function to parse the DNS response packet
// This function extracts the domain name and IP addresses from the DNS response
// It also handles CNAME records and prints the results
void parse_dns_response(const u_char *packet, int captured_packet_length)
{
    const u_char* dns = get_dns_response(packet);
    if (!dns)
        return;

    const u_char *ptr = dns + 12;

    printDomain(packet, ptr);

    int questions_count = (dns[4] << 8) | dns[5];
    ptr = skip_questions(ptr, questions_count, packet, captured_packet_length);

    print_dns_answers(dns,
                      ptr,
                      packet,
                      captured_packet_length);
}

// Packet handler function
// This function is called for each captured packet
// It extracts the DNS response and calls the parse_dns_response function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    parse_dns_response(packet, header->caplen);
}

int main(int argc, char *argv[])
{
    // Check if the user provided an interface name
    // Example usage: ./dns-sniffer eth0
    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    const char *interface = argv[1];

    // Open the network device for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // Set a filter to capture only DNS responses
    struct bpf_program fp;
    char filter_exp[] = "udp port 53 and udp[10] & 0x80 != 0"; // DNS responses only
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    // Start capturing packets
    printf("Listening on %s for DNS responses...\n", interface);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
