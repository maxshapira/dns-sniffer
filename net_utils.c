#include <netinet/ip.h>
#include <stddef.h> // Add this for NULL
#include "net_utils.h"
#include "common.h"

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
    if (dns_flags & (0x8000 == 0)) // Check if it's a DNS response
    {
        dns = NULL;
    }

    return dns;
}