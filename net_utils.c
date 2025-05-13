#include <stdio.h>  
#include <netinet/ip.h>   // For struct ip (IPv4 header)
#include <netinet/ip6.h>  // For struct ip6_hdr (IPv6 header)
#include <stddef.h>
#include "net_utils.h"
#include "common.h"

struct udphdr *get_udp_header(const u_char *packet) {
    // Skip the Ethernet header to get to the IP/IPv6 header
    const u_char *ip_packet = packet + ETHERNET_HEADER_LEN;

    // Check if the packet is IPv4 or IPv6
    struct ip *ip_hdr = (struct ip *)ip_packet;
    if (ip_hdr->ip_v == 4) { // IPv4
        // Check if the protocol is UDP
        if (ip_hdr->ip_p != IPPROTO_UDP)
            return NULL;

        // Locate the UDP header
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        return (struct udphdr *)(ip_packet + ip_hdr_len);
    } 
    else if (ip_hdr->ip_v == 6) { // IPv6
        printf("Processing IPv6 packet\n");
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ip_packet;

        // Check if the next header is UDP
        if (ip6_hdr->ip6_nxt != IPPROTO_UDP)
            return NULL;

        // Locate the UDP header (IPv6 header is always 40 bytes)
        return (struct udphdr *)(ip_packet + 40);
    }

    return NULL; // Not IPv4 or IPv6
}

const u_char* get_dns_response(const u_char *packet) {
    // Extract the UDP header
    struct udphdr *udp_hdr = get_udp_header(packet);
    if (!udp_hdr)
        return NULL;

    // Ensure it's DNS traffic (port 53)
    if (ntohs(udp_hdr->uh_dport) != DNS_PORT && ntohs(udp_hdr->uh_sport) != DNS_PORT)
        return NULL;
    
    // loocate the DNS header    
    const u_char *dns = (u_char *)(udp_hdr + 1);

    // Check if it's a DNS response
    int dns_flags = (dns[2] << 8) | dns[3];
    if ((dns_flags & 0x8000) == 0) 
    {
        dns = NULL;
    }

    return dns;
}