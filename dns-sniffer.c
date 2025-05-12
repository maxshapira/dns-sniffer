#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

//IPV4 example: dig @8.8.8.8 openai.com
//IPV6 example: dig @8.8.8.8 www.google.com AAAA
//CNAME example: dig @8.8.8.8 www.youtube.com

#define ETHERNET_HEADER_LEN 14
#define DNS_PORT 53
#define MAX_RECORDS 10

void parse_dns_response(const u_char *packet, int size) {
    const u_char *ip_packet = packet + ETHERNET_HEADER_LEN;
    struct ip *ip_hdr = (struct ip *)ip_packet;

    if (ip_hdr->ip_p != IPPROTO_UDP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct udphdr *udp_hdr = (struct udphdr *)(ip_packet + ip_hdr_len);

    if (ntohs(udp_hdr->uh_dport) != DNS_PORT && ntohs(udp_hdr->uh_sport) != DNS_PORT) return;

    const u_char *dns = (u_char *)(udp_hdr + 1);
    int dns_flags = (dns[2] << 8) | dns[3];
    if (!(dns_flags & 0x8000)) return;  // Not a DNS response

    int qdcount = (dns[4] << 8) | dns[5];
    int ancount = (dns[6] << 8) | dns[7];
    const u_char *ptr = dns + 12;

    // Skip questions
    for (int i = 0; i < qdcount; i++) {
        while (*ptr && (ptr - packet) < size) ptr += (*ptr) + 1;
        ptr += 5;
    }

    char ip4_list[MAX_RECORDS][INET_ADDRSTRLEN];
    char ip6_list[MAX_RECORDS][INET6_ADDRSTRLEN];
    char cname_list[MAX_RECORDS][256];
    int ip4_count = 0, ip6_count = 0, cname_count = 0;

    for (int i = 0; i < ancount; i++) {
        if ((ptr - packet) >= size) break;

        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2;
        } else {
            while (*ptr && (ptr - packet) < size) ptr += (*ptr) + 1;
            ptr += 1;
        }

        if ((ptr - packet + 10) >= size) break;

        uint16_t type = ntohs(*(uint16_t *)ptr); ptr += 2;
        ptr += 2;  // class
        ptr += 4;  // ttl
        uint16_t rdlen = ntohs(*(uint16_t *)ptr); ptr += 2;

        if ((ptr + rdlen - packet) > size) break;

        if (type == 1 && rdlen == 4 && ip4_count < MAX_RECORDS) {  // A
            inet_ntop(AF_INET, ptr, ip4_list[ip4_count++], INET_ADDRSTRLEN);
        } else if (type == 28 && rdlen == 16 && ip6_count < MAX_RECORDS) {  // AAAA
            inet_ntop(AF_INET6, ptr, ip6_list[ip6_count++], INET6_ADDRSTRLEN);
        } else if (type == 5 && cname_count < MAX_RECORDS) {  // CNAME
            const u_char *r = ptr;
            char *out = cname_list[cname_count];
            int out_i = 0;

            while ((r - packet) < size && *r && out_i < 255) {
                if ((*r & 0xC0) == 0xC0) {
                    strcpy(out + out_i, " (compressed)");
                    break;
                }
                int len = *r++;
                if (out_i != 0 && out_i < 255) out[out_i++] = '.';
                memcpy(out + out_i, r, len);
                r += len;
                out_i += len;
            }
            out[out_i] = '\0';
            cname_count++;
        }

        ptr += rdlen;
    }

    if(ip4_count == 0 && ip6_count == 0 && cname_count == 0) {
        printf("No records found.\n");
        return;
    }

    printf("Domain:\n");

    if(ip4_count > 0) printf("\nIPv4 addresses:\n");
    for (int i = 0; i < ip4_count; i++) printf("%s\n", ip4_list[i]);

    if(ip6_count > 0) printf("\nIPv6 addresses:\n");
    for (int i = 0; i < ip6_count; i++) printf("%s\n", ip6_list[i]);

    if(cname_count > 0) printf("\nCNAME records:\n");
    for (int i = 0; i < cname_count; i++) printf("%s\n", cname_list[i]);
    printf("\n");
}

void print_packet(const u_char *packet, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {
            int j = i - (i % 16);
            printf(" | ");
            for (; j <= i; j++) {
                char c = packet[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n");
        }
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("🎯 DNS packet captured! Length: %d bytes\n", header->len);
    print_packet(packet, header->len);
    parse_dns_response(packet, header->caplen);
}

int main(int argc, char *argv[]) {
    const char *interface = (argc == 2) ? argv[1] : "eth0";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "udp port 53 and udp[10] & 0x80 != 0";  // DNS responses only
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    printf("Listening on %s for DNS responses...\n", interface);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
