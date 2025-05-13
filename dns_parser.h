#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <pcap.h> // For u_char

/**
 * @brief Parses the DNS response packet.
 * 
 * This function extracts the domain name and IP addresses from the DNS response.
 * It also handles CNAME records and prints the results.
 * 
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 */
void parse_dns_response(const u_char *packet,
                        int captured_packet_length);

#endif // DNS_PARSER_H