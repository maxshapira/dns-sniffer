#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <netinet/udp.h>

/**
 * @brief Extracts the UDP header from a packet.
 * 
 * @param packet Pointer to the packet data.
 * @return Pointer to the UDP header, or NULL if not found.
 */
struct udphdr *get_udp_header(const u_char *packet);

/**
 * @brief Extracts the DNS response from a packet.
 * 
 * @param packet Pointer to the packet data.
 * @return Pointer to the DNS response, or NULL if not found.
 */
const u_char* get_dns_response(const u_char *packet);

#endif // NET_UTILS_H