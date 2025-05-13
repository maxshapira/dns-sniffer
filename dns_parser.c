#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "common.h"
#include "net_utils.h"
#include "dns_parser.h"

enum DnsRecordType {
    DNS_A     = 1,
    DNS_CNAME = 5,
    DNS_AAAA  = 28
};

/**
 * @brief Prints the domain name from the DNS response question part.
 * 
 * @param ptr Pointer to the DNS response packet.
 */
void print_domain(const u_char *ptr)
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

/**
 * @brief Checks if the pointer is out of bounds.
 * 
 * This function checks if the pointer plus the length exceeds the captured packet length.
 * 
 * @param ptr Pointer to the current position in the packet.
 * @param len Length to check.
 * @param packet Pointer to the start of the packet.
 * @param captured_packet_length Length of the captured packet.
 * @return 1 if out of bounds, 0 otherwise.
 */
int is_out_of_bounds(const u_char *ptr,
                     int len,
                     const u_char *packet,
                     int captured_packet_length)
{
    if ((ptr - packet + len) > captured_packet_length)
    {
        fprintf(stderr, "Error: Out-of-bounds access detected (ptr offset: %ld, length: %d, captured length: %d)\n",
                ptr - packet, len, captured_packet_length);
        return 1; // Out-of-bounds
    }
    return 0; // Within bounds
}

/**
 * @brief Reads the CNAME record from the DNS response.
 * 
 * This function handles DNS name compression and extracts the CNAME.
 * 
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 * @param dns Pointer to the DNS response.
 * @param ptr Pointer to the current position in the DNS response.
 * @param out Pointer to the output buffer for the CNAME.
 */
void read_cname(const u_char *packet,
                int captured_packet_length,
                const u_char *dns, 
                const u_char *ptr, 
                char* out)
{
    const u_char *name_ptr = ptr;
   
    int out_index = 0;

    // Track how many jumps we follow to prevent infinite loops
    int jumps = 0;
    const int MAX_JUMPS = 10;

    while ((name_ptr - packet) < captured_packet_length && out_index < MAX_NAME_LEN - 1)
    {
        // Handle compression
        if ((*name_ptr & 0xC0) == 0xC0)
        {
            if (is_out_of_bounds(name_ptr, 2, packet, captured_packet_length))
                break; // Prevent out-of-bounds

            uint16_t offset = ntohs(*(uint16_t *)name_ptr) & 0x3FFF; // Extract offset
            if (offset >= captured_packet_length || dns + offset >= packet + captured_packet_length)
            {
                fprintf(stderr, "Invalid offset in compressed name\n");
                break; // Invalid offset
            }

            name_ptr = dns + offset; // Jump to the compressed name

            jumps++;

            // Prevent infinite loops
            if (jumps > MAX_JUMPS)
            {
                fprintf(stderr, "CNAME compression loop detected\n");
                break;
            }
        }
        else //add the name
        {
            int len = *name_ptr++;
            if (len == 0)
                break; // End of name
            if ((is_out_of_bounds(name_ptr, len, packet, captured_packet_length)))
                break; // Prevent overflow
            if (out_index != 0 && out_index < MAX_NAME_LEN - 1)
                out[out_index++] = '.';
            memcpy(out + out_index, name_ptr, len); 
            name_ptr += len;
            out_index += len;
        }
    }
    out[out_index] = '\0';
}

/**
 * @brief Skips the question section of the DNS packet.
 * 
 * This function moves the pointer to the start of the answer section.
 * 
 * @param ptr Pointer to the current position in the DNS response.
 * @param questions_count Number of questions in the DNS response.
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 * @return Pointer to the start of the answer section.
 */
const u_char *skip_questions(const u_char *ptr,
                             int questions_count,
                             const u_char *packet,
                             int captured_packet_length)
{
    for (int i = 0; i < questions_count; i++)
    {
        while (*ptr && (ptr - packet) < captured_packet_length)
            ptr += (*ptr) + 1;
        ptr += 5;
    }
    return ptr;
}

/**
 * @brief Prints the DNS record based on its type.
 *
 * This function handles A, AAAA, and CNAME records.
 *
 * @param type Type of the DNS record.
 * @param ptr Pointer to the record data.
 * @param record_len Length of the record data.
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 * @param dns Pointer to the DNS response.
 */
void print_dns_record(uint16_t type,
                      const u_char *ptr,
                      int record_len,
                      const u_char *packet,
                      int captured_packet_length,
                      const u_char *dns)
{
    if (type == DNS_A && record_len == 4) // A (IPv4 Address)
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ptr, ip_str, INET_ADDRSTRLEN);
        printf("IPv4 Address: %s\n", ip_str);
    }
    else if (type == DNS_AAAA && record_len == 16) // AAAA (IPv6 Address)
    {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ptr, ip_str, INET6_ADDRSTRLEN);
        printf("IPv6 Address: %s\n", ip_str);
    }
    else if (type == DNS_CNAME) // CNAME
    {
        char cname[MAX_NAME_LEN];
        read_cname(packet, captured_packet_length, dns, ptr, cname);
        printf("CNAME: %s\n", cname);
    }
}

/**
 * @brief Skips the name field in the DNS response.
 *
 *
 * @param ptr Pointer to the current position in the DNS response.
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 * @return Pointer to the next position after the name field.
 */
const u_char *skip_name(const u_char *ptr,
                        const u_char *packet,
                        int captured_packet_length)
{
    if ((*ptr & 0xC0) == 0xC0)
    {
        return ptr + 2; // Compressed name
    }
    else
    {
        while (*ptr && (ptr - packet) < captured_packet_length)
            ptr += (*ptr) + 1;
        return ptr + 1; // Fully written name
    }
}

/**
 * @brief Extracts the record metadata from the DNS response.
 *
 * This function retrieves the type and length of the DNS record.
 *
 * @param ptr Pointer to the current position in the DNS response.
 * @param type Pointer to store the record type.
 * @param record_len Pointer to store the record length.
 * @return Pointer to the next position after the metadata.
 */
const u_char *extract_record_metadata(const u_char *ptr, uint16_t *type, uint16_t *record_len) {
    *type = ntohs(*(uint16_t *)ptr);
    ptr += 2; // Skip type
    ptr += 2; // Skip class
    ptr += 4; // Skip TTL
    *record_len = ntohs(*(uint16_t *)ptr);
    return ptr + 2; // Move past rdlen
}

/**
 * @brief Prints the DNS answers from the response.
 *
 * This function iterates through the answers and prints the relevant information.
 *
 * @param dns Pointer to the DNS response.
 * @param ptr Pointer to the current position in the DNS response.
 * @param packet Pointer to the captured packet data.
 * @param captured_packet_length Length of the captured packet.
 */
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

void parse_dns_response(const u_char *packet, int captured_packet_length)
{
    const u_char* dns = get_dns_response(packet);
    if (!dns)
        return;

    // skip the first 12 bytes of the DNS header        
    const u_char *ptr = dns + 12;

    print_domain(ptr);

    // skip the question section
    int questions_count = (dns[4] << 8) | dns[5];
    ptr = skip_questions(ptr, questions_count, packet, captured_packet_length);

    print_dns_answers(dns,
                      ptr,
                      packet,
                      captured_packet_length);
}