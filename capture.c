#include "capture.h"
#include "dns_parser.h"

pcap_t *open_interface(const char *interface)
{
    // Open the network device for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return NULL;
    }

    return handle;
}

int setup_filter(pcap_t *handle)
{
    // Set a filter to capture only DNS responses
    struct bpf_program fp;
    char filter_exp[] = "udp port 53 and udp[10] & 0x80 != 0"; // DNS responses only
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Error compiling filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 0;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 0;
    }

    // Free the compiled filter
    pcap_freecode(&fp);
    return 1;
}

// Packet handler function
// This function is called for each captured packet
// It extracts the DNS response and calls the parse_dns_response function
void packet_handler(__attribute__((unused)) u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    parse_dns_response(packet, header->caplen);
}

void start_sniffing(pcap_t *handle, const char *interface)
{
    // Start capturing packets
    printf("Listening on %s for DNS responses...\n", interface);
    if (pcap_loop(handle, -1, packet_handler, NULL) < 0)
    {
        fprintf(stderr, "Error during packet capture: %s\n", pcap_geterr(handle));
    }
}