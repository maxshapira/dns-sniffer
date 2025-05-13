#include "capture.h" 

// this program captures DNS responses and prints the domain name and IP addresses
// Test dig commands for reference:
// IPV4: dig @8.8.8.8 openai.com
// IPV6: dig @8.8.8.8 www.google.com AAAA
// CNAME: dig @8.8.8.8 www.youtube.com
// CNAME recursive: dig @8.8.8.8 www.gov.uk
// CNAME compressed: dig @8.8.8.8 www.microsoft.com
int main(int argc, char *argv[])
{
    // Check if the user provided an interface name
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *interface = argv[1];

    // Open the interface
    pcap_t *handle = open_interface(interface);
    if (!handle)
    {
        return 1; // Failed to open interface
    }

    // Set up the filter
    if (!setup_filter(handle))
    {
        return 1; // Failed to set up filter
    }

    // Start sniffing
    start_sniffing(handle, interface);

    // Close the handle
    pcap_close(handle);
    return 0;
}