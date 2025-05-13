#include "capture.h" 

// this program captures DNS responses and prints the domain name and IP addresses
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