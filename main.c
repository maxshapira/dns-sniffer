#include "capture.h" 

/**
 * @brief Main function to capture DNS packets and retrieve domains,
 *        IP addresses, and compressed names.
 */
int main(int argc, char *argv[])
{
    // Check if the user provided an interface name
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *interface = argv[1];

    pcap_t *handle = open_interface(interface);
    if (!handle)
    {
        return 1; // Failed to open interface
    }

    if (!setup_filter(handle))
    {
        return 1; // Failed to set up filter
    }

    start_sniffing(handle, interface);

    pcap_close(handle);
    return 0;
}