#include <signal.h>
#include <stdlib.h>
#include "capture.h" 

pcap_t *handle = NULL; // Global handle for cleanup

/**
 * @brief Exits the program and cleans up resources.
 *
 * @param status The exit status code.
 */
int exit_program(int status) {
    if (handle) {
        pcap_close(handle); // Close the pcap handle
    }
    exit(status);
}

/**
 * @brief Signal handler for SIGINT (Ctrl+C).
 *
 * @param signal The signal number.
 */
void handle_signal(int signal) {
    if (signal == SIGINT) {
        printf("\nSIGINT received. Cleaning up and exiting...\n");
        exit_program(0); // Clean up and exit
    }
}

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

    // Set up signal handler
    signal(SIGINT, handle_signal);

    handle = open_interface(interface);
    if (!handle)
    {
        exit_program(1); // Failed to open interface
    }

    if (!setup_filter(handle))
    {
        exit_program(1); // Failed to set up filter
    }

    if(!start_sniffing(handle, interface))
    {
        exit_program(1); // Failed to start sniffing
    }

    exit_program(0); // Successful exit
}