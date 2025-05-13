#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

/**
 * @brief Opens a network interface for packet capture.
 * 
 * @param interface The name of the network interface to open.
 * @return A pointer to the pcap_t handle, or NULL on failure.
 */
pcap_t *open_interface(const char *interface);

/**
 * @brief Sets up a filter to capture only DNS responses.
 * 
 * @param handle The pcap_t handle for the open interface.
 * @return 1 on success, 0 on failure.
 */
int setup_filter(pcap_t *handle);

/**
 * @brief Function that runs pcap_loop to continuously capture packets.
 * 
 * @param handle The pcap_t handle for the open interface.
 * @param interface The name of the network interface.
 * @return 1 on success, 0 on failure.
 */
int start_sniffing(pcap_t *handle, const char *interface);

#endif // CAPTURE_H