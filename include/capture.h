#pragma once

#include <pcap.h>
#include <stdint.h>

/* Maximum number of network interfaces to enumerate */
#define MAX_INTERFACES 16

/* Snapshot length — how many bytes of each packet to capture */
#define SNAP_LEN 65535

/* Promiscuous mode — capture all packets, not just ones addressed to us */
#define PROMISC 1

/*
 * Represents a network interface available for capture
 */
typedef struct {
    char name[256];
    char description[256];
} NetInterface;

/*
 * List all available network interfaces.
 * Returns the number of interfaces found, fills 'interfaces' array.
 */
int list_interfaces(NetInterface* interfaces, int max_count);

/*
 * Open a network interface for packet capture.
 * Returns a pcap handle on success, NULL on failure.
 * 'errbuf' must be at least PCAP_ERRBUF_SIZE bytes.
 */
pcap_t* open_interface(const char* device, char* errbuf);

/*
 * Start the capture loop on an open handle.
 * 'callback' is called for every packet received.
 * Blocks until capture is stopped.
 */
void start_capture(pcap_t* handle, pcap_handler callback, void* user_data);

/*
 * Stop an active capture loop.
 */
void stop_capture(pcap_t* handle);