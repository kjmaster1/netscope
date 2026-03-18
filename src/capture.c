#include "../include/capture.h"
#include <stdio.h>
#include <string.h>

int list_interfaces(NetInterface* interfaces, int max_count) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    /* Ask Npcap for all available network devices */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 0;
    }

    /* Copy device names and descriptions into our array */
    for (pcap_if_t* dev = alldevs;
         dev != NULL && count < max_count;
         dev = dev->next) {

        strncpy_s(interfaces[count].name,
          sizeof(interfaces[count].name),
          dev->name,
          sizeof(interfaces[count].name) - 1);

        strncpy_s(interfaces[count].description,
          sizeof(interfaces[count].description),
          dev->description ? dev->description : "(no description)",
          sizeof(interfaces[count].description) - 1);

        count++;
    }

    pcap_freealldevs(alldevs);
    return count;
}

pcap_t* open_interface(const char* device, char* errbuf) {
    pcap_t* handle = pcap_open_live(
        device,     /* network interface to open          */
        SNAP_LEN,   /* max bytes to capture per packet    */
        PROMISC,    /* promiscuous mode — capture all      */
        1000,       /* read timeout in milliseconds        */
        errbuf      /* error message buffer               */
    );

    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface %s: %s\n",
                device, errbuf);
        return NULL;
    }

    /*
     * Verify this interface provides Ethernet link-layer headers.
     * We need Ethernet because we parse from the Ethernet frame up.
     * Some interfaces (e.g. loopback on Windows) use different
     * link-layer types.
     */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr,
                "Interface %s does not provide Ethernet headers\n",
                device);
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

void start_capture(pcap_t* handle, pcap_handler callback, void* user_data) {
    /*
     * pcap_loop captures packets indefinitely.
     * -1 means loop forever until pcap_breakloop() is called.
     * callback is invoked for every packet.
     */
    pcap_loop(handle, -1, callback, (u_char*)user_data);
}

void stop_capture(pcap_t* handle) {
    pcap_breakloop(handle);
}