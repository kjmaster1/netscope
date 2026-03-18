#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "../include/capture.h"
#include "../include/analyser.h"

static int packet_count = 0;
static int parsed_count = 0;

static void packet_callback(u_char* user,
                             const struct pcap_pkthdr* header,
                             const u_char* packet) {
    (void)user;
    packet_count++;

    ParsedPacket pkt;
    if (!parse_packet(header, packet, &pkt)) {
        return;  /* not IPv4 or malformed — skip */
    }

    parsed_count++;

    char buf[256];
    format_packet(&pkt, buf, sizeof(buf));
    printf("[%4d] %s\n", parsed_count, buf);
}

int main(void) {
    printf("netscope v0.1\n");
    printf("libpcap: %s\n\n", pcap_lib_version());

    NetInterface interfaces[MAX_INTERFACES];
    int count = list_interfaces(interfaces, MAX_INTERFACES);

    if (count == 0) {
        fprintf(stderr, "No interfaces found. "
                        "Try running as administrator.\n");
        return 1;
    }

    printf("Available interfaces:\n");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s\n", i + 1, interfaces[i].description);
    }

    printf("\nSelect interface (1-%d): ", count);
    int choice;
    if (scanf_s("%d", &choice) != 1 ||
        choice < 1 || choice > count) {
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }

    const char* device = interfaces[choice - 1].name;
    printf("\nOpening: %s\n",
           interfaces[choice - 1].description);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = open_interface(device, errbuf);
    if (!handle) return 1;

    printf("Capturing IPv4 packets... (Ctrl+C to stop)\n\n");

    start_capture(handle, packet_callback, NULL);

    pcap_close(handle);
    printf("\nTotal: %d packets captured, %d IPv4 parsed.\n",
           packet_count, parsed_count);
    return 0;
}