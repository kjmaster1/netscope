#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#endif

#include "../include/capture.h"
#include "../include/analyser.h"
#include "../include/server.h"

static int        packet_count = 0;
static int        parsed_count = 0;
static WsServer*  g_server     = NULL;

static void packet_callback(u_char* user,
                             const struct pcap_pkthdr* header,
                             const u_char* packet) {
    (void)user;
    packet_count++;

    ParsedPacket pkt;
    if (!parse_packet(header, packet, &pkt)) {
        return;
    }

    parsed_count++;

    /* Print to console */
    char buf[256];
    format_packet(&pkt, buf, sizeof(buf));
    printf("[%4d] %s\n", parsed_count, buf);

    /* Send to WebSocket clients */
    if (g_server) {
        server_enqueue(g_server, &pkt);
    }
}

int main(void) {
    /* Initialise Winsock before anything else */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("netscope v0.1\n");
    printf("libpcap: %s\n\n", pcap_lib_version());

    /* Start WebSocket server */
    static PacketQueue queue;
    static WsServer    server;
    queue_init(&queue);

    if (!server_start(&server, &queue)) {
        fprintf(stderr, "Failed to start WebSocket server\n");
        WSACleanup();
        return 1;
    }
    g_server = &server;

    /* List and select network interface */
    NetInterface interfaces[MAX_INTERFACES];
    int count = list_interfaces(interfaces, MAX_INTERFACES);

    if (count == 0) {
        fprintf(stderr, "No interfaces found. "
                        "Try running as administrator.\n");
        WSACleanup();
        return 1;
    }

    printf("\nAvailable interfaces:\n");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s\n", i + 1, interfaces[i].description);
    }

    printf("\nSelect interface (1-%d): ", count);
    int choice;
    if (scanf_s("%d", &choice) != 1 ||
        choice < 1 || choice > count) {
        fprintf(stderr, "Invalid selection.\n");
        WSACleanup();
        return 1;
    }

    const char* device = interfaces[choice - 1].name;
    printf("\nOpening: %s\n",
           interfaces[choice - 1].description);
    printf("Open http://localhost:7681 in your browser\n\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = open_interface(device, errbuf);
    if (!handle) {
        WSACleanup();
        return 1;
    }

    printf("Capturing... (Ctrl+C to stop)\n\n");
    start_capture(handle, packet_callback, NULL);

    pcap_close(handle);
    server_stop(&server);
    queue_destroy(&queue);
    WSACleanup();

    printf("\nTotal: %d captured, %d parsed.\n",
           packet_count, parsed_count);
    return 0;
}