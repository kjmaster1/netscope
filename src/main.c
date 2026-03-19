#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <signal.h>
#endif

#include "../include/capture.h"
#include "../include/analyser.h"
#include "../include/server.h"
#include "../include/dns_cache.h"


/* Global stats */
static int      packet_count  = 0;
static int      parsed_count  = 0;
static uint64_t total_bytes   = 0;
static int      tcp_count     = 0;
static int      udp_count     = 0;
static int      icmp_count    = 0;

/* Top talkers — track bytes per source IP */
#define MAX_TALKERS 1024

typedef struct {
    uint8_t  ip[4];
    uint64_t bytes;
    int      packets;
} Talker;

static Talker    talkers[MAX_TALKERS];
static int       talker_count = 0;
static pcap_t*   g_handle     = NULL;

static WsServer*  g_server     = NULL;

static void update_talker(const uint8_t ip[4], uint32_t bytes) {
    for (int i = 0; i < talker_count; i++) {
        if (memcmp(talkers[i].ip, ip, 4) == 0) {
            talkers[i].bytes += bytes;
            talkers[i].packets++;
            return;
        }
    }
    if (talker_count < MAX_TALKERS) {
        memcpy(talkers[talker_count].ip, ip, 4);
        talkers[talker_count].bytes   = bytes;
        talkers[talker_count].packets = 1;
        talker_count++;
    }
}

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
    total_bytes += pkt.packet_len;

    switch (pkt.protocol) {
        case PROTO_TCP:  tcp_count++;  break;
        case PROTO_UDP:  udp_count++;  break;
        case PROTO_ICMP: icmp_count++; break;
    }

    update_talker(pkt.src_ip, pkt.packet_len);

    char buf[256];
    format_packet(&pkt, buf, sizeof(buf));
    printf("[%4d] %s\n", parsed_count, buf);

    if (g_server) {
        server_enqueue(g_server, &pkt);
    }
}

static int cmp_talkers(const void* a, const void* b) {
    const Talker* ta = (const Talker*)a;
    const Talker* tb = (const Talker*)b;
    if (tb->bytes > ta->bytes) return 1;
    if (tb->bytes < ta->bytes) return -1;
    return 0;
}

static void print_summary(void) {
    printf("\n");
    printf("========================================\n");
    printf("  netscope — capture summary\n");
    printf("========================================\n");
    printf("  Total packets : %d\n", packet_count);
    printf("  IPv4 parsed   : %d\n", parsed_count);
    printf("  Total bytes   : %llu\n", total_bytes);
    printf("  TCP           : %d\n", tcp_count);
    printf("  UDP           : %d\n", udp_count);
    printf("  ICMP          : %d\n", icmp_count);
    printf("\n  Top 5 talkers by bytes:\n");

    qsort(talkers, talker_count, sizeof(Talker), cmp_talkers);

    int show = talker_count < 5 ? talker_count : 5;
    for (int i = 0; i < show; i++) {
        char ip[16];
        format_ip(talkers[i].ip, ip);
        printf("    %-18s %8llu bytes  %d pkts\n",
               ip,
               talkers[i].bytes,
               talkers[i].packets);
    }
    printf("========================================\n");
}

static void signal_handler(int sig) {
    (void)sig;
    printf("\nStopping capture...\n");
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
}

int main(int argc, char* argv[]) {

    /* Optional BPF filter expression as command line argument */
    const char* filter_expr = NULL;
    if (argc > 1) {
        filter_expr = argv[1];
    }

    /* Initialise Winsock before anything else */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("netscope v0.1\n");
    printf("libpcap: %s\n\n", pcap_lib_version());
    printf("Usage: netscope.exe [filter]\n");
    printf("Examples:\n");
    printf("  netscope.exe\n");
    printf("  netscope.exe \"tcp port 443\"\n");
    printf("  netscope.exe \"not port 5353\"\n");
    printf("  netscope.exe \"host 8.8.8.8\"\n\n");

    /* Start WebSocket server */
    static PacketQueue queue;
    static WsServer    server;
    queue_init(&queue);

    static DnsCache dns;
    dns_cache_init(&dns);

    if (!server_start(&server, &queue, &dns)) {
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
    printf("Open http://localhost:%d in your browser\n\n", WS_PORT);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = open_interface(device, errbuf);
    if (!handle) {
        WSACleanup();
        return 1;
    }
    g_handle = handle;

    /* Apply BPF filter if provided */
    if (filter_expr) {
        if (!apply_filter(handle, filter_expr)) {
            pcap_close(handle);
            WSACleanup();
            return 1;
        }
    }

    printf("Capturing... (Ctrl+C to stop)\n\n");
    signal(SIGINT, signal_handler);
    start_capture(handle, packet_callback, NULL);
    print_summary();

    pcap_close(handle);
    server_stop(&server);
    queue_destroy(&queue);
    dns_cache_destroy(&dns);
    WSACleanup();

    printf("\nTotal: %d captured, %d parsed.\n",
           packet_count, parsed_count);
    return 0;
}