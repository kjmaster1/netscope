#pragma once

#include <stdint.h>
#include <pcap.h>

/* EtherType values */
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

/* IP protocol numbers */
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17

/* Ethernet header — always 14 bytes */
#define ETHERNET_HEADER_LEN 14

/*
 * Ethernet header layout.
 * We use __pragma(pack) to ensure the compiler adds no padding bytes —
 * the struct must match the exact byte layout on the wire.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

/* IPv4 header */
typedef struct {
    uint8_t  version_ihl;    /* version (top 4) + IHL (bottom 4) */
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
} IPv4Header;

/* TCP header */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;    /* top 4 bits = header length in 32-bit words */
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

/* UDP header */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;
#pragma pack(pop)

/* TCP flag bitmasks */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/*
 * Parsed packet — everything we extracted from one captured packet.
 * This is what gets passed to the dashboard.
 */
typedef struct {
    /* Timestamp */
    struct timeval timestamp;

    /* Layer 2 */
    uint16_t ethertype;

    /* Layer 3 */
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    uint8_t  protocol;
    uint8_t  ttl;
    uint16_t ip_total_length;

    /* Layer 4 */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;

    /* Metadata */
    uint32_t packet_len;
    int      valid;          /* 1 if successfully parsed, 0 otherwise */
} ParsedPacket;

/*
 * Parse a raw packet into a ParsedPacket struct.
 * Returns 1 on success, 0 if the packet is not IPv4 or is malformed.
 */
int parse_packet(const struct pcap_pkthdr* header,
                 const uint8_t* raw,
                 ParsedPacket* out);

/*
 * Format a ParsedPacket as a human-readable string.
 * 'buf' must be at least 256 bytes.
 */
void format_packet(const ParsedPacket* pkt, char* buf, int buf_len);

/*
 * Format an IPv4 address as a dotted decimal string.
 * 'buf' must be at least 16 bytes.
 */
void format_ip(const uint8_t ip[4], char* buf);

/*
 * Return a string name for a protocol number.
 */
const char* protocol_name(uint8_t proto);