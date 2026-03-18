#include "../include/analyser.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>  /* ntohs, ntohl */
#else
#include <arpa/inet.h>
#endif

void format_ip(const uint8_t ip[4], char* buf) {
    sprintf_s(buf, 16, "%d.%d.%d.%d",
              ip[0], ip[1], ip[2], ip[3]);
}

const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case PROTO_ICMP: return "ICMP";
        case PROTO_TCP:  return "TCP";
        case PROTO_UDP:  return "UDP";
        default:         return "OTHER";
    }
}

int parse_packet(const struct pcap_pkthdr* header,
                 const uint8_t* raw,
                 ParsedPacket* out) {
    memset(out, 0, sizeof(ParsedPacket));
    out->timestamp  = header->ts;
    out->packet_len = header->len;

    /* Need at least an Ethernet + IPv4 header */
    if (header->caplen < ETHERNET_HEADER_LEN + 20) {
        return 0;
    }

    /* Parse Ethernet header */
    const EthernetHeader* eth = (const EthernetHeader*)raw;
    out->ethertype = ntohs(eth->ethertype);

    /* We only handle IPv4 for now */
    if (out->ethertype != ETHERTYPE_IPV4) {
        return 0;
    }

    /* Parse IPv4 header */
    const IPv4Header* ip =
        (const IPv4Header*)(raw + ETHERNET_HEADER_LEN);

    /*
     * Extract IHL — Internet Header Length.
     * The bottom 4 bits of version_ihl give the header length
     * in 32-bit words. Multiply by 4 to get bytes.
     */
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    if (ihl < 20) return 0;  /* malformed — minimum IP header is 20 bytes */

    memcpy(out->src_ip, ip->src_ip, 4);
    memcpy(out->dst_ip, ip->dst_ip, 4);
    out->protocol       = ip->protocol;
    out->ttl            = ip->ttl;
    out->ip_total_length = ntohs(ip->total_length);

    /* Parse transport layer */
    const uint8_t* transport = raw + ETHERNET_HEADER_LEN + ihl;
    uint32_t transport_offset = ETHERNET_HEADER_LEN + ihl;

    if (transport_offset + 4 > header->caplen) {
        /* Not enough bytes for even a port number */
        out->valid = 1;  /* IP was valid, transport truncated */
        return 1;
    }

    if (ip->protocol == PROTO_TCP) {
        if (transport_offset + sizeof(TCPHeader) > header->caplen) {
            out->valid = 1;
            return 1;
        }
        const TCPHeader* tcp = (const TCPHeader*)transport;
        out->src_port  = ntohs(tcp->src_port);
        out->dst_port  = ntohs(tcp->dst_port);
        out->tcp_flags = tcp->flags;

    } else if (ip->protocol == PROTO_UDP) {
        if (transport_offset + sizeof(UDPHeader) > header->caplen) {
            out->valid = 1;
            return 1;
        }
        const UDPHeader* udp = (const UDPHeader*)transport;
        out->src_port = ntohs(udp->src_port);
        out->dst_port = ntohs(udp->dst_port);
    }

    out->valid = 1;
    return 1;
}

void format_packet(const ParsedPacket* pkt, char* buf, int buf_len) {
    char src_ip[16], dst_ip[16];
    format_ip(pkt->src_ip, src_ip);
    format_ip(pkt->dst_ip, dst_ip);

    if (pkt->src_port > 0 || pkt->dst_port > 0) {
        sprintf_s(buf, buf_len,
            "%-6s  %s:%-5d  ->  %s:%-5d  (%d bytes)",
            protocol_name(pkt->protocol),
            src_ip, pkt->src_port,
            dst_ip, pkt->dst_port,
            pkt->packet_len);
    } else {
        sprintf_s(buf, buf_len,
            "%-6s  %s  ->  %s  (%d bytes)",
            protocol_name(pkt->protocol),
            src_ip, dst_ip,
            pkt->packet_len);
    }
}