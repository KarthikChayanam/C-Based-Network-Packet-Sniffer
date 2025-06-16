// src/decode.c
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

#define ETHER_TYPE_IP 0x0800

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

void print_mac(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void decode_packet(const u_char *packet, int size) {
    if (size < 14) {
        printf("Packet too short for Ethernet header\n");
        return;
    }

    struct eth_header *eth = (struct eth_header *)packet;
    uint16_t eth_type = ntohs(eth->eth_type);

    printf("\n=== Ethernet Frame ===\n");
    printf("Src MAC: "); print_mac(eth->src_mac); printf("\n");
    printf("Dst MAC: "); print_mac(eth->dst_mac); printf("\n");
    printf("Type: 0x%04X\n", eth_type);

    if (eth_type != ETHER_TYPE_IP) {
        printf("Not an IPv4 packet\n");
        return;
    }

    const struct ip *ip_hdr = (struct ip *)(packet + 14);
    int ip_header_len = ip_hdr->ip_hl * 4;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

    printf("\n--- IP Header ---\n");
    printf("Src IP: %s\n", src_ip);
    printf("Dst IP: %s\n", dst_ip);
    printf("Protocol: %d\n", ip_hdr->ip_p);

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        printf("\n>>> TCP Segment <<<\n");
        printf("Src Port: %d\n", ntohs(tcp->th_sport));
        printf("Dst Port: %d\n", ntohs(tcp->th_dport));
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len);
        printf("\n>>> UDP Datagram <<<\n");
        printf("Src Port: %d\n", ntohs(udp->uh_sport));
        printf("Dst Port: %d\n", ntohs(udp->uh_dport));
    } else {
        printf("Other protocol: %d\n", ip_hdr->ip_p);
    }
}
