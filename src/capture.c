#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>     
#include <netinet/ip.h>   
#include "args.h"           // SnifferArgs
                             
void decode_packet(const u_char *packet, int size);

static pcap_t              *handle       = NULL;
static const SnifferArgs   *g_args       = NULL;
static volatile int         packet_count = 0;

static void sigint_handler(int signum)
{
    (void)signum;          
    if (handle) {
        pcap_breakloop(handle); 
    }
}

/* Ethernet header (14 bytes) */
struct eth_header {
    u_char  dst[6];
    u_char  src[6];
    uint16_t type;
};


static void handle_packet(u_char *user,
                          const struct pcap_pkthdr *hdr,
                          const u_char *packet)
{
    (void)user;  /* not used */

    /* Limit by packet count (if -n was provided) */
    if (g_args->packet_limit && packet_count >= g_args->packet_limit) {
        pcap_breakloop(handle);
        return;
    }

    /* Ethernet sanity check */
    if (hdr->caplen < sizeof(struct eth_header)) {
        fprintf(stderr, "Truncated Ethernet frame (%u bytes)\n", hdr->caplen);
        return;
    }

    const struct eth_header *eth = (const struct eth_header *)packet;

    /* Filter out non‑IPv4 frames early */
    if (ntohs(eth->type) != 0x0800) {               /* 0x0800 = IPv4 */
        return;
    }

    /* IP header starts right after Ethernet */
    const struct ip *ip_hdr = (const struct ip *)(packet + sizeof(struct eth_header));
    int proto = ip_hdr->ip_p;                       /* transport protocol */

    /* Protocol‑specific filtering */
    switch (g_args->proto_filter) {
        case PROTO_TCP:  if (proto != IPPROTO_TCP)  return; break;
        case PROTO_UDP:  if (proto != IPPROTO_UDP)  return; break;
        case PROTO_ICMP: if (proto != IPPROTO_ICMP) return; break;
        default: /* PROTO_ALL */ break;
    }

    printf("Captured packet: %u bytes\n", hdr->len);
    decode_packet(packet, hdr->caplen);

    packet_count++;
}

int start_capture(const SnifferArgs *args)
{
    g_args = args;

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(args->interface,
                            BUFSIZ,          
                            1,  
                            1000,        
                            errbuf);

    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    signal(SIGINT, sigint_handler);

    printf("Listening on %s (filter: %s, limit: %s)\n",
           args->interface,
           (args->proto_filter == PROTO_TCP)  ? "TCP"  :
           (args->proto_filter == PROTO_UDP)  ? "UDP"  :
           (args->proto_filter == PROTO_ICMP) ? "ICMP" : "ALL",
           args->packet_limit ? "ON" : "OFF");

    if (pcap_loop(handle, 0, handle_packet, NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    handle = NULL;

    printf("\nCapture finished: %d packet%s processed.\n",
           packet_count, (packet_count == 1) ? "" : "s");

    return 0;
}


/* -------------------------------------------------------------------------
Option	Meaning
-i <iface>	Network interface
--tcp	Filter only TCP packets
--udp	Filter only UDP packets
--icmp	Filter only ICMP packets
--all	Accept all protocols (default)
-n <count>	Stop after N packets
 */