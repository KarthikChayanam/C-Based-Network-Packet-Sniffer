#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>    
#include <netinet/ip.h>     
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "args.h"           /* SnifferArgs, enums    */

void decode_packet(const u_char *packet, int size);

static pcap_t            *handle       = NULL;      /* pcap session handle   */
static const SnifferArgs *g_args       = NULL;      /* CLI options           */
static volatile int       packet_count = 0;         /* packets processed     */
static FILE              *log_file     = NULL;      /* CSV log    */
static pcap_dumper_t *pcap_dumper = NULL;  /* PCAP file dumper */

static void sigint_handler(int sig)
{
    (void)sig;
    if (handle) {
        pcap_breakloop(handle);
    }
}

struct eth_header {
    u_char   dst[6];
    u_char   src[6];
    uint16_t type;
};

static void handle_packet(u_char *user,
                          const struct pcap_pkthdr *hdr,
                          const u_char *packet)
{
    (void)user;   /* not used */

    /* Respect packet‑limit option (-n) */
    if (g_args->packet_limit && packet_count >= g_args->packet_limit) {
        pcap_breakloop(handle);
        return;
    }

    /* Ensure we have at least an Ethernet header */
    if (hdr->caplen < sizeof(struct eth_header)) {
        fprintf(stderr, "Truncated frame (%u bytes)\n", hdr->caplen);
        return;
    }

    const struct eth_header *eth = (const struct eth_header *)packet;

    /* Filter non‑IPv4 frames early (EtherType 0x0800) */
    if (ntohs(eth->type) != 0x0800)
        return;

    const struct ip *ip_hdr = (const struct ip *)(packet + sizeof(struct eth_header));
    int proto = ip_hdr->ip_p;

    /* Protocol filter from CLI ------------------------------------------------*/
    switch (g_args->proto_filter) {
        case PROTO_TCP:  if (proto != IPPROTO_TCP)  return; break;
        case PROTO_UDP:  if (proto != IPPROTO_UDP)  return; break;
        case PROTO_ICMP: if (proto != IPPROTO_ICMP) return; break;
        default: break; /* PROTO_ALL */
    }

    /* --- Console output ----------------------------------------------------- */
    printf("Captured packet: %u bytes\n", hdr->len);
    decode_packet(packet, hdr->caplen);

    /* --- CSV logging -------------------------------------------------------- */
    if (log_file) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

        const char *proto_str = (proto == IPPROTO_TCP)  ? "TCP"  :
                                (proto == IPPROTO_UDP)  ? "UDP"  :
                                (proto == IPPROTO_ICMP) ? "ICMP" : "OTHER";

        /* Timestamp */
        time_t     now = time(NULL);
        struct tm *lt  = localtime(&now);
        char       ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);

        fprintf(log_file, "%s,%s,%s,%s,%u\n",
                ts, src_ip, dst_ip, proto_str, hdr->len);
        fflush(log_file);
    }

    if (pcap_dumper) {
        pcap_dump((u_char *)pcap_dumper, hdr, packet);
    }

    packet_count++;
}

int start_capture(const SnifferArgs *args)
{
    g_args = args;

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(args->interface,
                            BUFSIZ,        /* snapshot length         */
                            1,             /* promiscuous mode        */
                            1000,          /* timeout in ms           */
                            errbuf);

    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (args->pcap_output) {
        pcap_dumper = pcap_dump_open(handle, args->pcap_output);
        if (!pcap_dumper) {
            fprintf(stderr, "Error: Cannot open pcap file: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
    }


    if (args->output_file) {
        log_file = fopen(args->output_file, "w");
        if (!log_file) {
            perror("fopen (output file)");
            pcap_close(handle);
            return 1;
        }
        fprintf(log_file, "Timestamp,Src IP,Dest IP,Protocol,Length\n");
    }

    signal(SIGINT, sigint_handler);

    printf("Listening on %s | filter: %s | limit: %s | log: %s\n",
           args->interface,
           (args->proto_filter == PROTO_TCP)  ? "TCP"  :
           (args->proto_filter == PROTO_UDP)  ? "UDP"  :
           (args->proto_filter == PROTO_ICMP) ? "ICMP" : "ALL",
           args->packet_limit ? "ON" : "OFF",
           args->output_file  ? args->output_file : "OFF");

    if (pcap_loop(handle, 0, handle_packet, NULL) == -1) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        if (log_file) fclose(log_file);
        return 1;
    }

    pcap_close(handle);
    handle = NULL;

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    if (pcap_dumper) {
        pcap_dump_close(pcap_dumper);
        pcap_dumper = NULL;
    }


    printf("\nCapture complete — %d packet%s processed.\n",
           packet_count, (packet_count == 1) ? "" : "s");

    return 0;
}
