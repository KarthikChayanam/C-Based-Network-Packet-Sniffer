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
#include <stdint.h>
#include "args.h"

void decode_packet(const u_char *packet, int size);

/* globals */
static pcap_t            *cap  = NULL;
static pcap_dumper_t     *dump = NULL;
static FILE              *csv  = NULL;
static const SnifferArgs *opt  = NULL;
static int                seen = 0;

/* ethernet header */
struct eth_hdr { u_char dst[6], src[6]; uint16_t type; };

/* helpers */
static void stop(int _) { (void)_; if (cap) pcap_breakloop(cap); }

static void mac_str(const u_char *m, char *s)
{
    sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X",
            m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void box_print(const char *smac, const char *dmac, uint16_t eth_type,
                      const char *sip, const char *dip, int proto,
                      uint16_t sport, uint16_t dport)
{
    char line[128];
    const char *pname = (proto == IPPROTO_TCP)  ? "TCP"  :
                        (proto == IPPROTO_UDP)  ? "UDP"  :
                        (proto == IPPROTO_ICMP) ? "ICMP" : "OTHER";
    printf("┌──── Ethernet ─────────────────────────────┐\n");
    snprintf(line, sizeof line, " Src MAC: %s", smac);
    printf("│ %-41s │\n", line);
    snprintf(line, sizeof line, " Dst MAC: %s", dmac);
    printf("│ %-41s │\n", line);
    snprintf(line, sizeof line, " Type:    0x%04X", eth_type);
    printf("│ %-41s │\n", line);
    printf("├──── IP Header ────────────────────────────┤\n");
    snprintf(line, sizeof line, " Src IP:  %s", sip);
    printf("│ %-41s │\n", line);
    snprintf(line, sizeof line, " Dst IP:  %s", dip);
    printf("│ %-41s │\n", line);
    snprintf(line, sizeof line, " Proto:   %s (%d)", pname, proto);
    printf("│ %-41s │\n", line);

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        printf("├──── %s Segment ──────────────────────────┤\n", pname);
        snprintf(line, sizeof line, " Src Port: %u", sport);
        printf("│ %-41s │\n", line);
        snprintf(line, sizeof line, " Dst Port: %u", dport);
        printf("│ %-41s │\n", line);
    }
    printf("└───────────────────────────────────────────┘\n\n\n");
}

static void write_csv(const struct pcap_pkthdr *h,
                      const struct ip *ip, int proto)
{
    if (!csv) return;
    char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN], ts[32];
    inet_ntop(AF_INET, &ip->ip_src, sip, sizeof sip);
    inet_ntop(AF_INET, &ip->ip_dst, dip, sizeof dip);
    const char *p = (proto == IPPROTO_TCP)  ? "TCP"  :
                    (proto == IPPROTO_UDP)  ? "UDP"  :
                    (proto == IPPROTO_ICMP) ? "ICMP" : "OTHER";
    strftime(ts, sizeof ts, "%F %T", localtime(&h->ts.tv_sec));
    fprintf(csv, "%s,%s,%s,%s,%u\n", ts, sip, dip, p, h->len);
    fflush(csv);
}

/* pcap callback */
static void cb(u_char *u, const struct pcap_pkthdr *h, const u_char *pkt)
{
    (void)u;
    if (opt->packet_limit && seen >= opt->packet_limit) { pcap_breakloop(cap); return; }
    if (h->caplen < sizeof(struct eth_hdr)) return;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    if (ntohs(eth->type) != 0x0800) return;

    const struct ip *ip = (const struct ip *)(pkt + sizeof *eth);
    int proto = ip->ip_p;

    if (opt->proto_num && proto != opt->proto_num) return;
    switch (opt->proto_filter) {
        case PROTO_TCP:  if (proto != IPPROTO_TCP)  return; break;
        case PROTO_UDP:  if (proto != IPPROTO_UDP)  return; break;
        case PROTO_ICMP: if (proto != IPPROTO_ICMP) return; break;
        default: break;
    }

    char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, sip, sizeof sip);
    inet_ntop(AF_INET, &ip->ip_dst, dip, sizeof dip);
    if (opt->src_ip[0] && strcmp(sip, opt->src_ip)) return;
    if (opt->dst_ip[0] && strcmp(dip, opt->dst_ip)) return;

    uint16_t sport = 0, dport = 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        const u_char *l4 = (const u_char *)ip + ip->ip_hl * 4;
        if (proto == IPPROTO_TCP) {
            const struct tcphdr *tcp = (const struct tcphdr *)l4;
            sport = ntohs(tcp->th_sport); dport = ntohs(tcp->th_dport);
        } else {
            const struct udphdr *udp = (const struct udphdr *)l4;
            sport = ntohs(udp->uh_sport); dport = ntohs(udp->uh_dport);
        }
        if (opt->src_port && sport != opt->src_port) return;
        if (opt->dst_port && dport != opt->dst_port) return;
    }

    /* formatted boxed output */
    char smac[18], dmac[18];
    mac_str(eth->src, smac);
    mac_str(eth->dst, dmac);
    box_print(smac, dmac, ntohs(eth->type), sip, dip, proto, sport, dport);

    // decode_packet(pkt, h->caplen);  This is output of the old type, replaced with box output
    write_csv(h, ip, proto);
    if (dump) pcap_dump((u_char *)dump, h, pkt);
    ++seen;
}

/* entry */
int start_capture(const SnifferArgs *a)
{
    opt = a;
    char err[PCAP_ERRBUF_SIZE];
    cap = pcap_open_live(a->interface, BUFSIZ, 1, 1000, err);
    if (!cap) { fprintf(stderr, "%s\n", err); return 1; }

    if (a->output_file) {
        csv = fopen(a->output_file, "w");
        if (!csv) { perror("csv"); pcap_close(cap); return 1; }
        fprintf(csv, "Timestamp,Src IP,Dest IP,Protocol,Length\n");
    }
    if (a->pcap_output) {
        dump = pcap_dump_open(cap, a->pcap_output);
        if (!dump) { fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(cap));
                     if (csv) fclose(csv); pcap_close(cap); return 1; }
    }

    signal(SIGINT, stop);
    pcap_loop(cap, 0, cb, NULL);

    if (dump) { pcap_dump_close(dump); }
    if (csv)  { fclose(csv); }
    pcap_close(cap);
    printf("Processed %d packets.\n", seen);
    return 0;
}
