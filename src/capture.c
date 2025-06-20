/* capture.c — boxed output + DNS/HTTP/TLS/ARP parsing */
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
#include "decode/arp.h"
#include "decode/dns.h"
#include "decode/http.h"
#include "decode/tls.h"

static pcap_t        *cap  = NULL;
static pcap_dumper_t *dump = NULL;
static FILE          *csv  = NULL;
static const SnifferArgs *opt = NULL;
static int seen = 0;

struct eth_hdr { uint8_t dst[6], src[6]; uint16_t type; };

static void stop(int _) { (void)_; if (cap) pcap_breakloop(cap); }

static void mac(const uint8_t *m, char *s)
{ sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]); }

static void box(const char *sm,const char *dm,uint16_t et,
                const char *sip,const char *dip,int p,
                uint16_t sp,uint16_t dp)
{
    char line[64];
    const char *pn = (p==IPPROTO_TCP)?"TCP":(p==IPPROTO_UDP)?"UDP":
                     (p==IPPROTO_ICMP)?"ICMP":"OTHER";
    printf("┌──── Ethernet ─────────────────────────────┐\n");
    snprintf(line,sizeof line," Src MAC: %s",sm); printf("│ %-41s │\n",line);
    snprintf(line,sizeof line," Dst MAC: %s",dm); printf("│ %-41s │\n",line);
    snprintf(line,sizeof line," Type:    0x%04X",et); printf("│ %-41s │\n",line);
    printf("├──── IP Header ────────────────────────────┤\n");
    snprintf(line,sizeof line," Src IP:  %s",sip); printf("│ %-41s │\n",line);
    snprintf(line,sizeof line," Dst IP:  %s",dip); printf("│ %-41s │\n",line);
    snprintf(line,sizeof line," Proto:   %s (%d)",pn,p); printf("│ %-41s │\n",line);
    if (p==IPPROTO_TCP||p==IPPROTO_UDP){
        printf("├──── %s Segment ──────────────────────────┤\n",pn);
        snprintf(line,sizeof line," Src Port: %u",sp); printf("│ %-41s │\n",line);
        snprintf(line,sizeof line," Dst Port: %u",dp); printf("│ %-41s │\n",line);
    }
    printf("└───────────────────────────────────────────┘\n\n");
}

static void csv_row(const struct pcap_pkthdr *h,const struct ip *ip,int proto)
{
    if (!csv) return;
    char sip[INET_ADDRSTRLEN],dip[INET_ADDRSTRLEN],ts[32];
    inet_ntop(AF_INET,&ip->ip_src,sip,sizeof sip);
    inet_ntop(AF_INET,&ip->ip_dst,dip,sizeof dip);
    const char *pn=(proto==IPPROTO_TCP)?"TCP":(proto==IPPROTO_UDP)?"UDP":
                   (proto==IPPROTO_ICMP)?"ICMP":"OTHER";
    strftime(ts,sizeof ts,"%F %T",localtime(&h->ts.tv_sec));
    fprintf(csv,"%s,%s,%s,%s,%u\n",ts,sip,dip,pn,h->len);
    fflush(csv);
}

static void cb(u_char *u,const struct pcap_pkthdr *h,const u_char *pkt)
{
    (void)u;
    if (opt->packet_limit && seen>=opt->packet_limit){ pcap_breakloop(cap); return; }
    if (h->caplen < sizeof(struct eth_hdr)) return;

    const struct eth_hdr *eth=(const struct eth_hdr*)pkt;
    uint16_t et=ntohs(eth->type);

    if (et==0x0806){                           /* ARP */
        parse_arp(pkt+sizeof *eth,h->caplen-sizeof *eth);
        if (dump) pcap_dump((u_char*)dump,h,pkt);
        ++seen; return;
    }
    if (et!=0x0800) return;                    /* IPv4 only */

    const struct ip *ip=(const struct ip*)(pkt+sizeof *eth);
    int proto=ip->ip_p;

    if (opt->proto_num && proto!=opt->proto_num) return;
    if (opt->proto_filter==PROTO_TCP && proto!=IPPROTO_TCP) return;
    if (opt->proto_filter==PROTO_UDP && proto!=IPPROTO_UDP) return;
    if (opt->proto_filter==PROTO_ICMP && proto!=IPPROTO_ICMP) return;

    char sip[INET_ADDRSTRLEN],dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ip->ip_src,sip,sizeof sip);
    inet_ntop(AF_INET,&ip->ip_dst,dip,sizeof dip);
    if (opt->src_ip[0] && strcmp(sip,opt->src_ip)) return;
    if (opt->dst_ip[0] && strcmp(dip,opt->dst_ip)) return;

    const u_char *l4=(const u_char*)ip + ip->ip_hl*4;
    uint16_t sport=0,dport=0;
    if (proto==IPPROTO_TCP||proto==IPPROTO_UDP){
        if (proto==IPPROTO_TCP){
            const struct tcphdr *tcp=(const struct tcphdr*)l4;
            sport=ntohs(tcp->th_sport); dport=ntohs(tcp->th_dport);
        }else{
            const struct udphdr *udp=(const struct udphdr*)l4;
            sport=ntohs(udp->uh_sport); dport=ntohs(udp->uh_dport);
        }
        if (opt->src_port && sport!=opt->src_port) return;
        if (opt->dst_port && dport!=opt->dst_port) return;
    }

    char smac[18],dmac[18]; mac(eth->src,smac); mac(eth->dst,dmac);
    box(smac,dmac,et,sip,dip,proto,sport,dport);

    int pay_len=h->caplen - (l4 - pkt);
    if (proto==IPPROTO_UDP && (sport==53||dport==53))      parse_dns(l4,pay_len);
    else if (proto==IPPROTO_TCP && (sport==80||dport==80)) parse_http(l4,pay_len);
    else if (proto==IPPROTO_TCP && (sport==443||dport==443)) parse_tls(l4,pay_len);

    csv_row(h,ip,proto);
    if (dump) pcap_dump((u_char*)dump,h,pkt);
    ++seen;
}

int start_capture(const SnifferArgs *a)
{
    opt=a;
    char err[PCAP_ERRBUF_SIZE];
    cap=pcap_open_live(a->interface,BUFSIZ,1,1000,err);
    if(!cap){ fprintf(stderr,"%s\n",err); return 1; }

    if(a->output_file){
        csv=fopen(a->output_file,"w");
        if(!csv){ perror("csv"); pcap_close(cap); return 1; }
        fprintf(csv,"Timestamp,Src IP,Dest IP,Protocol,Length\n");
    }
    if(a->pcap_output){
        dump=pcap_dump_open(cap,a->pcap_output);
        if(!dump){ fprintf(stderr,"pcap_dump_open: %s\n",pcap_geterr(cap));
                   if(csv)fclose(csv); pcap_close(cap); return 1; }
    }

    signal(SIGINT,stop);
    pcap_loop(cap,0,cb,NULL);

    if(dump) pcap_dump_close(dump);
    if(csv)  fclose(csv);
    pcap_close(cap);
    printf("Processed %d packets.\n",seen);
    return 0;
}
