/* dns.c */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"

struct dns_hdr { uint16_t id, flags, qd, an, ns, ar; };

static int read_name(const uint8_t *p,int plen,int *o,char *out,int max){
    int i=*o,l=0;
    while(i<plen && p[i] && l<max-1){
        int n=p[i++]; if(n&0xc0) return -1;
        if(l) out[l++]='.';
        if(i+n>plen) return -1;
        memcpy(out+l,p+i,n); l+=n; i+=n;
    }
    out[l]=0; *o=i+1; return 0;
}
int parse_dns(const uint8_t *p,int len){
    if(len<12) return 0;
    const struct dns_hdr *h=(const struct dns_hdr*)p;
    if(ntohs(h->qd)==0) return 0;
    int off=12; char qname[256];
    if(read_name(p,len,&off,qname,sizeof qname)) return 0;
    if(off+4>len) return 0;
    uint16_t qtype=ntohs(*(uint16_t*)(p+off));
    printf("      ➤ DNS  QNAME=\"%s\"  QTYPE=%u\n",qname,qtype);
    return 1;
}
