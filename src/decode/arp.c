#include <stdio.h>
#include <arpa/inet.h>
#include "arp.h"

struct arp_hdr{uint16_t htype,ptype;uint8_t hlen,plen;uint16_t op;
               uint8_t sha[6],spa[4],tha[6],tpa[4];};
static void mac(const uint8_t*m,char*s){
    sprintf(s,"%02X:%02X:%02X:%02X:%02X:%02X",
            m[0],m[1],m[2],m[3],m[4],m[5]);
}
int parse_arp(const uint8_t*p,int len){
    if(len<28) return 0;
    const struct arp_hdr*h=(const struct arp_hdr*)p;
    if(ntohs(h->htype)!=1||ntohs(h->ptype)!=0x0800) return 0;
    char s[18],t[18],sip[16],tip[16];
    mac(h->sha,s); mac(h->tha,t);
    inet_ntop(AF_INET,h->spa,sip,sizeof sip);
    inet_ntop(AF_INET,h->tpa,tip,sizeof tip);
    const char*op=(ntohs(h->op)==1)?"REQUEST":(ntohs(h->op)==2)?"REPLY":"OTHER";
    printf("      ➤ ARP %-7s %s (%s) → %s (%s)\n",op,sip,s,tip,t);
    return 1;
}
