#include <stdio.h>
#include "tls.h"

int parse_tls(const uint8_t *p,int len){
    if(len<5||p[0]!=0x16) return 0;
    int rec_len=(p[3]<<8)|p[4]; if(rec_len+5>len) return 0;
    const uint8_t *hs=p+5; if(hs[0]!=0x01) return 0; /* ClientHello */
    const uint8_t *d=hs+4+34; if(d>=p+len) return 0;
    int sid=d[0]; d+=1+sid; int cs=(d[0]<<8)|d[1]; d+=2+cs;
    int cm=d[0]; d+=1+cm; int ext_len=(d[0]<<8)|d[1]; d+=2;
    const uint8_t *end=d+ext_len;
    while(d+4<=end){
        int t=(d[0]<<8)|d[1],l=(d[2]<<8)|d[3]; d+=4;
        if(t==0&&d+5<=end){ /* SNI */
            const uint8_t *n=d+5; int nlen=(d[3]<<8)|d[4];
            if(n+nlen<=end)
                printf("      ➤ TLS  SNI=\"%.*s\"\n",nlen,n);
            return 1;
        }
        d+=l;
    }
    return 0;
}
