#include <stdio.h>
#include <string.h>
#include "http.h"

static const void *find_mem(const void *h,int hlen,const char *n,int nlen){
    return memmem(h,hlen,n,nlen); /* GNU/libc; replace if needed */
}
int parse_http(const uint8_t *p,int len){
    if(len<14) return 0;
    if(memcmp(p,"GET ",4)&&memcmp(p,"POST",4)&&memcmp(p,"HEAD",4)&&memcmp(p,"PUT ",4))
        return 0;
    const char *end=find_mem(p,len,"\r\n",2); if(!end) return 0;
    printf("      ➤ HTTP %.*s\n",(int)(end-(char*)p),p);
    const char *h=find_mem(p,len,"\r\nHost:",7);
    if(h){
        h+=7; const char *he=find_mem(h, (const char *)p + len - (const char *)h, "\r\n", 2);
        if(he) printf("          Host:%.*s\n",(int)(he-h),h);
    }
    return 1;
}
