/* dns.h */          /*  — minimal DNS question parser —  */
#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include <stdint.h>
int parse_dns(const uint8_t *payload, int len);
#endif
