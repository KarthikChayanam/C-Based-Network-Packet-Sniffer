#ifndef ARGS_H
#define ARGS_H
#include <arpa/inet.h>

typedef enum {
    PROTO_ALL,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
} Protocol;

typedef struct {
    const char *interface;
    Protocol proto_filter;
    int packet_limit;
    const char *output_file; 
    const char *pcap_output;  

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
} SnifferArgs;

int parse_args(int argc, char *argv[], SnifferArgs *args);

#endif
