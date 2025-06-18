#ifndef ARGS_H
#define ARGS_H

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
} SnifferArgs;

int parse_args(int argc, char *argv[], SnifferArgs *args);

#endif
