#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "args.h"

int parse_args(int argc, char *argv[], SnifferArgs *args) {
    args->interface = NULL;
    args->proto_filter = PROTO_ALL;
    args->packet_limit = 0;

    static struct option long_options[] = {
        {"tcp",   no_argument,       0,  0 },
        {"udp",   no_argument,       0,  1 },
        {"icmp",  no_argument,       0,  2 },
        {"all",   no_argument,       0,  3 },
        {0,       0,                 0,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                args->interface = optarg;
                break;
            case 'n':
                args->packet_limit = atoi(optarg);
                break;
            case 0: args->proto_filter = PROTO_TCP; break;
            case 1: args->proto_filter = PROTO_UDP; break;
            case 2: args->proto_filter = PROTO_ICMP; break;
            case 3: args->proto_filter = PROTO_ALL; break;
            default:
                fprintf(stderr, "Usage: %s -i <interface> [--tcp|--udp|--icmp|--all] [-n <count>]\n", argv[0]);
                return 1;
        }
    }

    if (!args->interface) {
        fprintf(stderr, "Error: Interface is required. Use -i <interface>\n");
        return 1;
    }

    return 0;
}
