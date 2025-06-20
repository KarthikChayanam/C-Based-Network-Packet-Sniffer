#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "args.h"

int parse_args(int argc, char *argv[], SnifferArgs *args) {
    args->interface = NULL;
    args->proto_filter = PROTO_ALL;
    args->packet_limit = 0;
    args->output_file = NULL;
    args->pcap_output = NULL; 
    args->src_ip[0] = '\0';
    args->dst_ip[0] = '\0';
    args->src_port = 0;
    args->dst_port = 0;
    args->proto_num = 0;

    static struct option long_options[] = {
        {"tcp",   no_argument,       0,  0 },
        {"udp",   no_argument,       0,  1 },
        {"icmp",  no_argument,       0,  2 },
        {"all",   no_argument,       0,  3 },
        {"output", required_argument, 0, 'o' },
        {"pcap", required_argument, 0, 4},
        {"src-ip",    required_argument, 0, 5},
        {"dst-ip",    required_argument, 0, 6},
        {"src-port",  required_argument, 0, 7},
        {"dst-port",  required_argument, 0, 8},
        {"proto-num", required_argument, 0, 9},
        {0,       0,                 0,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': args->interface = optarg; break;
            case 'n': args->packet_limit = atoi(optarg); break;
            case 'o': args->output_file = optarg; break;
            case 0:   args->proto_filter = PROTO_TCP; break;
            case 1:   args->proto_filter = PROTO_UDP; break;
            case 2:   args->proto_filter = PROTO_ICMP; break;
            case 3:   args->proto_filter = PROTO_ALL; break;
            case 4:   args->pcap_output = optarg; break;
            case 5:   strncpy(args->src_ip, optarg, INET_ADDRSTRLEN); break;
            case 6:   strncpy(args->dst_ip, optarg, INET_ADDRSTRLEN); break;
            case 7:   args->src_port = atoi(optarg); break;
            case 8: args->dst_port = atoi(optarg); break;
            case 9: {
                int n = atoi(optarg);
                if (n < 0 || n > 255) {
                    fprintf(stderr, "Error: protocol number must be 0‑255\n");
                    return 1;
                }
                args->proto_num = n;
                break;
            }
            default:
                fprintf(stderr, "Usage: %s -i <iface> [--tcp|--udp|--icmp|--all] [-n N] [-o file.csv] [--pcap file.pcap] "
                        "[--src-ip IP] [--dst-ip IP] [--src-port PORT] [--dst-port PORT] [--proto-num N]\n", argv[0]);
                return 1;
        }
    }

    if (!args->interface) {
        fprintf(stderr, "Error: Interface is required.\n");
        return 1;
    }

    return 0;
}

