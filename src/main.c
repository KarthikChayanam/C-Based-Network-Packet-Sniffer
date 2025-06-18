// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include "args.h"

int start_capture(const SnifferArgs *args);

void usage(const char *progname) {
    printf("Usage: %s <interface>\n", progname);
    printf("Example: %s eth0\n", progname);
}

int main(int argc, char *argv[]) {
    SnifferArgs args;
    if (parse_args(argc, argv, &args)) {
        return 1;
    }
    return start_capture(&args);
}
