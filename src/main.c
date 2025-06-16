// src/main.c
#include <stdio.h>
#include <stdlib.h>

int start_capture(const char *device);  // Declare the function from capture.c

void usage(const char *progname) {
    printf("Usage: %s <interface>\n", progname);
    printf("Example: %s eth0\n", progname);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    return start_capture(argv[1]);
}
