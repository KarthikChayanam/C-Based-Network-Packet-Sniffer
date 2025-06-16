// src/capture.c
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static pcap_t *handle = NULL;

void decode_packet(const u_char *packet, int size);

void handle_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Captured packet of length: %d bytes\n", header->len);
    decode_packet(packet, header->len);
}


void cleanup(int signum) {
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        printf("\nCapture session terminated.\n");
    }
    exit(0);
}

int start_capture(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open device for live capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    // Handle Ctrl+C (SIGINT)
    signal(SIGINT, cleanup);

    printf("Listening on %s...\n", device);
    pcap_loop(handle, 0, handle_packet, NULL);  // 0 = infinite

    pcap_close(handle);
    return 0;
}
