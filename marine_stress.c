#if __APPLE__
    #include "macos_ether.h"
#else
    #include <netinet/ether.h>
#endif

#include "marine.h"
#include "marine_dev.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ip.h>

#define PACKET_LEN 800U
#define IP_LEN (PACKET_LEN - sizeof(struct ether_header))
void fill_random(char *buf, size_t len) {
    for (size_t i = 0; i < len / sizeof(int); ++i) {
        *(((int *)buf) + i) = rand();
    }
}

void random_ip(char *buf) {
    struct ether_header* ether_header = (struct ether_header*) buf;
    struct iphdr* iphdr = (struct iphdr*) (buf + sizeof(struct ether_header));
    ether_header->ether_type = htons(ETHERTYPE_IP);
    iphdr->ihl = 5;
    iphdr->version = 4;
    iphdr->tos = 0;
    iphdr->tot_len = htons(IP_LEN);
    iphdr->frag_off = 0;
}

void random_tcp(char *buf) {
    struct iphdr* iphdr = (struct iphdr*) (buf + sizeof(struct ether_header));
    iphdr->protocol = IPPROTO_TCP;
}

int report_mem(size_t rss) {
    return printf("MEMORY: %.2lfMB\n", rss / 1024.0 / 1024.0);
}

size_t report_current_mem(void) {
    size_t rss = get_current_rss();
    report_mem(rss);
    return rss;
}

#define CHUNK (1U << 15U)
#define TOTAL_PACKETS (CHUNK << 4U)

int main(void) {
    srand(0);
    char *fields[] = {"eth.src", "ip.dst", "tcp.srcport"};
    char *err_msg;
    report_current_mem();
    printf("Loading marine...\n");
    set_epan_auto_reset_count(CHUNK - 1);
    init_marine();
    report_current_mem();
    printf("Adding filter\n");
    int filter_id = marine_add_filter("ether[0] & 1 == 0", "frame[0] & 2",
                                      fields, 3, ETHERNET_ENCAP, &err_msg);
    if (filter_id < 0) {
        fprintf(stderr, "Could not add filter: %s\n", err_msg);
        marine_free_err_msg(err_msg);
        return -1;
    }
    char data[PACKET_LEN] = {0};
    size_t prev_rss;
    size_t rss = report_current_mem();
    double bytes_per_packet;
    double total_bytes_per_packet = 0;
    size_t chunks = 0;
    for (size_t i = 1; i <= TOTAL_PACKETS; ++i) {
        fill_random(data, PACKET_LEN);
        unsigned int flags = rand();
        if ((flags & 1U) == 0) {
            random_ip(data);
            if ((flags & 2U) == 0) {
                random_tcp(data);
            }
        }
        marine_free(marine_dissect_packet(filter_id, data, PACKET_LEN));
        if (i % CHUNK == 0) {
            prev_rss = rss;
            rss = get_current_rss();
            // cast to long long to handle negative numbers properly
            bytes_per_packet = ((double) (long long)(rss - prev_rss)) / CHUNK;
            total_bytes_per_packet += bytes_per_packet;
            ++chunks;
            printf("CHUNK #%ld: BYTES-PER-PACKET: %.2lf, ", chunks, bytes_per_packet);
            report_mem(rss);
        }
    }
    printf("\nTOTAL\n----------\n");
    printf("bytes-per-packet:: %.2lf\n", total_bytes_per_packet / chunks);
    destroy_marine();
    return 0;
}
