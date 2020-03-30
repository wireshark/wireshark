//
// Created by reznik on 3/29/20.
//
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))
#define PACKET_COUNT 200000
#define TEST_COUNT 5

#include<stdio.h>
#include<pcap.h>
#include "marine.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

typedef struct {
    struct pcap_pkthdr *header;
    const u_char *data;
} packet;

int load_cap(char *file, packet packets[]) {
    printf("Start loading packets from cap\n");

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(file, errbuff);
    if (pcap == NULL) {
        printf("Error will opening the cap: %s", errbuff);
        return 0;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int packet_counter = 0;
    while (pcap_next_ex(pcap, &header, &data) >= 0) {
        packet p = {header, data};
        packets[packet_counter] = p;
        ++packet_counter;
    }
    printf("Cap has been loaded, %d packets were loaded, start benchmarking\n\n", packet_counter);
    return packet_counter;
}


void benchmark(packet packets[], int packets_len, char *bpf, char *display_filter, char *fields[], int fields_len) {
    char err_msg[512];
    int filter_id = marine_add_filter(bpf, display_filter, fields, fields_len, err_msg);

    if (filter_id < 0) {
        printf("Error creating filter id: %s", err_msg);
        return;
    }
    clock_t total = 0;
    marine_result *results[PACKET_COUNT];
    for(int c = 0; c < TEST_COUNT; ++c) {
        clock_t start = clock();
        for (int i = 0; i < packets_len; ++i) {
            packet p = packets[i];
            marine_result *packet_results = marine_dissect_packet(filter_id, (char *) p.data, p.header->len);
            results[i] = packet_results;
        }
        clock_t end = clock();

        for (int i = 0; i < packets_len; ++i) {
            assert(results[i]->result == 1);
            marine_free(results[i]);
        }
        total += end - start;
    }
    float total_time = ((float) total) / TEST_COUNT / CLOCKS_PER_SEC;
    float pps = (float) packets_len / total_time;
    printf("Result after %d cycles:\n %d packets took: %f, which is its %f pps!\n", TEST_COUNT, packets_len, total_time, pps);
}


int main(void) {
    init_marine();
    char *file = "/projects/marine-core/00:00:00:9f:f8:3b-00:00:00:87:7e:0e-88.44.85.145-212.110.118.170-27000:56385.cap";
    packet packets[PACKET_COUNT];
    int packets_len = load_cap(file, packets);

    char* bpf = "tcp port 56385 or tcp port 27000";
    char* dfilter = "tcp.srcport == 27000 or tcp.srcport == 56385";
    char *three_fields[] = {"ip.proto", "tcp.port", "ip.host"};
    char *eight_fields[] = {"ip.proto", "tcp.port", "ip.host", "eth.addr", "eth.type", "ip.hdr_len", "ip.version", "frame.encap_type"};

    printf("Benchmark with BPF\n");
    benchmark(packets, packets_len, bpf, NULL, NULL, 0);
    printf("\n");

    printf("Benchmark with Display filter\n");
    benchmark(packets, packets_len, NULL, dfilter, NULL, 0);
    printf("\n");

    printf("Benchmark with BPF and Display filter\n");
    benchmark(packets, packets_len, bpf, dfilter, NULL, 0);
    printf("\n");

    printf("Benchmark with three extracted fields\n");
    benchmark(packets, packets_len, NULL, NULL, three_fields, 3);
    printf("\n");

    printf("Benchmark with eight extracted fields\n");
    benchmark(packets, packets_len, NULL, NULL, eight_fields, 8);
    printf("\n");

    printf("Benchmark with BPF, Display filter and three extracted fields\n");
    benchmark(packets, packets_len, bpf, dfilter, three_fields, 3);
    printf("\n");

    printf("Benchmark with BPF, Display filter and eight extracted fields\n");
    benchmark(packets, packets_len, bpf, dfilter, eight_fields, 8);
    printf("\n");

    destroy_marine();
    return 0;
}

