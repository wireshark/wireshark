//
// Created by reznik on 3/29/20.
//
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))
#define PACKET_COUNT 210000
#define CASES 7
#define PART PACKET_COUNT / CASES

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
        printf("Have you run cap_maker.py to create the testing cap?");
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
    float total_time = ((float) total)  / CLOCKS_PER_SEC;
    float pps = (float) packets_len / total_time;
    printf("%d packets took: %f, which is its %f pps!\n", packets_len, total_time, pps);
}


int main(void) {
    init_marine();
    char *file = "/projects/marine-core/benchmark.cap";
    packet packets[PACKET_COUNT];
    packet part[PART];
    load_cap(file, packets);

    char* bpf = "tcp port 4000 or tcp port 4001 or tcp port 4002 or tcp port 4003 or tcp port 4004 or tcp port 4005 or tcp port 4006 or tcp port 4007 or tcp port 4008 or tcp port 4009 or tcp port 4010 or tcp port 4011 or tcp port 4012 or tcp port 4013 or tcp port 4014 or tcp port 4015 or tcp port 4016 or tcp port 4017 or tcp port 4018 or tcp port 4019 or udp port 4000 or udp port 4001 or udp port 4002 or udp port 4003 or udp port 4004 or udp port 4005 or udp port 4006 or udp port 4007 or udp port 4008 or udp port 4009 or udp port 4010 or udp port 4011 or udp port 4012 or udp port 4013 or udp port 4014 or udp port 4015 or udp port 4016 or udp port 4017 or udp port 4018 or udp port 4019";
    char* dfilter = "tcp.port == 4000 or tcp.port == 4001 or tcp.port == 4002 or tcp.port == 4003 or tcp.port == 4004 or tcp.port == 4005 or tcp.port == 4006 or tcp.port == 4007 or tcp.port == 4008 or tcp.port == 4009 or tcp.port == 4010 or tcp.port == 4011 or tcp.port == 4012 or tcp.port == 4013 or tcp.port == 4014 or tcp.port == 4015 or tcp.port == 4016 or tcp.port == 4017 or tcp.port == 4018 or tcp.port == 4019 or udp.port == 4000 or udp.port == 4001 or udp.port == 4002 or udp.port == 4003 or udp.port == 4004 or udp.port == 4005 or udp.port == 4006 or udp.port == 4007 or udp.port == 4008 or udp.port == 4009 or udp.port == 4010 or udp.port == 4011 or udp.port == 4012 or udp.port == 4013 or udp.port == 4014 or udp.port == 4015 or udp.port == 4016 or udp.port == 4017 or udp.port == 4018 or udp.port == 4019";
    char *three_fields[] = {"ip.proto", "eth.dst", "ip.host"};
    char *eight_fields[] = {"ip.proto", "eth.dst", "ip.host", "eth.src", "eth.type", "ip.hdr_len", "ip.version", "frame.encap_type"};

    memcpy(part, &packets[PART*0], PART * sizeof(*packets));
    printf("Benchmark with BPF\n");
    benchmark(part, PART, bpf, NULL, NULL, 0);
    printf("\n");

    memcpy(part, &packets[PART*1], PART * sizeof(*packets));
    printf("Benchmark with Display filter\n");
    benchmark(part, PART, NULL, dfilter, NULL, 0);
    printf("\n");

    memcpy(part, &packets[PART*2], PART * sizeof(*packets));
    printf("Benchmark with BPF and Display filter\n");
    benchmark(part, PART, bpf, dfilter, NULL, 0);
    printf("\n");

    memcpy(part, &packets[PART*3], PART * sizeof(*packets));
    printf("Benchmark with three extracted fields\n");
    benchmark(part, PART, NULL, NULL, three_fields, 3);
    printf("\n");

    memcpy(part, &packets[PART*4], PART * sizeof(*packets));
    printf("Benchmark with eight extracted fields\n");
    benchmark(part, PART, NULL, NULL, eight_fields, 8);
    printf("\n");

    memcpy(part, &packets[PART*5], PART * sizeof(*packets));
    printf("Benchmark with BPF, Display filter and three extracted fields\n");
    benchmark(part, PART, bpf, dfilter, three_fields, 3);
    printf("\n");

    memcpy(part, &packets[PART*6], PART * sizeof(*packets));
    printf("Benchmark with BPF, Display filter and eight extracted fields\n");
    benchmark(part, PART, bpf, dfilter, eight_fields, 8);
    printf("\n");

    destroy_marine();
    return 0;
}

