//
// Created by reznik on 3/29/20.
//
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))
#define PACKET_COUNT 210000
#define CASES 7
#define PART_LEN PACKET_COUNT / CASES

#include<stdio.h>
#include<pcap.h>
#include "marine.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>



/*
* Author:  David Robert Nadeau
* Site:    http://NadeauSoftware.com/
* License: Creative Commons Attribution 3.0 Unported License
*          http://creativecommons.org/licenses/by/3.0/deed.en_US
*/
size_t getCurrentRSS(void)
{

    long rss = 0L;
    FILE* fp = NULL;
    if ( (fp = fopen( "/proc/self/statm", "r" )) == NULL )
        return (size_t)0L;      /* Can't open? */
    if ( fscanf( fp, "%*s%ld", &rss ) != 1 )
    {
        fclose( fp );
        return (size_t)0L;      /* Can't read? */
    }
    fclose( fp );
    return (size_t)rss * (size_t)sysconf( _SC_PAGESIZE);
}







typedef struct {
    struct pcap_pkthdr *header;
    const u_char *data;
} packet;

int load_cap(char *file, packet packets[]) {
    printf("Start loading packets from cap\n");

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(file, errbuff);
    if (pcap == NULL) {
        printf("Error will opening the cap: %s\n", errbuff);
        return -1;
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


void benchmark(packet packets[], int part, char *bpf, char *display_filter, char *fields[], int fields_len) {
    char err_msg[512];
    int filter_id = marine_add_filter(bpf, display_filter, fields, fields_len, err_msg);

    if (filter_id < 0) {
        printf("Error creating filter id: %s", err_msg);
        return;
    }

    // Splitting the cap into parts so no cache inside wireshark will effect the results
    packet packet_part[PART_LEN];
    memcpy(packet_part, &packets[PART_LEN * part], PART_LEN * sizeof(*packets));

    marine_result *results[PACKET_COUNT];
    size_t memory_start = getCurrentRSS( );
    clock_t start = clock();
    for (int i = 0; i < PART_LEN; ++i) {
        packet p = packets[i];
        marine_result *packet_results = marine_dissect_packet(filter_id, (char *) p.data, p.header->len);
        results[i] = packet_results;
    }
    clock_t end = clock();

    // Splitting those for loops to avoid wasting time on asserting and marine_free in the benchmark
    for (int i = 0; i < PART_LEN; ++i) {
        assert(results[i]->result == 1);
        marine_free(results[i]);
    }
    sleep(60);
    size_t memory_end = getCurrentRSS();


    float total_time = ((float) end - start) / CLOCKS_PER_SEC;
    float pps = (float) PART_LEN / total_time;
    float memory_usage = ((float)memory_end - memory_start) / 1024 / 1024;
    printf("%d packets took: %f, which is its %f pps!\n The test took: %lf MB\n", PART_LEN, total_time, pps,
           memory_usage);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("You didn't pass a cap!\n");
        printf("Have you run cap_maker.py to create the testing cap?\n");
        printf("After generating the cap add the path as argument\n");
        return -1;
    }

    char *file = argv[1];
    packet packets[PACKET_COUNT];
    if (load_cap(file, packets) < 0) {
        printf("\nSomething went wrong\n");
        return -1;
    }

    int part = 0;
//    char *bpf = "tcp port 4000 or tcp port 4001 or tcp port 4002 or tcp port 4003 or tcp port 4004 or tcp port 4005 or tcp port 4006 or tcp port 4007 or tcp port 4008 or tcp port 4009 or tcp port 4010 or tcp port 4011 or tcp port 4012 or tcp port 4013 or tcp port 4014 or tcp port 4015 or tcp port 4016 or tcp port 4017 or tcp port 4018 or tcp port 4019 or udp port 4000 or udp port 4001 or udp port 4002 or udp port 4003 or udp port 4004 or udp port 4005 or udp port 4006 or udp port 4007 or udp port 4008 or udp port 4009 or udp port 4010 or udp port 4011 or udp port 4012 or udp port 4013 or udp port 4014 or udp port 4015 or udp port 4016 or udp port 4017 or udp port 4018 or udp port 4019";
//    char *dfilter = "tcp.port == 4000 or tcp.port == 4001 or tcp.port == 4002 or tcp.port == 4003 or tcp.port == 4004 or tcp.port == 4005 or tcp.port == 4006 or tcp.port == 4007 or tcp.port == 4008 or tcp.port == 4009 or tcp.port == 4010 or tcp.port == 4011 or tcp.port == 4012 or tcp.port == 4013 or tcp.port == 4014 or tcp.port == 4015 or tcp.port == 4016 or tcp.port == 4017 or tcp.port == 4018 or tcp.port == 4019 or udp.port == 4000 or udp.port == 4001 or udp.port == 4002 or udp.port == 4003 or udp.port == 4004 or udp.port == 4005 or udp.port == 4006 or udp.port == 4007 or udp.port == 4008 or udp.port == 4009 or udp.port == 4010 or udp.port == 4011 or udp.port == 4012 or udp.port == 4013 or udp.port == 4014 or udp.port == 4015 or udp.port == 4016 or udp.port == 4017 or udp.port == 4018 or udp.port == 4019";
    char *three_fields[] = {"ip.proto", "eth.dst", "ip.host"};
//    char *eight_fields[] = {"ip.proto", "eth.dst", "ip.host", "eth.src", "eth.type", "ip.hdr_len", "ip.version", "frame.encap_type"};


    init_marine();
//    size_t memory_start = getCurrentRSS( );
//    printf("Benchmark with BPF\n");
//    benchmark(packets, part++, bpf, NULL, NULL, 0);
//
//    printf("\nBenchmark with Display filter\n");
//    benchmark(packets, part++, NULL, dfilter, NULL, 0);
//
//    printf("\nBenchmark with BPF and Display filter\n");
//    benchmark(packets, part++, bpf, dfilter, NULL, 0);

    printf("\nBenchmark with three extracted fields\n");
    benchmark(packets, part++, NULL, NULL, three_fields, 3);

//    printf("\nBenchmark with eight extracted fields\n");
//    benchmark(packets, part++, NULL, NULL, eight_fields, 8);
//
//    printf("\nBenchmark with BPF, Display filter and three extracted fields\n");
//    benchmark(packets, part++, bpf, dfilter, three_fields, 3);
//
//    printf("\nBenchmark with BPF, Display filter and eight extracted fields\n");
//    benchmark(packets, part, bpf, dfilter, eight_fields, 8);
//    size_t memory_end = getCurrentRSS( );
//    printf("%lf", (((float)memory_end - memory_start) / 1024 / 1024));
    destroy_marine();
    return 0;
}

