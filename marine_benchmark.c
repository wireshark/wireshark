#define CASES 7

#include<stdio.h>
#include<pcap.h>
#include "marine.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <zconf.h>

typedef struct {
    struct pcap_pkthdr *header;
    const u_char *data;
} packet;


/*
* Author:  David Robert Nadeau
* Site:    http://NadeauSoftware.com/
* License: Creative Commons Attribution 3.0 Unported License
*          http://creativecommons.org/licenses/by/3.0/deed.en_US
*/
size_t get_current_rss(void) {
    long rss = 0L;
    FILE *fp = NULL;
    if ((fp = fopen("/proc/self/statm", "r")) == NULL) {
        return (size_t) 0L;
    }
    if (fscanf(fp, "%*s%ld", &rss) != 1) {
        fclose(fp);
        return (size_t) 0L;
    }
    fclose(fp);
    return (size_t) rss * (size_t) sysconf(_SC_PAGESIZE);
}

int load_cap(char *file, packet **packets) {
    printf("Start loading packets from cap\n");

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(file, errbuff);
    if (pcap == NULL) {
        printf("Error will opening the cap: %s\n", errbuff);
        return -1;
    }

    int allocated_packets = 10000;
    int p_count = 0;
    struct pcap_pkthdr *header;
    const u_char *data;

    packet* inner_packets = (packet *)malloc(sizeof(packet) * allocated_packets);
    while (pcap_next_ex(pcap, &header, &data) >= 0) {
        packet p = {header, data};
        inner_packets[p_count] = p;
        p_count++;
        if (p_count >= allocated_packets) {
            allocated_packets *= 2;
            inner_packets = (packet * )realloc(inner_packets, allocated_packets * sizeof(packet));
        }
    }
    inner_packets = (packet * )realloc(inner_packets, p_count * sizeof(packet));
    *packets = inner_packets;
    printf("Cap has been loaded, %d packets were loaded\n", p_count);
    return p_count;
}

void benchmark(packet packets[], int packet_len, int part, char *bpf, char *display_filter, char *fields[], int fields_len) {
    char err_msg[512];
    int filter_id = marine_add_filter(bpf, display_filter, fields, fields_len, err_msg);

    if (filter_id < 0) {
        printf("Error creating filter id: %s", err_msg);
        return;
    }

    // Splitting the cap into parts so no cache inside wireshark will effect the results
    int start_index = packet_len * part;
    int end_index = start_index + packet_len;

    size_t memory_start = get_current_rss();
    clock_t start = clock();
    for (int i = start_index; i < end_index; ++i) {
        packet p = packets[i];
        marine_result *packet_results = marine_dissect_packet(filter_id, (char *) p.data, p.header->len);
        assert(packet_results->result == 1);
        marine_free(packet_results);
    }
    clock_t end = clock();
    size_t memory_end = get_current_rss();

    float total_time = ((float) end - start) / CLOCKS_PER_SEC;
    float pps = (float) packet_len / total_time;
    float memory_usage = ((float) memory_end - memory_start) / 1024 / 1024;
    printf("%d packets took: %f, which is its %f pps!\n The test took: %lf MB\n", 30000, total_time, pps,
           memory_usage);
}

int print_title(char *str) {
    return printf("\n\033[4:1m%s\033[0m\n", str);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("You didn't pass a cap!\n");
        printf("Have you run cap_maker.py to create the testing cap?\n");
        printf("After generating the cap add the path as argument\n");
        return -1;
    }

    char *cap_file = argv[1];
    packet *packets;
    int packet_count = load_cap(cap_file, &packets);
    if (packet_count < 0) {
        printf("\nSomething went wrong\n");
        return -1;
    }

    int packet_per_case = packet_count / CASES;

    int part = 0;
    char *bpf = "tcp port 4000 or tcp port 4001 or tcp port 4002 or tcp port 4003 or tcp port 4004 or tcp port 4005 or tcp port 4006 or tcp port 4007 or tcp port 4008 or tcp port 4009 or tcp port 4010 or tcp port 4011 or tcp port 4012 or tcp port 4013 or tcp port 4014 or tcp port 4015 or tcp port 4016 or tcp port 4017 or tcp port 4018 or tcp port 4019 or udp port 4000 or udp port 4001 or udp port 4002 or udp port 4003 or udp port 4004 or udp port 4005 or udp port 4006 or udp port 4007 or udp port 4008 or udp port 4009 or udp port 4010 or udp port 4011 or udp port 4012 or udp port 4013 or udp port 4014 or udp port 4015 or udp port 4016 or udp port 4017 or udp port 4018 or udp port 4019";
    char *dfilter = "tcp.port == 4000 or tcp.port == 4001 or tcp.port == 4002 or tcp.port == 4003 or tcp.port == 4004 or tcp.port == 4005 or tcp.port == 4006 or tcp.port == 4007 or tcp.port == 4008 or tcp.port == 4009 or tcp.port == 4010 or tcp.port == 4011 or tcp.port == 4012 or tcp.port == 4013 or tcp.port == 4014 or tcp.port == 4015 or tcp.port == 4016 or tcp.port == 4017 or tcp.port == 4018 or tcp.port == 4019 or udp.port == 4000 or udp.port == 4001 or udp.port == 4002 or udp.port == 4003 or udp.port == 4004 or udp.port == 4005 or udp.port == 4006 or udp.port == 4007 or udp.port == 4008 or udp.port == 4009 or udp.port == 4010 or udp.port == 4011 or udp.port == 4012 or udp.port == 4013 or udp.port == 4014 or udp.port == 4015 or udp.port == 4016 or udp.port == 4017 or udp.port == 4018 or udp.port == 4019";
    char *three_fields[] = {
            "ip.proto",
            "eth.dst",
            "ip.host"
    };
    char *eight_fields[] = {
            "ip.proto",
            "eth.dst",
            "ip.host",
            "eth.src",
            "eth.type",
            "ip.hdr_len",
            "ip.version",
            "frame.encap_type"
    };

    init_marine();
    size_t memory_start = get_current_rss();
    print_title("Benchmark with BPF");
    benchmark(packets, packet_per_case, part++, bpf, NULL, NULL, 0);

    print_title("Benchmark with Display filter");
    benchmark(packets, packet_per_case, part++, NULL, dfilter, NULL, 0);

    print_title("Benchmark with BPF and Display filter");
    benchmark(packets, packet_per_case, part++, bpf, dfilter, NULL, 0);

    print_title("Benchmark with three extracted fields");
    benchmark(packets, packet_per_case, part++, NULL, NULL, three_fields, 3);

    print_title("Benchmark with eight extracted fields");
    benchmark(packets, packet_per_case, part++, NULL, NULL, eight_fields, 8);

    print_title("Benchmark with BPF, Display filter and three extracted fields");
    benchmark(packets, packet_per_case, part++, bpf, dfilter, three_fields, 3);

    print_title("Benchmark with BPF, Display filter and eight extracted fields");
    benchmark(packets, packet_per_case, part, bpf, dfilter, eight_fields, 8);

    size_t memory_end = get_current_rss();
    printf("Total memory usage: %lf", (((float) memory_end - memory_start) / 1024 / 1024));
    free(packets);
    destroy_marine();
    return 0;
}

