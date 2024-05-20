/** @file
 *
 * TCP stream statistics
 * Originally from tcp_graph.c by Pavel Mores <pvl@uh.cz>
 * Win32 port:  rwh@unifiedtech.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_TCP_STREAM_H__
#define __TAP_TCP_STREAM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum tcp_graph_type_ {
    GRAPH_TSEQ_STEVENS,
    GRAPH_TSEQ_TCPTRACE,
    GRAPH_THROUGHPUT,
    GRAPH_RTT,
    GRAPH_WSCALE,
    GRAPH_UNDEFINED
} tcp_graph_type;

struct segment {
    struct segment *next;
    uint32_t num;
    uint32_t rel_secs;
    uint32_t rel_usecs;
    /* Currently unused.
    time_t abs_secs;
    uint32_t abs_usecs;
    */

    uint32_t th_seq;
    uint32_t th_ack;
    uint32_t th_rawseq;
    uint32_t th_rawack;
    uint16_t th_flags;
    uint32_t th_win;   /* make it 32 bits so we can handle some scaling */
    uint32_t th_seglen;
    uint16_t th_sport;
    uint16_t th_dport;
    address ip_src;
    address ip_dst;

    uint8_t num_sack_ranges;
    uint32_t sack_left_edge[MAX_TCP_SACK_RANGES];
    uint32_t sack_right_edge[MAX_TCP_SACK_RANGES];
};

struct tcp_graph {
    tcp_graph_type   type;

    /* The stream this graph will show */
    address          src_address;
    uint16_t         src_port;
    address          dst_address;
    uint16_t         dst_port;
    uint32_t         stream;
    /* Should this be a map or tree instead? */
    struct segment  *segments;
};

/** Fill in the segment list for a TCP graph
 *
 * @param cf Capture file to scan
 * @param tg TCP graph. A valid stream must be set. If either the source or
 *        destination address types are AT_NONE the address and port
 *        information will be filled in using the first packet in the
 *        specified stream.
 */
void graph_segment_list_get(capture_file *cf, struct tcp_graph *tg);
void graph_segment_list_free(struct tcp_graph * );

/* for compare_headers() */
/* segment went the same direction as the currently selected one */
#define COMPARE_CURR_DIR    0
#define COMPARE_ANY_DIR     1

int compare_headers(address *saddr1, address *daddr1, uint16_t sport1, uint16_t dport1, const address *saddr2, const address *daddr2, uint16_t sport2, uint16_t dport2, int dir);

int get_num_dsegs(struct tcp_graph * );
int get_num_acks(struct tcp_graph *, int * );

uint32_t select_tcpip_session(capture_file *);

/* This is used by rtt module only */
struct rtt_unack {
    struct rtt_unack *next;
    double        time;
    unsigned int  seqno;
    unsigned int  end_seqno;
};

int rtt_is_retrans(struct rtt_unack * , unsigned int );
struct rtt_unack *rtt_get_new_unack(double , unsigned int , unsigned int );
void rtt_put_unack_on_list(struct rtt_unack ** , struct rtt_unack * );
void rtt_delete_unack_from_list(struct rtt_unack ** , struct rtt_unack * );
void rtt_destroy_unack_list(struct rtt_unack ** );

static inline int
tcp_seq_before(uint32_t s1, uint32_t s2) {
    return (int32_t)(s1 - s2) < 0;
}

static inline int
tcp_seq_eq_or_after(uint32_t s1, uint32_t s2) {
    return !tcp_seq_before(s1, s2);
}

static inline int
tcp_seq_after(uint32_t s1, uint32_t s2) {
    return (int32_t)(s1 - s2) > 0;
}

static inline int tcp_seq_before_or_eq(uint32_t s1, uint32_t s2) {
    return !tcp_seq_after(s1, s2);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_TCP_STREAM_H__ */
