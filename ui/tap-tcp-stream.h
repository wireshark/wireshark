/* tap-tcp-stream.h
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
    guint32 num;
    guint32 rel_secs;
    guint32 rel_usecs;
    /* Currently unused.
    guint32 abs_secs;
    guint32 abs_usecs;
    */

    guint32 th_seq;
    guint32 th_ack;
    guint16 th_flags;
    guint32 th_win;   /* make it 32 bits so we can handle some scaling */
    guint32 th_seglen;
    guint16 th_sport;
    guint16 th_dport;
    address ip_src;
    address ip_dst;

    guint8  num_sack_ranges;
    guint32 sack_left_edge[MAX_TCP_SACK_RANGES];
    guint32 sack_right_edge[MAX_TCP_SACK_RANGES];
};

struct tcp_graph {
    tcp_graph_type   type;

    /* The stream this graph will show */
    address          src_address;
    guint16          src_port;
    address          dst_address;
    guint16          dst_port;
    guint32          stream;
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

int compare_headers(address *saddr1, address *daddr1, guint16 sport1, guint16 dport1, const address *saddr2, const address *daddr2, guint16 sport2, guint16 dport2, int dir);

int get_num_dsegs(struct tcp_graph * );
int get_num_acks(struct tcp_graph *, int * );

guint32 select_tcpip_session(capture_file *);

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
tcp_seq_before(guint32 s1, guint32 s2) {
    return (gint32)(s1 - s2) < 0;
}

static inline int
tcp_seq_eq_or_after(guint32 s1, guint32 s2) {
    return !tcp_seq_before(s1, s2);
}

static inline int
tcp_seq_after(guint32 s1, guint32 s2) {
    return (gint32)(s1 - s2) > 0;
}

static inline int tcp_seq_before_or_eq(guint32 s1, guint32 s2) {
    return !tcp_seq_after(s1, s2);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_TCP_STREAM_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
