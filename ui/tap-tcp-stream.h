/* tap-tcp-stream.h
 * TCP stream statistics
 * Originally from tcp_graph.c by Pavel Mores <pvl@uh.cz>
 * Win32 port:  rwh@unifiedtech.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
    GRAPH_WSCALE
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
 * @param stream_known If FALSE, session information will be filled in using
 *        the currently selected packet. If FALSE, session information will
 *        be matched against tg.
 */
void graph_segment_list_get(capture_file *cf, struct tcp_graph *tg, gboolean stream_known );
void graph_segment_list_free(struct tcp_graph * );

/* for compare_headers() */
/* segment went the same direction as the currently selected one */
#define COMPARE_CURR_DIR    0
#define COMPARE_ANY_DIR     1

int compare_headers(address *saddr1, address *daddr1, guint16 sport1, guint16 dport1, const address *saddr2, const address *daddr2, guint16 sport2, guint16 dport2, int dir);

int get_num_dsegs(struct tcp_graph * );
int get_num_acks(struct tcp_graph *, int * );

struct tcpheader *select_tcpip_session(capture_file *, struct segment * );

/* This is used by rtt module only */
struct unack {
    struct unack *next;
    double        time;
    unsigned int  seqno;
};

int rtt_is_retrans(struct unack * , unsigned int );
struct unack *rtt_get_new_unack(double , unsigned int );
void rtt_put_unack_on_list(struct unack ** , struct unack * );
void rtt_delete_unack_from_list(struct unack ** , struct unack * );


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
