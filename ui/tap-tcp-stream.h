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

#define RTT_ALL             0x0001
#define RTT_SAK             0x0002
#define RTT_RTT             0x0004
#define RTT_KRN             0x0008

typedef enum rtt_sampling_method_ {
    SAMPLING_ALL,
    SAMPLING_ALL_SACK,
    SAMPLING_RTT,
    SAMPLING_KARN,
    SAMPLING_UNDEFINED
} rtt_sampling_method;

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

    bool     ack_karn; /* true when ambiguous according to Karn's algo */

    uint8_t num_sack_ranges;
    uint32_t sack_left_edge[MAX_TCP_SACK_RANGES];
    uint32_t sack_right_edge[MAX_TCP_SACK_RANGES];
};

struct tcp_graph {
    tcp_graph_type   type;

    /* RTT sampling method (for RTT graphs only) */
    uint8_t          rtt_sampling;

    /* The stream this graph will show */
    address          src_address;
    uint16_t         src_port;
    address          dst_address;
    uint16_t         dst_port;
    uint32_t         stream;
    /* Should this be a map or tree instead? */
    struct segment  *segments;
    struct segment  *last;
};

/**
 * @brief Fill in the segment list for a TCP graph
 *
 * @param cf Capture file to scan
 * @param tg TCP graph. A valid stream must be set. If either the source or
 *        destination address types are AT_NONE the address and port
 *        information will be filled in using the first packet in the
 *        specified stream.
 */
void graph_segment_list_get(capture_file *cf, struct tcp_graph *tg);

/**
 * @brief Frees the memory allocated for a TCP graph segment list.
 *
 * This function releases all resources associated with the given TCP graph,
 * including freeing memory for addresses and segments.
 *
 * @param tg Pointer to the TCP graph structure to be freed.
 */
void graph_segment_list_free(struct tcp_graph *tg);

/* for compare_headers() */
/* segment went the same direction as the currently selected one */
#define COMPARE_CURR_DIR    0
#define COMPARE_ANY_DIR     1

/**
 * @brief Compares the headers of two TCP segments.
 * @param saddr1 Source address of the first segment.
 * @param daddr1 Destination address of the first segment.
 * @param sport1 Source port of the first segment.
 * @param dport1 Destination port of the first segment.
 * @param saddr2 Source address of the second segment.
 * @param daddr2 Destination address of the second segment.
 * @param sport2 Source port of the second segment.
 * @param dport2 Destination port of the second segment.
 * @param dir Direction flag for comparison.
 * @return The result of the comparison.
 */
int compare_headers(address *saddr1, address *daddr1, uint16_t sport1, uint16_t dport1, const address *saddr2, const address *daddr2, uint16_t sport2, uint16_t dport2, int dir);

/**
 * @brief Gets the number of data segments in a TCP graph.
 * @param tg Pointer to the TCP graph structure.
 * @return The count of data segments.
 */
int get_num_dsegs(struct tcp_graph *tg);

/**
 * @brief Gets the number of ACKs in a TCP graph.
 * @param tg Pointer to the TCP graph structure.
 * @param num_sack_ranges Pointer to an integer where the sum of SACK ranges will be stored.
 * @return The count of ACKs.
 */
int get_num_acks(struct tcp_graph *tg, int *num_sack_ranges);

/**
 * @brief Selects a TCP/IP session based on capture file.
 *
 * This function is used to select a TCP/IP session from a capture file.
 *
 * @param cf Pointer to the capture file containing the sessions.
 * @return The selected TCP/IP session ID.
 */
uint32_t select_tcpip_session(capture_file *cf);

/* This is used by rtt module only */
struct rtt_unack {
    struct rtt_unack *next;
    double        time;
    unsigned int  seqno;
    unsigned int  end_seqno;
};

/**
 * Check if a sequence number is currently in the Unacked list,
 * typically for avoiding adding redundant sequences.
 * In practice, the retrans meaning in this particular code is different
 * from TCP's one and would rather cover Keep-Alives and Spurious Retrans.
 *
 * @param list The list containing the Unacked sequences
 * @param seqno The sequence number to be searched for in the Unacked list
 * @return true if the list contains the sequence number, false otherwise
 */
bool rtt_is_retrans(struct rtt_unack *list, unsigned int seqno);

/**
 * @brief Creates a new RTT unacknowledged packet structure.
 *
 * @param time_val The timestamp of the packet.
 * @param seqno The sequence number of the packet.
 * @param seglen The length of the segment.
 * @return A pointer to the newly created rtt_unack structure.
 */
struct rtt_unack *rtt_get_new_unack(double time_val, unsigned int seqno, unsigned int seglen);

/**
 * @brief Adds a new unacknowledged packet to the list.
 *
 * @param l Pointer to the head of the unacknowledged packet list.
 * @param new_unack The new unacknowledged packet to add.
 */
void rtt_put_unack_on_list(struct rtt_unack **l, struct rtt_unack *new_unack);

/**
 * @brief Removes a specific RTT unacknowledged packet from the list.
 *
 * @param l Pointer to the head of the RTT unacknowledged packet list.
 * @param dead The RTT unacknowledged packet to be removed.
 */
void rtt_delete_unack_from_list(struct rtt_unack **l, struct rtt_unack *dead);

/**
 * @brief Destroys the unacknowledged list of TCP sequences.
 *
 * @param l Pointer to the pointer of the head of the unacknowledged list.
 */
void rtt_destroy_unack_list(struct rtt_unack **l);

/**
 * @brief Compares two TCP sequence numbers for equality.
 *
 * @param s1 The first sequence number.
 * @param s2 The second sequence number.
 * @return int 0 if the sequence numbers are equal, non-zero otherwise.
 */
static inline int
tcp_seq_eq(uint32_t s1, uint32_t s2) {
    return (int32_t)(s1 - s2) == 0;
}

/**
 * @brief Determines if one TCP sequence number is before another.
 *
 * @param s1 The first sequence number.
 * @param s2 The second sequence number.
 * @return int Returns 1 if s1 is before s2, otherwise 0.
 */
static inline int
tcp_seq_before(uint32_t s1, uint32_t s2) {
    return (int32_t)(s1 - s2) < 0;
}

/**
 * @brief Checks if one TCP sequence number is equal to or after another.
 *
 * @param s1 The first TCP sequence number.
 * @param s2 The second TCP sequence number.
 * @return int True if s1 is equal to or after s2, false otherwise.
 */
static inline int
tcp_seq_eq_or_after(uint32_t s1, uint32_t s2) {
    return !tcp_seq_before(s1, s2);
}

/**
 * @brief Determines if sequence number s1 is after sequence number s2.
 *
 * @param s1 The first sequence number.
 * @param s2 The second sequence number.
 * @return int Returns 1 if s1 is after s2, otherwise returns 0.
 */
static inline int
tcp_seq_after(uint32_t s1, uint32_t s2) {
    return (int32_t)(s1 - s2) > 0;
}

/**
 * @brief Checks if one TCP sequence number is before or equal to another.
 *
 * @param s1 The first TCP sequence number.
 * @param s2 The second TCP sequence number.
 * @return true If s1 is before or equal to s2.
 * @return false Otherwise.
 */
static inline int
tcp_seq_before_or_eq(uint32_t s1, uint32_t s2) {
    return !tcp_seq_after(s1, s2);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_TCP_STREAM_H__ */
