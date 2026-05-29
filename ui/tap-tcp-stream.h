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

/**
 * @brief Selects the plot type displayed in the TCP Stream Graph dialog.
 */
typedef enum tcp_graph_type_ {
    GRAPH_TSEQ_STEVENS,  /**< Time/sequence graph using Stevens-style dot plotting */
    GRAPH_TSEQ_TCPTRACE, /**< Time/sequence graph using tcptrace-style segment bars with SACKs */
    GRAPH_THROUGHPUT,    /**< Throughput over time graph */
    GRAPH_RTT,           /**< Round-trip time (RTT) over sequence number graph */
    GRAPH_WSCALE,        /**< Window scaling over time graph */
    GRAPH_UNDEFINED      /**< Graph type has not been set */
} tcp_graph_type;

/** @brief RTT series flag: include all ACK samples in the RTT plot. */
#define RTT_ALL  0x0001
/** @brief RTT series flag: include selective ACK (SACK) samples in the RTT plot. */
#define RTT_SAK  0x0002
/** @brief RTT series flag: include standard RTT samples in the RTT plot. */
#define RTT_RTT  0x0004
/** @brief RTT series flag: apply Karn's algorithm to filter ambiguous retransmit samples. */
#define RTT_KRN  0x0008

/**
 * @brief Selects which ACK events are used as RTT sample points in the RTT graph.
 */
typedef enum rtt_sampling_method_ {
    SAMPLING_ALL,       /**< Sample RTT from every ACK */
    SAMPLING_ALL_SACK,  /**< Sample RTT from every ACK including selective ACKs */
    SAMPLING_RTT,       /**< Sample RTT from standard (non-retransmit) ACKs only */
    SAMPLING_KARN,      /**< Sample RTT using Karn's algorithm to exclude ambiguous retransmit ACKs */
    SAMPLING_UNDEFINED  /**< Sampling method has not been set */
} rtt_sampling_method;

/**
 * @brief Represents a single decoded TCP segment extracted from a captured frame for graph analysis.
 */
struct segment {
    struct segment *next;       /**< Pointer to the next segment in the singly-linked list */
    uint32_t        num;        /**< Wireshark frame number of the packet containing this segment */
    nstime_t        rel_ts;     /**< Capture timestamp relative to the first packet in the stream */

    uint32_t th_seq;            /**< Relative TCP sequence number (after base sequence subtraction) */
    uint32_t th_ack;            /**< Relative TCP acknowledgement number (after base sequence subtraction) */
    uint32_t th_rawseq;         /**< Raw (absolute) TCP sequence number as seen in the packet */
    uint32_t th_rawack;         /**< Raw (absolute) TCP acknowledgement number as seen in the packet */
    uint16_t th_flags;          /**< TCP header flags (SYN, ACK, FIN, RST, etc.) */
    uint32_t th_win;            /**< TCP receive window size in bytes (32-bit to accommodate window scaling) */
    uint32_t th_seglen;         /**< Length of the TCP payload data in bytes */
    uint16_t th_sport;          /**< TCP source port */
    uint16_t th_dport;          /**< TCP destination port */
    address  ip_src;            /**< Source IP address */
    address  ip_dst;            /**< Destination IP address */

    bool    ack_karn;           /**< True if this ACK is ambiguous under Karn's algorithm (i.e. acknowledges a retransmit) */

    uint8_t  num_sack_ranges;                        /**< Number of valid SACK ranges present in this segment */
    uint32_t sack_left_edge[MAX_TCP_SACK_RANGES];    /**< Left (start) sequence number of each SACK block */
    uint32_t sack_right_edge[MAX_TCP_SACK_RANGES];   /**< Right (end) sequence number of each SACK block */
};

/**
 * @brief Describes a TCP stream graph, including the stream identity, graph type, and collected segment list.
 */
struct tcp_graph {
    tcp_graph_type  type;          /**< Plot type to render for this graph (see ::tcp_graph_type) */

    uint8_t         rtt_sampling;  /**< Bitmask of RTT_* flags controlling which samples appear on RTT graphs */

    /* --- Stream identity --- */
    address  src_address; /**< Source IP address of the TCP stream being graphed */
    uint16_t src_port;    /**< Source TCP port of the stream */
    address  dst_address; /**< Destination IP address of the TCP stream being graphed */
    uint16_t dst_port;    /**< Destination TCP port of the stream */
    uint32_t stream;      /**< Wireshark TCP stream index identifying this flow */

    /* --- Segment list --- */
    struct segment *segments; /**< Head of the singly-linked list of ::segment records for this stream */
    struct segment *last;     /**< Tail pointer for O(1) append to the segment list */
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

/**
 * @brief Represents a single unacknowledged segment in the RTT tracking linked list.
 */
struct rtt_unack {
    struct rtt_unack *next;      /**< Pointer to the next unacknowledged segment in the list; NULL if this is the last entry. */
    double            time;      /**< Timestamp in seconds at which this segment was sent, used to compute RTT upon acknowledgement. */
    unsigned int      seqno;     /**< Starting sequence number of this unacknowledged segment. */
    unsigned int      end_seqno; /**< Ending sequence number (exclusive) of this unacknowledged segment. */
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
