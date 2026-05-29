/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WTAP_PCAPNG_NETFLIX_CUSTOM_H
#define WTAP_PCAPNG_NETFLIX_CUSTOM_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Netflix custom blocks and options.
 *
 * https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
#define PEN_NFLX 10949

/*
 * Netflix BBLog custom block types.
 */
#define NFLX_BLOCK_TYPE_EVENT   1
#define NFLX_BLOCK_TYPE_SKIP    2

/**
 * @brief Mandatory payload of a Netflix-specific WTAP_BLOCK_CUSTOM block in a pcapng file.
 */
typedef struct nflx {
    uint32_t type;     /**< Netflix custom block subtype; determines how the remainder of the block is interpreted (e.g., NFLX_BLOCK_TYPE_SKIP). */
    uint32_t skipped;  /**< Number of packets skipped before this block; only valid when @ref type == NFLX_BLOCK_TYPE_SKIP. */
} wtapng_nflx_custom_mandatory_t;

#define NFLX_OPT_TYPE_VERSION    1
#define NFLX_OPT_TYPE_TCPINFO    2
#define NFLX_OPT_TYPE_DUMPINFO   4
#define NFLX_OPT_TYPE_DUMPTIME   5
#define NFLX_OPT_TYPE_STACKNAME  6

/* Flags used in tlb_eventflags */
#define NFLX_TLB_FLAG_RXBUF     0x0001 /* Includes receive buffer info */
#define NFLX_TLB_FLAG_TXBUF     0x0002 /* Includes send buffer info */
#define NFLX_TLB_FLAG_HDR       0x0004 /* Includes a TCP header */
#define NFLX_TLB_FLAG_VERBOSE   0x0008 /* Includes function/line numbers */
#define NFLX_TLB_FLAG_STACKINFO 0x0010 /* Includes stack-specific info */

/* Flags used in tlb_flags */
#define NFLX_TLB_TF_REQ_SCALE   0x00000020 /* Sent WS option */
#define NFLX_TLB_TF_RCVD_SCALE  0x00000040 /* Received WS option */

/* Values of tlb_state */
#define NFLX_TLB_TCPS_ESTABLISHED 4
#define NFLX_TLB_IS_SYNCHRONIZED(state) (state >= NFLX_TLB_TCPS_ESTABLISHED)

/*
 * DO NOT USE sizeof (struct nflx_tcpinfo) AS THE SIZE OF THE CUSTOM
 * OPTION DATA FOLLOWING THE TYPE. This structure has 64-bit integral
 * type values in it, but the sum of the sizes of the elements plus
 * internal padding is *not* a multiple of 8, so, on a platform
 * on which 64-bit integral type values are aligned on an 8-byte
 * boundary - i.e., on all 64-bit platforms on which we run,
 * probably meaning on the majority of machines on which Wireshark
 * is run these days, especially given that we don't support 32-bit
 * Windows or macOS any more - it will have 4 bytes of unnamed padding
 * at the end.
 *
 * The custom option data in capture files does *not* necessarily include
 * the unnamed padding.
 */
#define OPT_NFLX_TCPINFO_SIZE 268U

/**
 * @brief Netflix BBLog per-event TCP state snapshot recorded at each TCP stack event.
 */
struct nflx_tcpinfo {
    uint64_t tlb_tv_sec;                      /**< Event timestamp seconds component (wall clock). */
    uint64_t tlb_tv_usec;                     /**< Event timestamp microseconds component (wall clock). */
    uint32_t tlb_ticks;                       /**< TCP stack tick counter at the time of the event. */
    uint32_t tlb_sn;                          /**< Monotonically increasing sequence number for this log entry. */
    uint8_t  tlb_stackid;                     /**< Identifier of the TCP stack implementation that generated this event. */
    uint8_t  tlb_eventid;                     /**< Event type identifier indicating which TCP stack event was logged. */
    uint16_t tlb_eventflags;                  /**< Bitmask of flags providing additional context for the event. */
    int32_t  tlb_errno;                       /**< errno value at the time of the event; zero if no error. */
    uint32_t tlb_rxbuf_tls_sb_acc;            /**< RX TLS socket buffer: bytes accessible to the application. */
    uint32_t tlb_rxbuf_tls_sb_ccc;            /**< RX TLS socket buffer: claimed, committed, or in-use byte count. */
    uint32_t tlb_rxbuf_tls_sb_spare;          /**< RX TLS socket buffer: spare/reserved bytes. */
    uint32_t tlb_txbuf_tls_sb_acc;            /**< TX TLS socket buffer: bytes accessible for transmission. */
    uint32_t tlb_txbuf_tls_sb_ccc;            /**< TX TLS socket buffer: claimed, committed, or in-use byte count. */
    uint32_t tlb_txbuf_tls_sb_spare;          /**< TX TLS socket buffer: spare/reserved bytes. */
    int32_t  tlb_state;                       /**< TCP connection state (e.g., ESTABLISHED, FIN_WAIT_1) at event time. */
    uint32_t tlb_starttime;                   /**< Tick value at which this TCP connection was established. */
    uint32_t tlb_iss;                         /**< Initial Send Sequence number for this connection. */
    uint32_t tlb_flags;                       /**< TCP control flags (tcpcb t_flags) at event time. */
    uint32_t tlb_snd_una;                     /**< Oldest unacknowledged send sequence number. */
    uint32_t tlb_snd_max;                     /**< Highest sequence number ever sent on this connection. */
    uint32_t tlb_snd_cwnd;                    /**< Current congestion window size in bytes. */
    uint32_t tlb_snd_nxt;                     /**< Next send sequence number to be used. */
    uint32_t tlb_snd_recover;                 /**< Sequence number target for recovery from a retransmission event. */
    uint32_t tlb_snd_wnd;                     /**< Current send window size advertised by the peer. */
    uint32_t tlb_snd_ssthresh;                /**< Slow-start threshold in bytes. */
    uint32_t tlb_srtt;                        /**< Smoothed round-trip time estimate in TCP ticks. */
    uint32_t tlb_rttvar;                      /**< Round-trip time variance used for RTO calculation. */
    uint32_t tlb_rcv_up;                      /**< Receive urgent pointer sequence number. */
    uint32_t tlb_rcv_adv;                     /**< Highest sequence number the receiver is willing to accept. */
    uint32_t tlb_flags2;                      /**< Extended TCP control flags (tcpcb t_flags2) at event time. */
    uint32_t tlb_rcv_nxt;                     /**< Next receive sequence number expected from the peer. */
    uint32_t tlb_rcv_wnd;                     /**< Current receive window size advertised to the peer. */
    uint32_t tlb_dupacks;                     /**< Number of consecutive duplicate ACKs received. */
    int32_t  tlb_segqlen;                     /**< Number of segments currently in the out-of-order segment queue. */
    int32_t  tlb_snd_numholes;                /**< Number of holes (gaps) in the send sequence space tracked for SACK. */
    uint32_t tlb_flex1;                       /**< Event-specific auxiliary field 1; interpretation depends on tlb_eventid. */
    uint32_t tlb_flex2;                       /**< Event-specific auxiliary field 2; interpretation depends on tlb_eventid. */
    uint32_t tlb_fbyte_in;                    /**< Tick timestamp of the first byte received on this connection. */
    uint32_t tlb_fbyte_out;                   /**< Tick timestamp of the first byte sent on this connection. */
    uint8_t  tlb_snd_scale:4,                 /**< Negotiated send window scaling shift count (0–14). */
             tlb_rcv_scale:4;                 /**< Negotiated receive window scaling shift count (0–14). */
    uint8_t  _pad[3];                         /**< Explicit padding to maintain structure alignment. */

    /* The following fields might become part of a union */
    uint64_t tlb_stackinfo_bbr_cur_del_rate;  /**< BBR: current measured delivery rate in bytes per second. */
    uint64_t tlb_stackinfo_bbr_delRate;       /**< BBR: filtered peak delivery rate in bytes per second. */
    uint64_t tlb_stackinfo_bbr_rttProp;       /**< BBR: minimum RTT (propagation delay estimate) in microseconds. */
    uint64_t tlb_stackinfo_bbr_bw_inuse;      /**< BBR: bandwidth currently in use, in bytes per second. */
    uint32_t tlb_stackinfo_bbr_inflight;      /**< BBR: number of bytes currently in flight. */
    uint32_t tlb_stackinfo_bbr_applimited;    /**< BBR: non-zero if the sender is application-limited rather than network-limited. */
    uint32_t tlb_stackinfo_bbr_delivered;     /**< BBR: total bytes delivered and acknowledged so far. */
    uint32_t tlb_stackinfo_bbr_timeStamp;     /**< BBR: timestamp associated with the current BBR state snapshot. */
    uint32_t tlb_stackinfo_bbr_epoch;         /**< BBR: current BBR round-trip count epoch. */
    uint32_t tlb_stackinfo_bbr_lt_epoch;      /**< BBR: epoch at which long-term bandwidth sampling began. */
    uint32_t tlb_stackinfo_bbr_pkts_out;      /**< BBR: number of packets currently outstanding in the network. */
    uint32_t tlb_stackinfo_bbr_flex1;         /**< BBR: stack-specific auxiliary field 1. */
    uint32_t tlb_stackinfo_bbr_flex2;         /**< BBR: stack-specific auxiliary field 2. */
    uint32_t tlb_stackinfo_bbr_flex3;         /**< BBR: stack-specific auxiliary field 3. */
    uint32_t tlb_stackinfo_bbr_flex4;         /**< BBR: stack-specific auxiliary field 4. */
    uint32_t tlb_stackinfo_bbr_flex5;         /**< BBR: stack-specific auxiliary field 5. */
    uint32_t tlb_stackinfo_bbr_flex6;         /**< BBR: stack-specific auxiliary field 6. */
    uint32_t tlb_stackinfo_bbr_lost;          /**< BBR: total number of packets detected as lost. */
    uint16_t tlb_stackinfo_bbr_pacing_gain;   /**< BBR: pacing gain as a fixed-point ratio applied to the estimated bandwidth. */
    uint16_t tlb_stackinfo_bbr_cwnd_gain;     /**< BBR: congestion window gain as a fixed-point ratio. */
    uint16_t tlb_stackinfo_bbr_flex7;         /**< BBR: stack-specific auxiliary field 7. */
    uint8_t  tlb_stackinfo_bbr_bbr_state;     /**< BBR: current high-level BBR state machine state. */
    uint8_t  tlb_stackinfo_bbr_bbr_substate;  /**< BBR: current sub-state within the active BBR state. */
    uint8_t  tlb_stackinfo_bbr_inhpts;        /**< BBR: non-zero if the connection is currently in the hpts (pacing timer) system. */
    uint8_t  tlb_stackinfo_bbr_ininput;       /**< BBR: non-zero if the event was triggered from within the input path. */
    uint8_t  tlb_stackinfo_bbr_use_lt_bw;     /**< BBR: non-zero if long-term bandwidth estimation is active. */
    uint8_t  tlb_stackinfo_bbr_flex8;         /**< BBR: stack-specific auxiliary field 8. */
    uint32_t tlb_stackinfo_bbr_pkt_epoch;     /**< BBR: packet-level epoch counter used for delivery rate sampling. */

    uint32_t tlb_len;                         /**< Length in bytes of the TCP segment associated with this event. */
};

/*
 * This is 208 bytes long, and that's a multiple of 8, so the padding
 * problem that struct nflx_tcpinfo has doesn't appear here.
 */

/**
 * @brief Netflix BBLog dump info block describing the identity and context of a TCP connection log stream.
 */
struct nflx_dumpinfo {
    uint32_t tlh_version;               /**< Version of the BBLog dump format used in this stream. */
    uint32_t tlh_type;                  /**< Log stream type identifier. */
    uint64_t tlh_length;                /**< Total length in bytes of the log data following this header. */
    uint16_t tlh_ie_fport;              /**< Foreign (remote) TCP port of the logged connection. */
    uint16_t tlh_ie_lport;              /**< Local TCP port of the logged connection. */
    uint32_t tlh_ie_faddr_addr32[4];    /**< Foreign (remote) IP address; supports both IPv4 (first element) and IPv6 (all four elements). */
    uint32_t tlh_ie_laddr_addr32[4];    /**< Local IP address; supports both IPv4 (first element) and IPv6 (all four elements). */
    uint32_t tlh_ie_zoneid;             /**< Jail or network zone identifier of the connection. */
    uint64_t tlh_offset_tv_sec;         /**< Seconds component of the reference time offset for timestamps in this stream. */
    uint64_t tlh_offset_tv_usec;        /**< Microseconds component of the reference time offset for timestamps in this stream. */
    char     tlh_id[64];                /**< Null-terminated string uniquely identifying this log stream. */
    char     tlh_reason[32];            /**< Null-terminated string describing why this log was captured. */
    char     tlh_tag[32];               /**< Null-terminated user-supplied tag string for this log stream. */
    uint8_t  tlh_af;                    /**< Address family of the connection (e.g., AF_INET or AF_INET6). */
    uint8_t  _pad[7];                   /**< Explicit padding to maintain 8-byte alignment; value is undefined. */
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_PCAPNG_NETFLIX_CUSTOM_H */
