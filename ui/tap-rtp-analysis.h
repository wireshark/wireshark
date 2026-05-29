/** @file
 *
 * RTP analysis addition for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * based on tap_rtp.c
 * Copyright 2003, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_RTP_ANALYSIS_H__
#define __TAP_RTP_ANALYSIS_H__

#include <epan/address.h>
#include <epan/packet_info.h>

/** @file
 *  ???
 *  @todo what's this?
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************/
/**
 * @brief Records a single bandwidth history sample for an RTP stream at a point in time.
 */
typedef struct _bw_history_item {
    double   time;  /**< Timestamp in seconds at which this bandwidth sample was recorded. */
    uint32_t bytes; /**< Number of bytes observed in this bandwidth sample interval. */
} bw_history_item;


#define BUFF_BW 300 /**< Number of bandwidth history entries retained in the rolling history buffer. */


/**
 * @brief Accumulates per-packet statistics for an RTP stream delivered via the tap interface.
 */
typedef struct _tap_rtp_stat_t {
    bool            first_packet;             /**< True if this is the first packet seen; do not use after rtppacket_analyse() — check (flags & STAT_FLAG_FIRST) instead. */
    /* All fields below are valid only after rtppacket_analyse() has been called. */
    uint32_t        flags;                    /**< Bitmask of STAT_FLAG_* values describing the state of this packet. */
    uint16_t        seq_num;                  /**< RTP sequence number of this packet. */
    uint64_t        timestamp;                /**< Generated extended RTP timestamp, unwrapped to 64 bits to handle rollover. */
    uint64_t        seq_timestamp;            /**< Extended RTP timestamp of the last in-sequence packet. */
    double          bandwidth;                /**< Current estimated stream bandwidth in bytes per second. */
    bw_history_item bw_history[BUFF_BW];      /**< Rolling circular buffer of recent bandwidth history samples. */
    uint16_t        bw_start_index;           /**< Index into @p bw_history marking the start of the valid history window. */
    uint16_t        bw_index;                 /**< Index into @p bw_history at which the next sample will be written. */
    uint32_t        total_bytes;              /**< Cumulative total bytes received for this stream. */
    uint32_t        clock_rate;               /**< RTP clock rate in Hz used to convert timestamps to wall-clock time. */
    double          delta;                    /**< Arrival time delta from the previous packet in seconds. */
    double          jitter;                   /**< Instantaneous jitter estimate per RFC 3550 in seconds. */
    double          diff;                     /**< Difference between expected and actual arrival time in seconds. */
    double          skew;                     /**< Cumulative clock skew between sender and receiver in seconds. */
    double          sumt;                     /**< Running sum of arrival times; used for linear regression of clock skew. */
    double          sumTS;                    /**< Running sum of RTP timestamps; used for linear regression of clock skew. */
    double          sumt2;                    /**< Running sum of squared arrival times; used for linear regression of clock skew. */
    double          sumtTS;                   /**< Running sum of arrival time × RTP timestamp products; used for linear regression of clock skew. */
    double          time;                     /**< Absolute arrival time of this packet in milliseconds. */
    double          start_time;               /**< Absolute arrival time of the first packet in this stream in milliseconds. */
    double          lastnominaltime;          /**< Nominal (expected) arrival time of the previous packet in milliseconds. */
    double          lastarrivaltime;          /**< Actual arrival time of the previous packet in milliseconds. */
    double          min_delta;                /**< Minimum inter-arrival delta observed over the lifetime of this stream in seconds. */
    double          max_delta;                /**< Maximum inter-arrival delta observed over the lifetime of this stream in seconds. */
    double          mean_delta;               /**< Running mean inter-arrival delta over the lifetime of this stream in seconds. */
    double          min_jitter;               /**< Minimum instantaneous jitter observed over the lifetime of this stream in seconds. */
    double          max_jitter;               /**< Maximum instantaneous jitter observed over the lifetime of this stream in seconds. */
    double          max_skew;                 /**< Maximum cumulative clock skew observed over the lifetime of this stream in seconds. */
    double          mean_jitter;              /**< Running mean jitter over the lifetime of this stream in seconds. */
    uint32_t        max_nr;                   /**< Frame number of the packet with the largest RTP timestamp seen so far. */
    uint32_t        start_seq_nr;             /**< Extended base sequence number per RFC 3550 §A.1. */
    uint32_t        stop_seq_nr;              /**< Extended maximum sequence number seen per RFC 3550 §A.1. */
    uint32_t        total_nr;                 /**< Total number of RTP packets received for this stream. */
    uint32_t        sequence;                 /**< Cumulative count of sequence number errors detected in this stream. */
    uint16_t        pt;                       /**< Payload type of the most recent packet. */
    int             reg_pt;                   /**< Registered payload type for this stream. */
    uint32_t        first_packet_num;         /**< Frame number of the first packet in this stream. */
    unsigned        last_payload_len;         /**< Payload length in bytes of the most recently processed packet. */
} tap_rtp_stat_t;

/**
 * @brief Holds the minimal per-packet data needed when saving an RTP stream's payload to file.
 */
typedef struct _tap_rtp_save_data_t {
    uint32_t     timestamp;    /**< RTP timestamp of the packet, used for reordering and timing during save. */
    unsigned int payload_type; /**< RTP payload type identifying the codec or format of the payload. */
    size_t       payload_len;  /**< Length in bytes of the RTP payload to be saved. */
} tap_rtp_save_data_t;

#define PT_UNDEFINED -1

/* status flags for the flags parameter in tap_rtp_stat_t */
#define STAT_FLAG_FIRST             0x001
#define STAT_FLAG_MARKER            0x002
#define STAT_FLAG_WRONG_SEQ         0x004
#define STAT_FLAG_PT_CHANGE         0x008
#define STAT_FLAG_PT_CN             0x010
#define STAT_FLAG_FOLLOW_PT_CN      0x020
#define STAT_FLAG_REG_PT_CHANGE     0x040
#define STAT_FLAG_WRONG_TIMESTAMP   0x080
#define STAT_FLAG_PT_T_EVENT        0x100
#define STAT_FLAG_DUP_PKT           0x200

/* forward */
struct _rtp_info;

/* function for analysing an RTP packet. Called from rtp_analysis and rtp_streams */

/**
 * @brief Analyzes an RTP packet and updates statistics.
 *
 * @param statinfo Pointer to the RTP statistics structure.
 * @param pinfo Pointer to the packet information structure.
 * @param rtpinfo Pointer to the RTP information structure.
 */
extern void rtppacket_analyse(tap_rtp_stat_t *statinfo,
                              const packet_info *pinfo,
                              const struct _rtp_info *rtpinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_RTP_ANALYSIS_H__ */
