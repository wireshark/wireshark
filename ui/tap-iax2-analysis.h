/** @file
 *
 * IAX2 analysis addition for Wireshark
 *
 * based on rtp_analysis.c
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

#ifndef __TAP_IAX2_ANALYSIS_H__
#define __TAP_IAX2_ANALYSIS_H__

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
 * @brief Records a single bandwidth history sample for an IAX2 stream at a point in time.
 */
typedef struct _iax2_bw_history_item {
    double   time;  /**< Timestamp in seconds at which this bandwidth sample was recorded. */
    uint32_t bytes; /**< Number of bytes observed in this bandwidth sample interval. */
} iax2_bw_history_item;


#define BUFF_BW 300 /**< Number of bandwidth history entries retained in the rolling history buffer. */


/**
 * @brief Accumulates per-packet statistics for an IAX2 stream delivered via the tap interface.
 */
typedef struct _tap_iax2_stat_t {
    bool     first_packet;                    /**< True if this is the first packet seen; do not use after iax2_packet_analyse() — check (flags & STAT_FLAG_FIRST) instead. */
    /* All fields below are valid only after iax2_packet_analyse() has been called. */
    uint32_t flags;                           /**< Bitmask of STAT_FLAG_* values describing the state of this packet. */
    uint16_t seq_num;                         /**< RTP-compatible sequence number of this IAX2 packet. */
    uint32_t timestamp;                       /**< IAX2 timestamp of this packet in milliseconds. */
    uint32_t delta_timestamp;                 /**< Difference in IAX2 timestamp from the previous packet in milliseconds. */
    double   bandwidth;                       /**< Current estimated stream bandwidth in bytes per second. */
    iax2_bw_history_item bw_history[BUFF_BW]; /**< Rolling circular buffer of recent bandwidth history samples. */
    uint16_t bw_start_index;                  /**< Index into @p bw_history marking the start of the valid history window. */
    uint16_t bw_index;                        /**< Index into @p bw_history at which the next sample will be written. */
    uint32_t total_bytes;                     /**< Cumulative total bytes received for this stream. */
    double   delta;                           /**< Arrival time delta from the previous packet in seconds. */
    double   jitter;                          /**< Instantaneous jitter estimate for this packet in seconds. */
    double   diff;                            /**< Difference between expected and actual arrival time in seconds. */
    double   time;                            /**< Absolute arrival time of this packet in seconds. */
    double   start_time;                      /**< Absolute arrival time of the first packet in this stream in seconds. */
    double   max_delta;                       /**< Maximum inter-arrival delta observed over the lifetime of this stream in seconds. */
    double   max_jitter;                      /**< Maximum instantaneous jitter observed over the lifetime of this stream in seconds. */
    double   mean_jitter;                     /**< Running mean jitter over the lifetime of this stream in seconds. */
    uint32_t max_nr;                          /**< Frame number of the packet at which the maximum delta was observed. */
    uint16_t start_seq_nr;                    /**< Sequence number of the first packet in this stream. */
    uint16_t stop_seq_nr;                     /**< Sequence number of the most recent packet in this stream. */
    uint32_t total_nr;                        /**< Total number of packets received for this stream. */
    uint32_t sequence;                        /**< Running sequence counter used for internal ordering. */
    bool     under;                           /**< Underflow flag (currently unused). */
    int      cycles;                          /**< Sequence number cycle counter (currently unused). */
    uint16_t pt;                              /**< Payload type of the most recent packet. */
    int      reg_pt;                          /**< Registered payload type for this stream. */
} tap_iax2_stat_t;

#define PT_UNDEFINED -1

/* status flags for the flags parameter in tap_iax2_stat_t */
#define STAT_FLAG_FIRST				0x001
#define STAT_FLAG_MARKER			0x002
#define STAT_FLAG_WRONG_SEQ			0x004
#define STAT_FLAG_PT_CHANGE			0x008
#define STAT_FLAG_PT_CN				0x010
#define STAT_FLAG_FOLLOW_PT_CN		0x020
#define STAT_FLAG_REG_PT_CHANGE		0x040
#define STAT_FLAG_WRONG_TIMESTAMP	0x080

/* function for analysing an IAX2 packet. Called from iax2_analysis. */

/**
 * @brief Analyzes an IAX2 packet and updates statistics.
 *
 * This function analyzes an incoming IAX2 packet, updating various statistics
 * such as payload type changes, time differences, jitter, and delta times.
 *
 * @param statinfo Pointer to the statistics structure to be updated.
 * @param pinfo Pointer to the packet information structure.
 * @param iax2info Pointer to the IAX2-specific information structure.
 */
extern void iax2_packet_analyse(tap_iax2_stat_t *statinfo,
        packet_info *pinfo,
        const struct _iax2_info_t *iax2info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_IAX2_ANALYSIS_H__ */
