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
/* structure that holds the information about the forward and reversed direction */
typedef struct _bw_history_item {
    double time;
    uint32_t bytes;
} bw_history_item;

#define BUFF_BW 300

typedef struct _tap_rtp_stat_t {
    bool            first_packet; /**< do not use in code that is called after rtppacket_analyse */
                               /* use (flags & STAT_FLAG_FIRST) instead */
    /* all of the following fields will be initialized after
     * rtppacket_analyse has been called
     */
    uint32_t        flags;      /* see STAT_FLAG-defines below */
    uint16_t        seq_num;
    uint64_t        timestamp;     /* The generated "extended" timestamp */
    uint64_t        seq_timestamp; /* The last in-sequence extended timestamp */
    double          bandwidth;
    bw_history_item bw_history[BUFF_BW];
    uint16_t        bw_start_index;
    uint16_t        bw_index;
    uint32_t        total_bytes;
    uint32_t        clock_rate;
    double          delta;
    double          jitter;
    double          diff;
    double          skew;
    double          sumt;
    double          sumTS;
    double          sumt2;
    double          sumtTS;
    double          time;       /**< Unit is ms */
    double          start_time; /**< Unit is ms */
    double          lastnominaltime;
    double          lastarrivaltime;
    double          min_delta;
    double          max_delta;
    double          mean_delta;
    double          min_jitter;
    double          max_jitter;
    double          max_skew;
    double          mean_jitter;
    uint32_t        max_nr; /**< The frame number of the last packet by timestamp */
    uint32_t        start_seq_nr; /**< (extended) base_seq per RFC 3550 A.1 */
    uint32_t        stop_seq_nr; /**< (extended) max_seq per RFC 3550 A.1 */
    uint32_t        total_nr; /**< total number of received packets */
    uint32_t        sequence; /**< total number of sequence errors */
    uint16_t        pt;
    int             reg_pt;
    uint32_t        first_packet_num;
    unsigned        last_payload_len;
} tap_rtp_stat_t;

typedef struct _tap_rtp_save_data_t {
    uint32_t timestamp;
    unsigned int payload_type;
    size_t payload_len;
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
extern void rtppacket_analyse(tap_rtp_stat_t *statinfo,
                              const packet_info *pinfo,
                              const struct _rtp_info *rtpinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_RTP_ANALYSIS_H__ */
