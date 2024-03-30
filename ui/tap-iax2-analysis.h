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
/* structure that holds the information about the forward and reversed direction */
typedef struct _iax2_bw_history_item {
    double time;
    uint32_t bytes;
} iax2_bw_history_item;

#define BUFF_BW 300

typedef struct _tap_iax2_stat_t {
    bool first_packet;     /* do not use in code that is called after iax2_packet_analyse */
    /* use (flags & STAT_FLAG_FIRST) instead */
    /* all of the following fields will be initialized after
       iax2_packet_analyse has been called */
    uint32_t flags;             /* see STAT_FLAG-defines below */
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t delta_timestamp;
    double bandwidth;
    iax2_bw_history_item bw_history[BUFF_BW];
    uint16_t bw_start_index;
    uint16_t bw_index;
    uint32_t total_bytes;
    double delta;
    double jitter;
    double diff;
    double time;
    double start_time;
    double max_delta;
    double max_jitter;
    double mean_jitter;
    uint32_t max_nr;
    uint16_t start_seq_nr;
    uint16_t stop_seq_nr;
    uint32_t total_nr;
    uint32_t sequence;
    bool under; /* Unused? */
    int cycles; /* Unused? */
    uint16_t pt;
    int reg_pt;
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
extern void iax2_packet_analyse(tap_iax2_stat_t *statinfo,
        packet_info *pinfo,
        const struct _iax2_info_t *iax2info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_IAX2_ANALYSIS_H__ */
