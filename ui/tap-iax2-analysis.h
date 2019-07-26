/* tap-iax2-analysis.h
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
    guint32 bytes;
} iax2_bw_history_item;

#define BUFF_BW 300

typedef struct _tap_iax2_stat_t {
    gboolean first_packet;     /* do not use in code that is called after iax2_packet_analyse */
    /* use (flags & STAT_FLAG_FIRST) instead */
    /* all of the following fields will be initialized after
       iax2_packet_analyse has been called */
    guint32 flags;             /* see STAT_FLAG-defines below */
    guint16 seq_num;
    guint32 timestamp;
    guint32 delta_timestamp;
    double bandwidth;
    iax2_bw_history_item bw_history[BUFF_BW];
    guint16 bw_start_index;
    guint16 bw_index;
    guint32 total_bytes;
    double delta;
    double jitter;
    double diff;
    double time;
    double start_time;
    double max_delta;
    double max_jitter;
    double mean_jitter;
    guint32 max_nr;
    guint16 start_seq_nr;
    guint16 stop_seq_nr;
    guint32 total_nr;
    guint32 sequence;
    gboolean under; /* Unused? */
    gint cycles; /* Unused? */
    guint16 pt;
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

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
