/** @file
 *
 * LTE RLC stream statistics
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_RLC_GRAPH_H__
#define __TAP_RLC_GRAPH_H__

#include <epan/epan.h>
#include <epan/packet.h>
#include <cfile.h>
#include <epan/dissectors/packet-rlc-lte.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct rlc_segment {
    struct rlc_segment *next;
    guint32         num;            /* framenum */
    time_t          rel_secs;
    guint32         rel_usecs;

    gboolean        isControlPDU;
    guint16         SN;
    guint16         isResegmented;
    guint16         ACKNo;
    #define MAX_NACKs 128
    guint16         noOfNACKs;
    guint16         NACKs[MAX_NACKs];
    guint16         pduLength;

    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint8          rlcMode;
    guint8          direction;
};

/* A collection of channels that may be found in one frame.  Used when working out
   which channel(s) are present in a frame. */
typedef struct _th_t {
    int num_hdrs;
    #define MAX_SUPPORTED_CHANNELS 8
    rlc_lte_tap_info *rlchdrs[MAX_SUPPORTED_CHANNELS];
} th_t;

struct rlc_graph {
    /* List of segments to show */
    struct rlc_segment *segments;
    struct rlc_segment *last_segment;

    /* These are filled in with the channel/direction this graph is showing */
    gboolean        channelSet;
    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint8          rlcMode;
    guint8          direction;
};

gboolean rlc_graph_segment_list_get(capture_file *cf, struct rlc_graph *tg, gboolean stream_known,
                                    char **err_string);
void rlc_graph_segment_list_free(struct rlc_graph * );



gboolean compare_rlc_headers(guint16 ueid1, guint16 channelType1, guint16 channelId1, guint8 rlcMode1, guint8 direction1,
                            guint16 ueid2, guint16 channelType2, guint16 channelId2, guint8 rlcMode2, guint8 direction2,
                            gboolean isControlFrame);
rlc_lte_tap_info *select_rlc_lte_session(capture_file *cf, struct rlc_segment *hdrs,
                                         gchar **err_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
