/* tap-rlc-stream.h
 * LTE RLC stream statistics
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

#ifndef __TAP_RLC_GRAPH_H__
#define __TAP_RLC_GRAPH_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/epan.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <cfile.h>
#include <epan/dissectors/packet-rlc-lte.h>

struct rlc_segment {
    struct rlc_segment *next;
    guint32 num;            /* framenum */
    guint32 rel_secs;
    guint32 rel_usecs;
    guint32 abs_secs;
    guint32 abs_usecs;

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

    /* Lists of elements to draw. N.B. GTK version only. */
    struct element_list *elists;
};

gboolean rlc_graph_segment_list_get(capture_file *cf, struct rlc_graph *tg, gboolean stream_known,
                                    char **err_string);
void rlc_graph_segment_list_free(struct rlc_graph * );



int compare_rlc_headers(guint16 ueid1, guint16 channelType1, guint16 channelId1, guint8 rlcMode1, guint8 direction1,
                        guint16 ueid2, guint16 channelType2, guint16 channelId2, guint8 rlcMode2, guint8 direction2,
                        gboolean isControlFrame);
rlc_lte_tap_info *select_rlc_lte_session(capture_file *cf, struct rlc_segment *hdrs,
                                         gchar **err_msg);
int rlc_lte_tap_for_graph_data(void *pct, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
