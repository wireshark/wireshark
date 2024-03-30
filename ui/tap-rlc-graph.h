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
#include <epan/dissectors/packet-rlc-3gpp-common.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct rlc_segment {
    struct rlc_segment *next;
    uint32_t        num;            /* framenum */
    time_t          rel_secs;
    uint32_t        rel_usecs;

    bool            isControlPDU;
    uint32_t        SN;
    uint16_t        isResegmented;
    uint32_t        ACKNo;
    uint16_t        noOfNACKs;
    uint32_t        NACKs[MAX_NACKs];
    uint16_t        pduLength;

    uint8_t         rat;
    uint16_t        ueid;
    uint16_t        channelType;
    uint16_t        channelId;
    uint8_t         rlcMode;
    uint8_t         direction;
    uint16_t        sequenceNumberLength;
};

/* A collection of channels that may be found in one frame.  Used when working out
   which channel(s) are present in a frame. */
typedef struct _th_t {
    int num_hdrs;
    #define MAX_SUPPORTED_CHANNELS 8
    rlc_3gpp_tap_info *rlchdrs[MAX_SUPPORTED_CHANNELS];
} th_t;

struct rlc_graph {
    /* List of segments to show */
    struct rlc_segment *segments;
    struct rlc_segment *last_segment;

    /* These are filled in with the channel/direction this graph is showing */
    bool            channelSet;

    uint8_t         rat;
    uint16_t        ueid;
    uint16_t        channelType;
    uint16_t        channelId;
    uint8_t         rlcMode;
    uint8_t         direction;
};

bool rlc_graph_segment_list_get(capture_file *cf, struct rlc_graph *tg, bool stream_known,
                                    char **err_string);
void rlc_graph_segment_list_free(struct rlc_graph * );



bool compare_rlc_headers(uint8_t rat1, uint8_t rat2,
                             uint16_t ueid1, uint16_t channelType1, uint16_t channelId1, uint8_t rlcMode1, uint8_t direction1,
                             uint16_t ueid2, uint16_t channelType2, uint16_t channelId2, uint8_t rlcMode2, uint8_t direction2,
                             bool isControlFrame);
rlc_3gpp_tap_info *select_rlc_lte_session(capture_file *cf, struct rlc_segment *hdrs,
                                         char **err_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
