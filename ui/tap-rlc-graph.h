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
#include <epan/cfile.h>
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

/**
 * @brief Retrieves a list of RLC segments from a capture file.
 *
 * @param cf Pointer to the capture file.
 * @param tg Pointer to the RLC graph structure.
 * @param stream_known Indicates if the stream is already known.
 * @param err_string Pointer to an error string (if any).
 * @return true if successful, false otherwise.
 */
bool rlc_graph_segment_list_get(capture_file *cf, struct rlc_graph *tg, bool stream_known,
                                    char **err_string);

/**
 * @brief Frees the list of RLC segments in the given RLC graph.
 * @param g Pointer to the RLC graph structure whose segments are to be freed.
 */
void rlc_graph_segment_list_free(struct rlc_graph *g);

/**
 * @brief Compares two RLC headers for equality.
 *
 * This function compares two RLC (Radio Link Control) headers based on their parameters.
 * It checks if the headers are equal, considering both data and control frames.
 *
 * @param rat1 Radio Access Technology of the first header.
 * @param rat2 Radio Access Technology of the second header.
 * @param ueid1 User Equipment ID of the first header.
 * @param channelType1 Channel type of the first header.
 * @param channelId1 Channel ID of the first header.
 * @param rlcMode1 RLC mode of the first header.
 * @param direction1 Direction of the first header (0 for uplink, 1 for downlink).
 * @param ueid2 User Equipment ID of the second header.
 * @param channelType2 Channel type of the second header.
 * @param channelId2 Channel ID of the second header.
 * @param rlcMode2 RLC mode of the second header.
 * @param direction2 Direction of the second header (0 for uplink, 1 for downlink).
 * @param isControlFrame Indicates if the frame is a control frame.
 * @return true if the headers are equal, false otherwise.
 */
bool compare_rlc_headers(uint8_t rat1, uint8_t rat2,
                             uint16_t ueid1, uint16_t channelType1, uint16_t channelId1, uint8_t rlcMode1, uint8_t direction1,
                             uint16_t ueid2, uint16_t channelType2, uint16_t channelId2, uint8_t rlcMode2, uint8_t direction2,
                             bool isControlFrame);

/**
 * @brief Selects an RLC LTE session from a capture file.
 *
 * This function selects an RLC LTE session based on the current frame in the capture file and filters for RLC-LTE or RLC-NR packets.
 *
 * @param cf The capture file containing the data.
 * @param hdrs The RLC segment headers.
 * @param err_msg A pointer to a string that will hold any error message if an error occurs.
 * @return An rlc_3gpp_tap_info structure representing the selected RLC LTE session, or NULL if no valid session is found.
 */
rlc_3gpp_tap_info *select_rlc_lte_session(capture_file *cf, struct rlc_segment *hdrs,
                                         char **err_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
