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

/**
 * @brief Represents a single RLC PDU or control segment captured from the air interface.
 */
struct rlc_segment {
    struct rlc_segment *next;                /**< Pointer to the next segment in the singly-linked list. */
    uint32_t        num;                     /**< Wireshark frame number of the packet containing this segment. */
    nstime_t        rel_ts;                  /**< Timestamp of the segment relative to the start of the capture. */

    bool            isControlPDU;            /**< True if this segment is a control PDU (STATUS); false for data PDUs. */
    uint32_t        SN;                      /**< RLC Sequence Number of this data PDU. */
    uint16_t        isResegmented;           /**< Non-zero if this PDU is a resegmented AMD PDU. */
    uint32_t        ACKNo;                   /**< Acknowledgement sequence number carried in a STATUS PDU. */
    uint16_t        noOfNACKs;               /**< Number of NACK entries present in a STATUS PDU. */
    uint32_t        NACKs[MAX_NACKs];        /**< Array of sequence numbers negatively acknowledged in a STATUS PDU. */
    uint16_t        pduLength;               /**< Length of the PDU in bytes. */

    uint8_t         rat;                     /**< Radio Access Technology (e.g., LTE, NR). */
    uint16_t        ueid;                    /**< UE identifier that this segment belongs to. */
    uint16_t        channelType;             /**< Logical channel type (e.g., DCCH, DTCH). */
    uint16_t        channelId;               /**< Logical channel ID within the UE. */
    uint8_t         rlcMode;                 /**< RLC mode: TM, UM, or AM. */
    uint8_t         direction;               /**< Transmission direction: uplink or downlink. */
    uint16_t        sequenceNumberLength;    /**< Configured sequence number field length in bits. */
};

/**
 * @brief Accumulates all RLC channel headers found within a single captured frame.
 */
typedef struct _th_t {
    int num_hdrs;                                        /**< Number of valid entries in @ref rlchdrs. */
    #define MAX_SUPPORTED_CHANNELS 8
    rlc_3gpp_tap_info *rlchdrs[MAX_SUPPORTED_CHANNELS]; /**< Array of tap info pointers, one per distinct RLC channel in the frame. */
} th_t;

/**
 * @brief Holds all state required to render an RLC sequence-number graph for one channel.
 */
struct rlc_graph {
    struct rlc_segment *segments;      /**< Head of the linked list of segments to be plotted. */
    struct rlc_segment *last_segment;  /**< Tail of the linked list, used for O(1) appends. */

    bool            channelSet;        /**< True if the channel identity fields below have been populated. */

    uint8_t         rat;               /**< Radio Access Technology of the graphed channel. */
    uint16_t        ueid;              /**< UE identifier of the graphed channel. */
    uint16_t        channelType;       /**< Logical channel type of the graphed channel. */
    uint16_t        channelId;         /**< Logical channel ID of the graphed channel. */
    uint8_t         rlcMode;           /**< RLC mode of the graphed channel. */
    uint8_t         direction;         /**< Direction (uplink or downlink) of the graphed channel. */
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
