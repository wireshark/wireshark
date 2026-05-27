/** @file
 *
 * RTP streams summary addition for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RTP_STREAM_H__
#define __RTP_STREAM_H__

#include <glib.h>

#include "tap-rtp-analysis.h"
#include <stdio.h>

#include <epan/cfile.h>

#include <epan/address.h>
#include <epan/tap.h>

#include "ui/rtp_stream_id.h"

/** @file
 *  "RTP Streams" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Holds all state and statistics accumulated for a single RTP stream.
 */
typedef struct _rtpstream_info {
    rtpstream_id_t id; /**< Network 5-tuple and SSRC that uniquely identify this stream */

    /* --- Payload type tracking --- */
    uint8_t     first_payload_type;          /**< Numeric RTP payload type of the first observed packet */
    const char *first_payload_type_name;     /**< Human-readable codec name for @p first_payload_type */
    const char *payload_type_names[256];     /**< Codec name for each payload type byte value seen in this stream; populated during ::TAP_ANALYSE only */
    char       *all_payload_type_names;      /**< Comma-separated string of all codec names observed across the stream's lifetime */

    /* --- Stream status --- */
    bool     is_srtp;      /**< True if the stream is SRTP (encrypted RTP) */
    uint32_t packet_count; /**< Total number of RTP packets observed in this stream */
    bool     end_stream;   /**< True when the stream has ended; used to track continuity across payload type changes */
    int      rtp_event;    /**< RTP event code if this stream carries RFC 2833 telephone events; -1 if not an event stream */

    /* --- Call association --- */
    int      call_num;           /**< Call number matching the parent ::voip_calls_info_t entry; used to correlate streams with VoIP calls */
    uint32_t setup_frame_number; /**< Frame number of the signalling message (e.g. SDP) that set up this stream */

    /* --- Timing extents --- */
    frame_data *start_fd;       /**< Pointer to the ::frame_data of the first packet in the stream */
    frame_data *stop_fd;        /**< Pointer to the ::frame_data of the last packet in the stream */
    nstime_t    start_rel_time; /**< Relative capture timestamp of the first packet */
    nstime_t    stop_rel_time;  /**< Relative capture timestamp of the last packet */
    nstime_t    start_abs_time; /**< Absolute wall-clock timestamp of the first packet */

    /* --- VLAN and QoS tagging --- */
    uint16_t vlan_id;            /**< VLAN identifier associated with this stream; 0 if untagged */
    bool     tag_vlan_error;     /**< True if an inconsistent or unexpected VLAN tag was detected */
    bool     tag_diffserv_error; /**< True if an inconsistent or unexpected DSCP/DiffServ marking was detected */

    /* --- Statistics and diagnostics --- */
    tap_rtp_stat_t rtp_stats;  /**< Detailed RTP quality statistics (jitter, loss, etc.) accumulated by the tap */
    bool           problem;    /**< True if sequence number or timestamp anomalies were detected in this stream */
    const char    *ed137_info; /**< Pointer to a static string describing ED-137 radio metadata; no freeing required */
} rtpstream_info_t;

/**
 * @brief Selects the operation performed by the RTP stream tap on the collected stream data.
 */
typedef enum
{
    TAP_ANALYSE, /**< Analyse all streams and populate statistics */
    TAP_SAVE,    /**< Save the payload audio data of a stream to a file */
    TAP_MARK     /**< Mark all frames belonging to selected streams in the packet list */
} tap_mode_t;

typedef struct _rtpstream_tapinfo rtpstream_tapinfo_t;

typedef void (*rtpstream_tap_reset_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*rtpstream_tap_draw_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*tap_mark_packet_cb)(rtpstream_tapinfo_t *tapinfo, frame_data *fd);
typedef void (*rtpstream_tap_error_cb)(GString *error_string);

/* structure that holds the information about all detected streams */
/** struct holding all information of the tap */
struct _rtpstream_tapinfo {
    rtpstream_tap_reset_cb tap_reset;       /**< tap reset callback */
    rtpstream_tap_draw_cb tap_draw;         /**< tap draw callback */
    tap_mark_packet_cb tap_mark_packet;     /**< packet marking callback */
    void              *tap_data;            /**< data for tap callbacks */
    int                nstreams; /**< number of streams in the list */
    GList             *strinfo_list; /**< list of rtpstream_info_t* */
    GHashTable        *strinfo_hash; /**< multihash of rtpstream_info_t **/
                                     /*   multihash means that there can be */
                                     /*   more values related to one hash key */
    int                npackets; /**< total number of rtp packets of all streams */
    /* used while tapping. user shouldn't modify these */
    tap_mode_t         mode;
    rtpstream_info_t  *filter_stream_fwd; /**< used as filter in some tap modes */
    rtpstream_info_t  *filter_stream_rev; /**< used as filter in some tap modes */
    FILE              *save_file;
    bool               is_registered; /**< if the tap listener is currently registered or not */
    bool               apply_display_filter; /**< if apply display filter during analyse */
};

#if 0
#define RTP_STREAM_DEBUG(...) { \
    char *RTP_STREAM_DEBUG_MSG = ws_strdup_printf(__VA_ARGS__); \
    ws_warning("rtp_stream: %s:%d %s", G_STRFUNC, __LINE__, RTP_STREAM_DEBUG_MSG); \
    g_free(RTP_STREAM_DEBUG_MSG); \
}
#else
#define RTP_STREAM_DEBUG(...)
#endif

/****************************************************************************/
/* INTERFACE */

/**
 * @brief Shows an error message when tap registration fails
 * @param error_string The error message to display
 */
void show_tap_registration_error(GString *error_string);

/**
* @brief Scans all packets for RTP streams and updates the RTP streams list.
* (redissects all packets)
* @param tapinfo The rtp stream tap state structure to populate.
* @param cap_file The capture file to scan for RTP streams.
* @param fstring A filter string to apply when scanning for RTP streams (empty = no filter).
*/
void rtpstream_scan(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, const char *fstring);

/**
* @brief Saves an RTP stream as raw data stream with timestamp information for later RTP playback.
* (redissects all packets)
* @param tapinfo The rtp stream tap state structure containing the stream to save.
* @param cap_file The capture file to scan for the RTP stream.
* @param stream The RTP stream to save.
* @param filename The name of the file to save the RTP stream to.
* @return true on success, false on failure.
*/
bool rtpstream_save(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream, const char *filename);

/**
* @brief Marks all packets belonging to either of stream_fwd or stream_rev.
* (both can be NULL)
* (redissects all packets)
* @param tapinfo The rtp stream tap state structure containing the streams to mark.
* @param cap_file The capture file to scan for the RTP streams.
* @param stream_fwd The RTP stream in the forward direction to mark (NULL = ignore).
* @param stream_rev The RTP stream in the reverse direction to mark (NULL = ignore).
*/
void rtpstream_mark(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream_fwd, rtpstream_info_t* stream_rev);

/**
* @brief Sets whether only packets that pass the current main display filter should
* be scanned for RTP streams.
* @param tapinfo The rtp stream tap state structure containing the streams to mark.
* @param apply Whether to apply the display filter.
*/
void rtpstream_set_apply_display_filter(rtpstream_tapinfo_t *tapinfo, bool apply);

/**
 * @brief Constant based on fix for bug 4119/5902: don't insert too many silence
 * frames.
 */
#define MAX_SILENCE_FRAMES 14400000

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_H__ */
