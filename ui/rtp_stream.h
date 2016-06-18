/* rtp_stream.h
 * RTP streams summary addition for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __RTP_STREAM_H__
#define __RTP_STREAM_H__

/** @file
 *  "RTP Streams" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "tap-rtp-analysis.h"
#include <glib.h>
#include <stdio.h>

#include "cfile.h"

#include <epan/address.h>
#include <epan/tap.h>

/** Defines an rtp stream */
typedef struct _rtp_stream_info {
    address         src_addr;
    guint32         src_port;
    address         dest_addr;
    guint32         dest_port;
    guint32         ssrc;

    guint8          payload_type; /**< Numeric payload type */
    gchar          *payload_type_name; /**< Payload type name */
    gboolean        is_srtp;

    guint32         packet_count;
    gboolean        end_stream; /**< Used to track streams across payload types */
    int             rtp_event;

    int             call_num; /**< Used to match call_num in voip_calls_info_t */
    guint32         setup_frame_number; /**< frame number of setup message */
    /* Start and stop packets needed for .num and .abs_ts */
    frame_data     *start_fd;
    frame_data     *stop_fd;
    nstime_t        start_rel_time;     /**< relative start time from pinfo */
    nstime_t        stop_rel_time;      /**< relative stop time from pinfo */
    guint16         vlan_id;
    gboolean        tag_vlan_error;
    gboolean        tag_diffserv_error;

    gboolean        decode; /**< Decode this stream. GTK+ only? */
    GList          *rtp_packet_list; /**< List of RTP rtp_packet_t. GTK+ only */

    tap_rtp_stat_t  rtp_stats;  /**< here goes the RTP statistics info */
    gboolean        problem;    /**< if the streams had wrong sequence numbers or wrong timestamps */
} rtp_stream_info_t;

/** tapping modes */
typedef enum
{
    TAP_ANALYSE,
    TAP_SAVE,
    TAP_MARK
} tap_mode_t;

typedef struct _rtpstream_tapinfo rtpstream_tapinfo_t;

typedef void (*rtpstream_tap_reset_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*rtpstream_tap_draw_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*tap_mark_packet_cb)(rtpstream_tapinfo_t *tapinfo, frame_data *fd);

/* structure that holds the information about all detected streams */
/** struct holding all information of the tap */
struct _rtpstream_tapinfo {
    rtpstream_tap_reset_cb tap_reset;       /**< tap reset callback */
    rtpstream_tap_draw_cb tap_draw;         /**< tap draw callback */
    tap_mark_packet_cb tap_mark_packet;     /**< packet marking callback */
    void *tap_data;                         /**< data for tap callbacks */
    int                nstreams; /**< number of streams in the list */
    GList             *strinfo_list; /**< list of rtp_stream_info_t* */
    int                npackets; /**< total number of rtp packets of all streams */
    /* used while tapping. user shouldn't modify these */
    tap_mode_t         mode;
    rtp_stream_info_t *filter_stream_fwd; /**< used as filter in some tap modes */
    rtp_stream_info_t *filter_stream_rev; /**< used as filter in some tap modes */
    FILE              *save_file;
    gboolean           is_registered; /**< if the tap listener is currently registered or not */
};

#if 0
#define RTP_STREAM_DEBUG(...) { \
    char *RTP_STREAM_DEBUG_MSG = g_strdup_printf(__VA_ARGS__); \
    g_warning("rtp_stream: %s:%d %s", G_STRFUNC, __LINE__, RTP_STREAM_DEBUG_MSG); \
    g_free(RTP_STREAM_DEBUG_MSG); \
}
#else
#define RTP_STREAM_DEBUG(...)
#endif

/****************************************************************************/
/* INTERFACE */

/**
* Registers the rtp_streams tap listener (if not already done).
* From that point on, the RTP streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever rtp_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the rtp_streams and rtp_analysis functions that need it.
*/
void register_tap_listener_rtp_stream(rtpstream_tapinfo_t *tapinfo, const char *fstring);

/**
* Removes the rtp_streams tap listener (if not already done)
* From that point on, the RTP streams list won't be updated any more.
*/
void remove_tap_listener_rtp_stream(rtpstream_tapinfo_t *tapinfo);

/**
* Cleans up memory of rtp streams tap.
*/
void rtpstream_reset(rtpstream_tapinfo_t *tapinfo);

/**
* Scans all packets for RTP streams and updates the RTP streams list.
* (redissects all packets)
*/
void rtpstream_scan(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, const char *fstring);

/**
* Saves an RTP stream as raw data stream with timestamp information for later RTP playback.
* (redissects all packets)
*/
gboolean rtpstream_save(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtp_stream_info_t* stream, const gchar *filename);

/**
* Compares the endpoints of two RTP streams.
*
* @return TRUE if the
*/
gboolean rtp_stream_info_is_reverse(const rtp_stream_info_t *stream_a, rtp_stream_info_t *stream_b);

/**
* Marks all packets belonging to either of stream_fwd or stream_rev.
* (both can be NULL)
* (redissects all packets)
*/
void rtpstream_mark(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtp_stream_info_t* stream_fwd, rtp_stream_info_t* stream_rev);

#define MAX_SILENCE_FRAMES 14400000

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
