/* rtp_stream.h
 * RTP streams summary addition for Wireshark
 *
 * $Id$
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

#include "rtp_analysis.h"
#include <glib.h>
#include <stdio.h>
#include <epan/address.h>


/****************************************************************************/
/* type for storing rtp frame information */
typedef struct st_rtp_sample_header {
	guint32 rec_time;	/* milliseconds since start of recording */
	guint16 frame_length;   /* number of bytes in *frame */
} rtp_sample_header_t;

/* type for storing rtp frame information */
typedef struct st_rtp_sample {
	rtp_sample_header_t header;  /* date and size */
	const guint8 *frame;                 /* data bytes */
} rtp_sample_t;

typedef rtp_sample_t* rtp_sample_p;


/* defines an rtp stream */
typedef struct _rtp_stream_info {
	address src_addr;
	guint32 src_port;
	address dest_addr;
	guint32 dest_port;
	guint32 ssrc;
	guint8  pt;
	gchar	*info_payload_type_str;
	guint32 npackets;

	guint32 first_frame_num; /* frame number of first frame */
	guint32 setup_frame_number; /* frame number of setup message */
	/* start of recording (GMT) of this stream */
	guint32 start_sec;         /* seconds */
	guint32 start_usec;        /* microseconds */
	gboolean tag_vlan_error;
	guint32 start_rel_sec;         /* start stream rel seconds */
	guint32 start_rel_usec;        /* start stream rel microseconds */
	guint32 stop_rel_sec;         /* stop stream rel seconds */
	guint32 stop_rel_usec;        /* stop stream rel microseconds */
	gboolean tag_diffserv_error;
	guint16 vlan_id;

	tap_rtp_stat_t rtp_stats;  /* here goes the RTP statistics info */
	gboolean problem; /* if the streams had wrong sequence numbers or wrong timerstamps */
} rtp_stream_info_t;


/* tapping modes */
typedef enum
{
	TAP_ANALYSE,
	TAP_SAVE,
	TAP_MARK
} tap_mode_t;


/* structure that holds the information about all detected streams */
/* struct holding all information of the tap */
typedef struct _rtpstream_tapinfo {
	int     nstreams;       /* number of streams in the list */
	GList*  strinfo_list;   /* list with all streams */
	int     npackets;       /* total number of rtp packets of all streams */
	/* used while tapping. user shouldnt modify these */
	tap_mode_t mode;
	rtp_stream_info_t* filter_stream_fwd;  /* used as filter in some tap modes */
	rtp_stream_info_t* filter_stream_rev;  /* used as filter in some tap modes */
	FILE*   save_file;
	guint32 launch_count;   /* number of times the tap has been run */
	gboolean is_registered; /* if the tap listener is currently registered or not */
} rtpstream_tapinfo_t;

/****************************************************************************/
/* INTERFACE */

/**
* Registers the rtp_streams tap listener (if not already done).
* From that point on, the RTP streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever rtp_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the rtp_streams and rtp_analysis functions that need it.
*/
void register_tap_listener_rtp_stream(void);

/**
* Removes the rtp_streams tap listener (if not already done)
* From that point on, the RTP streams list won't be updated any more.
*/
void remove_tap_listener_rtp_stream(void);

/**
* Retrieves a constant reference to the unique info structure of the rtp_streams tap listener.
* The user should not modify the data pointed to.
*/
const rtpstream_tapinfo_t* rtpstream_get_info(void);

/**
* Cleans up memory of rtp streams tap.
*/
void rtpstream_reset(rtpstream_tapinfo_t *tapinfo);

/**
* Scans all packets for RTP streams and updates the RTP streams list.
* (redissects all packets)
*/
void rtpstream_scan(void);

/**
* Saves an RTP stream as raw data stream with timestamp information for later RTP playback.
* (redissects all packets)
*/
gboolean rtpstream_save(rtp_stream_info_t* stream, const gchar *filename);

/**
* Marks all packets belonging to either of stream_fwd or stream_rev.
* (both can be NULL)
* (redissects all packets)
*/
void rtpstream_mark(rtp_stream_info_t* stream_fwd, rtp_stream_info_t* stream_rev);


#endif /* __RTP_STREAM_H__ */
