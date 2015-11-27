/* mcast_stream.h
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.h
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

#ifndef __MCAST_STREAM_H__
#define __MCAST_STREAM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/tap.h>

#define MAX_SPEED 200000

/* typedefs for sliding window and buffer size */
typedef struct buffer{
    nstime_t *buff;            /* packet times */
    gint32 first;              /* pointer to the first element */
    gint32 last;               /* pointer to the last element */
    gint32 burstsize;          /* current burst */
    gint32 topburstsize;       /* maximum burst in the refresh interval*/
    gint32 count;              /* packet counter */
    gint32 burststatus;        /* burst status */
    gint32 numbursts;          /* number of bursts */
    gint32 buffusage;          /* buffer usage */
    gint32 buffstatus;         /* buffer status */
    gint32 numbuffalarms;      /* number of alarms triggered by buffer underruns */
    gint32 topbuffusage;       /* top buffer usage in refresh interval */
    double maxbw;              /* Maximum bandwidth usage. Bits/s */
} t_buffer;


/* defines an mcast stream */
typedef struct _mcast_stream_info {
    address src_addr;
    guint16 src_port;
    address dest_addr;
    guint16 dest_port;
    guint32 npackets;
    double  apackets;
    guint32 total_bytes;
    double  average_bw;         /* Bits/s */

    guint32 first_frame_num; /* frame number of first frame */
    /* start of recording (GMT) of this stream */
    nstime_t start_abs;        /* absolute stream start time */
    nstime_t start_rel;        /* stream start time relative to first packet in capture */
    nstime_t stop_rel;         /* stream stop time relative to first packet in capture */
    guint16 vlan_id;

    /*for the sliding window */
    t_buffer element;

} mcast_stream_info_t;

typedef struct _mcaststream_tapinfo mcaststream_tapinfo_t;

typedef void (*mcaststream_tap_reset_cb)(mcaststream_tapinfo_t *tapinfo);
typedef void (*mcaststream_tap_draw_cb)(mcaststream_tapinfo_t *tapinfo);

/* structure that holds the information about all detected streams */
/* struct holding all information of the tap */
struct _mcaststream_tapinfo {
    gpointer user_data;     /* User data pointer */
    mcaststream_tap_reset_cb tap_reset; /**< tap reset callback */
    mcaststream_tap_draw_cb tap_draw;   /**< tap draw callback */
    GList*  strinfo_list;   /* list of mcast_stream_info_t */
    guint32 npackets;       /* total number of mcast packets of all streams */
    mcast_stream_info_t* allstreams; /* structure holding information common for all streams */

    gboolean is_registered; /* if the tap listener is currently registered or not */
};


extern gint32  mcast_stream_trigger;
extern gint32  mcast_stream_bufferalarm;
extern guint16 mcast_stream_burstint;
extern gint32  mcast_stream_emptyspeed;
extern gint32  mcast_stream_cumulemptyspeed;

/****************************************************************************/
/* INTERFACE */

/*
* Registers the mcast_streams tap listener (if not already done).
* From that point on, the Mcast streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever mcast_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the mcast_streams and mcast_analysis functions that need it.
*/
void register_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);

/*
* Removes the mcast_streams tap listener (if not already done)
* From that point on, the Mcast streams list won't be updated any more.
*/
void remove_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);

/*
* Cleans up memory of mcast streams tap.
*/
void mcaststream_reset(mcaststream_tapinfo_t *tapinfo);

/*
* Scans all packets for Mcast streams and updates the Mcast streams list.
* (redissects all packets)
*/
void mcaststream_scan(mcaststream_tapinfo_t *tapinfo, capture_file *cap_file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MCAST_STREAM_H__ */

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
