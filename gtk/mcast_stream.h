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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef Mcast_STREAM_H_INCLUDED
#define Mcast_STREAM_H_INCLUDED

#include <glib.h>
#include <stdio.h>
#include <epan/address.h>

/** @file
 *  ??? 
 *  @ingroup dialog_group
 *  @todo what's this?
 */

#define INTERFACE        2
#define FILTER           3
#define TRIGGER          4
#define TIMER            5
#define REFRESHTIMER     6
#define EMPTYSPEED       7
#define BUFFERALARM      8
#define CUMULEMPTYSPEED  9

#define MAX_SPEED 200000

/* typedefs for sliding window and buffer size */
typedef struct buffer{
    struct timeval *buff;   /* packet times */
    gint32 first;              /* pointer to the first element */
    gint32 last;               /* pointer to the last element */
    gint32 burstsize;          /* current burst */
    gint32 topburstsize;       /* maximum burst in the refresh interval*/
    gint32 count;              /* packet counter */
    gint32 burststatus;        /* burst status */
    gint32 numbursts;          /* number of bursts */
    gint32 buffusage;         /* buffer usage */
    gint32 buffstatus;        /* buffer status */
    gint32 numbuffalarms;      /* number of alarms triggered by buffer underruns */
    gint32 topbuffusage;      /* top buffer usage in refresh interval */
    float  maxbw;            /* maximum bandwidth usage */
} t_buffer;


/* defines an mcast stream */
typedef struct _mcast_stream_info {
	address src_addr;
	guint16 src_port;
	address dest_addr;
	guint16 dest_port;
	guint32 npackets;
	guint32 apackets;
	guint32 total_bytes;
	float   average_bw;

	guint32 first_frame_num; /* frame number of first frame */
	/* start of recording (GMT) of this stream */
	guint32 start_sec;         /* seconds */
	guint32 start_usec;        /* microseconds */
	guint32 start_rel_sec;         /* start stream rel seconds */
	guint32 start_rel_usec;        /* start stream rel microseconds */
	guint32 stop_rel_sec;         /* stop stream rel seconds */
	guint32 stop_rel_usec;        /* stop stream rel microseconds */
	guint16 vlan_id;
	
	/*for the sliding window */
	t_buffer element;

} mcast_stream_info_t;


/* structure that holds the information about all detected streams */
/* struct holding all information of the tap */
typedef struct _mcaststream_tapinfo {
	int     nstreams;       /* number of streams in the list */
	GList*  strinfo_list;   /* list with all streams */
	guint32 npackets;       /* total number of mcast packets of all streams */
	mcast_stream_info_t* allstreams; /* structure holding information common for all streams */

	guint32 launch_count;   /* number of times the tap has been run */
	gboolean is_registered; /* if the tap listener is currently registered or not */
} mcaststream_tapinfo_t;

/****************************************************************************/
/* INTERFACE */

/*
* Registers the mcast_streams tap listener (if not already done).
* From that point on, the Mcast streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever mcast_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the mcast_streams and mcast_analysis functions that need it.
*/
void register_tap_listener_mcast_stream(void);

/*
* Removes the mcast_streams tap listener (if not already done)
* From that point on, the Mcast streams list won't be updated any more.
*/
void remove_tap_listener_mcast_stream(void);

/*
* Retrieves a constant reference to the unique info structure of the mcast_streams tap listener.
* The user should not modify the data pointed to.
*/
const mcaststream_tapinfo_t* mcaststream_get_info(void);

/*
* Cleans up memory of mcast streams tap.
*/
void mcaststream_reset(mcaststream_tapinfo_t *tapinfo);

/*
* Scans all packets for Mcast streams and updates the Mcast streams list.
* (redissects all packets)
*/
void mcaststream_scan(void);

#endif /*Mcast_STREAM_H_INCLUDED*/
