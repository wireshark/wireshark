/* capture.h
 * Definitions for packet capture windows
 *
 * $Id: capture.h,v 1.38 2003/11/15 08:47:28 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#ifdef HAVE_LIBPCAP

/* Name we give to the child process when doing a "-S" capture. */
#define	CHILD_NAME	"ethereal-capture"

typedef struct {
	gboolean has_snaplen;		/* TRUE if maximum capture packet
					   length is specified */
	int snaplen;			/* Maximum captured packet length */
	int promisc_mode;		/* Capture in promiscuous mode */
	int sync_mode;			/* Fork a child to do the capture,
					   and sync between them */
	gboolean has_autostop_count;	/* TRUE if maximum packet count is
					   specified */
	int autostop_count;		/* Maximum packet count */
	gboolean has_autostop_duration;	/* TRUE if maximum capture duration
					   is specified */
	gint32 autostop_duration;	/* Maximum capture duration */
	gboolean has_autostop_filesize;	/* TRUE if maximum capture file size
					   is specified */
	gint32 autostop_filesize;	/* Maximum capture file size */
	gboolean ringbuffer_on;		/* TRUE if ring buffer in use */
	guint32 ringbuffer_num_files;	/* Number of ring buffer files */
	gboolean has_ring_duration;	/* TRUE if ring duration specified */
	gint32 ringbuffer_duration;     /* Switch file after n seconds */
	int linktype;			/* Data link type to use, or -1 for
					   "use default" */
} capture_options;

extern capture_options capture_opts;

extern int quit_after_cap; /* Makes a "capture only mode". Implies -k */
extern gboolean capture_child;	/* if this is the child for "-S" */

/* Open a specified file, or create a temporary file, and start a capture
   to the file in question.  Returns TRUE if the capture starts
   successfully, FALSE otherwise. */
gboolean do_capture(const char *save_file);

/* Do the low-level work of a capture. */
int    capture(gboolean *stats_known, struct pcap_stat *stats);

/* Stop a capture from a menu item. */
void   capture_stop(void);

/* Terminate the capture child cleanly when exiting. */
void   kill_capture_child(void);


/* XXX: improve this macro (put something like this into epan/packet.h?) */
#define CAPTURE_PACKET_COUNTS sizeof(packet_counts) / sizeof (gint)

typedef struct {
    /* handles */
    gpointer        callback_data;  /* capture callback handle */
    gpointer        ui;             /* user interfaces own handle */

    /* capture info */
    packet_counts   *counts;        /* protocol specific counters */
    time_t          running_time;   /* running time since last update */
    gint            new_packets;    /* packets since last update */
} capture_info;


/* create the capture info dialog */
extern void capture_info_create(
capture_info    *cinfo);

/* Update the capture info counters in the dialog */
extern void capture_info_update(
capture_info    *cinfo);

/* destroy the capture info dialog again */
extern void capture_info_destroy(
capture_info    *cinfo);

/* ui calls this, when user wants to stop capturing */
extern void capture_ui_stop_callback(
gpointer 		callback_data);


#endif /* HAVE_LIBPCAP */

#define EMPTY_FILTER ""
#endif /* capture.h */
