/* capture.h
 * Definitions for packet capture windows
 *
 * $Id: capture.h,v 1.31 2002/02/24 09:25:34 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
} capture_options;

extern capture_options capture_opts;

extern int sync_pipe[2]; /* used to sync father */
extern int quit_after_cap; /* Makes a "capture only mode". Implies -k */
extern gboolean capture_child;	/* if this is the child for "-S" */

/* Open a specified file, or create a temporary file, and start a capture
   to the file in question. */
void   do_capture(char *capfile_name);

/* Do the low-level work of a capture. */
int    capture(gboolean *stats_known, struct pcap_stat *stats);

/* Stop a capture from a menu item. */
void   capture_stop(void);

/* Terminate the capture child cleanly when exiting. */
void   kill_capture_child(void);

#endif /* HAVE_LIBPCAP */

#define EMPTY_FILTER ""
#endif /* capture.h */
