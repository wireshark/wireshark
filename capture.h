/* capture.h
 * Definitions for packet capture windows
 *
 * $Id$
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

/** @file
 *  Capture related things.
 */

/** Name we give to the child process when doing a "-S" capture. */
#define	CHILD_NAME	"ethereal-capture"

#ifdef HAVE_LIBPCAP

/** Capture options coming from user interface */
typedef struct capture_options_tag {
    /* general */
    void *cf;               /**< handle to cfile (note: untyped handle) */
#ifdef _WIN32
    int buffer_size;        /**< the capture buffer size (MB) */
#endif
	gboolean has_snaplen;		/**< TRUE if maximum capture packet
					   length is specified */
	int snaplen;			/**< Maximum captured packet length */
	gboolean promisc_mode;  /**< Capture in promiscuous mode */
	int linktype;			/**< Data link type to use, or -1 for
					   "use default" */
	gboolean capture_child;	/**< True if this is the child for "-S" */
    gchar    *save_file;    /**< File that user saved capture to */
    int      save_file_fd;  /**< File descriptor for saved file */

    /* GUI related */
	gboolean sync_mode;			/**< Fork a child to do the capture,
					   and sync between them */
    gboolean show_info;     /**< show the info dialog */
    gboolean quit_after_cap;    /** Makes a "capture only mode". Implies -k */

    /* multiple files (and ringbuffer) */
    gboolean multi_files_on;    /**< TRUE if ring buffer in use */

	gboolean has_file_duration;	/**< TRUE if ring duration specified */
	gint32 file_duration;     /* Switch file after n seconds */
	gboolean has_ring_num_files;/**< TRUE if ring num_files specified */
	guint32 ring_num_files;	        /**< Number of multiple buffer files */

    /* autostop conditions */
    gboolean has_autostop_files;/**< TRUE if maximum number of capture files
					   are specified */
    gint32 autostop_files;      /**< Maximum number of capture files */

    gboolean has_autostop_packets;	/**< TRUE if maximum packet count is
					   specified */
	int autostop_packets;		/**< Maximum packet count */
	gboolean has_autostop_filesize;	/**< TRUE if maximum capture file size
					   is specified */
	gint32 autostop_filesize;	/**< Maximum capture file size */
	gboolean has_autostop_duration;	/**< TRUE if maximum capture duration
					   is specified */
	gint32 autostop_duration;	/**< Maximum capture duration */

    /* internally used (don't touch from outside) */
    int fork_child;	            /**< If not -1, in parent, process ID of child */
} capture_options;


/** Open a specified file, or create a temporary file, and start a capture
 * to the file in question.  
 *
 * @return TRUE if the capture starts successfully, FALSE otherwise. */
extern gboolean do_capture(capture_options *capture_opts, const char *save_file);

/** Do the low-level work of a capture (start the capture child). */
extern int  capture_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats);

/** Stop a capture from a menu item. */
extern void capture_stop(capture_options *capture_opts);

/** Terminate the capture child cleanly when exiting. */
extern void kill_capture_child(capture_options *capture_opts);

/** Do the low-level work of a capture. */
extern int  capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats);

/** Stop a low-level capture. */
extern void capture_loop_stop(void);



/** Current Capture info. */
typedef struct {
    /* handles */
    gpointer        callback_data;  /**< capture callback handle */
    gpointer        ui;             /**< user interfaces own handle */

    /* capture info */
    packet_counts   *counts;        /**< protocol specific counters */
    time_t          running_time;   /**< running time since last update */
    gint            new_packets;    /**< packets since last update */
} capture_info;


/** Create the capture info dialog */
extern void capture_info_create(
capture_info    *cinfo,
gchar           *iface);

/** Update the capture info counters in the dialog */
extern void capture_info_update(
capture_info    *cinfo);

/** Destroy the capture info dialog again */
extern void capture_info_destroy(
capture_info    *cinfo);


#endif /* HAVE_LIBPCAP */

#endif /* capture.h */
