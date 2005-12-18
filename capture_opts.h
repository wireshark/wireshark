/* capture_opts.h
 * Capture options (all parameters needed to do the actual capture)
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


/** @file
 *  
 *  Capture options (all parameters needed to do the actual capture)
 *
 */

#ifndef __CAPTURE_OPTS_H__
#define __CAPTURE_OPTS_H__


/* Current state of capture engine. XXX - differentiate states */
typedef enum {
	CAPTURE_STOPPED,		/**< stopped */
    CAPTURE_PREPARING,      /**< preparing, but still no response from capture child */
	CAPTURE_RUNNING		    /**< capture child signalled ok, capture is running now */
} capture_state;


/** Capture options coming from user interface */
typedef struct capture_options_tag {
    /* general */
    void     *cf;           /**< handle to cfile (note: untyped handle) */
    gchar    *cfilter;      /**< Capture filter string */
    gchar    *iface;        /**< the network interface to capture from */

#ifdef _WIN32
    int      buffer_size;   /**< the capture buffer size (MB) */
#endif
    gboolean has_snaplen;   /**< TRUE if maximum capture packet length
                                 is specified */
    int      snaplen;       /**< Maximum captured packet length */
    gboolean promisc_mode;  /**< Capture in promiscuous mode */
    int      linktype;      /**< Data link type to use, or -1 for
                                 "use default" */
    gchar    *save_file;    /**< the capture file name */

    /* GUI related */
    gboolean real_time_mode;    /**< Update list of packets in real time */
    gboolean show_info;         /**< show the info dialog */
    gboolean quit_after_cap;    /** Makes a "capture only mode". Implies -k */
    gboolean restart;           /**< restart after closing is done */

    /* multiple files (and ringbuffer) */
    gboolean multi_files_on;    /**< TRUE if ring buffer in use */

    gboolean has_file_duration;	/**< TRUE if ring duration specified */
    gint32 file_duration;       /* Switch file after n seconds */
    gboolean has_ring_num_files;/**< TRUE if ring num_files specified */
    guint32 ring_num_files;     /**< Number of multiple buffer files */

    /* autostop conditions */
    gboolean has_autostop_files;/**< TRUE if maximum number of capture files
					   are specified */
    gint32 autostop_files;      /**< Maximum number of capture files */

    gboolean has_autostop_packets;	/**< TRUE if maximum packet count is
					   specified */
    int autostop_packets;               /**< Maximum packet count */
    gboolean has_autostop_filesize;     /**< TRUE if maximum capture file size
                                             is specified */
    gint32 autostop_filesize;           /**< Maximum capture file size */
    gboolean has_autostop_duration;     /**< TRUE if maximum capture duration
                                             is specified */
    gint32 autostop_duration;           /**< Maximum capture duration */

    /* internally used (don't touch from outside) */
    int fork_child;	            /**< If not -1, in parent, process ID of child */
#ifdef _WIN32
    int signal_pipe_fd;         /**< the pipe to signal the child */
#endif
    capture_state state;        /**< current state of the capture engine */
} capture_options;


/* initialize the capture_options with some reasonable values */
extern void
capture_opts_init(capture_options *capture_opts, void *cfile);

/* set a command line option value */
extern void
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg, gboolean *start_capture);

/* log content of capture_opts */
extern void
capture_opts_log(const char *log_domain, GLogLevelFlags log_level, capture_options *capture_opts);

/* list link layer types */
extern void 
capture_opts_list_link_layer_types(capture_options *capture_opts);

/* list interfaces */
extern void
capture_opts_list_interfaces(void);

/* trim the snaplen entry */
extern void 
capture_opts_trim_snaplen(capture_options *capture_opts, int snaplen_min);

/* trim the ring_num_files entry */
extern void 
capture_opts_trim_ring_num_files(capture_options *capture_opts);

/* trim the interface entry */
extern gboolean
capture_opts_trim_iface(capture_options *capture_opts, const char *capture_device);

#endif /* capture_opts.h */
