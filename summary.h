/* summary.h
 * Definitions for capture file summary data
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

#ifdef HAVE_LIBPCAP
#include "capture.h"
#endif

typedef struct iface_options_tag {
    char	*name;
    char	*descr;
    char	*cfilter;
    guint64	drops;		/* number of packet drops */
    gboolean	drops_known;	/* TRUE if number of packet drops is known */
    gboolean	has_snap;	/* TRUE if maximum capture packet length is known */
    int		snap;		/* Maximum captured packet length */
    int		linktype;	/* wiretap encapsulation type */
} iface_options;

typedef struct _summary_tally {
    guint64	bytes;			/**< total bytes */
    double	start_time;		/**< seconds, with msec resolution */
    double	stop_time;		/**< seconds, with msec resolution */
    double	elapsed_time;		/**< seconds, with msec resolution,
					   includes time before first packet
					   and after last packet */
    guint32	marked_count;		/**< number of marked packets */
    guint32	marked_count_ts;	/**< number of time-stamped marked packets */
    guint64	marked_bytes;		/**< total bytes in the marked packets */
    double 	marked_start;		/**< time in seconds, with msec resolution */
    double 	marked_stop;		/**< time in seconds, with msec resolution */
    guint32	ignored_count;		/**< number of ignored packets */
    guint32	packet_count;		/**< total number of packets in trace */
    guint32	packet_count_ts;	/**< total number of time-stamped packets in trace */
    guint32	filtered_count;		/**< number of filtered packets */
    guint32	filtered_count_ts;	/**< number of time-stamped filtered packets */
    guint64	filtered_bytes;		/**< total bytes in the filtered packets */
    double 	filtered_start;		/**< time in seconds, with msec resolution */
    double 	filtered_stop;		/**< time in seconds, with msec resolution */
    const char	*filename;
    gint64		file_length;	/**< file length in bytes */
    int			file_type;		/**< wiretap file type */
    int			encap_type;		/**< wiretap encapsulation type */
    gboolean	has_snap;		/**< TRUE if maximum capture packet length is known */
    int			snap;			/**< Maximum captured packet length */
    gboolean    drops_known;	/**< TRUE if number of packet drops is known */
    guint64     drops;			/**< number of packet drops */
    const char	*dfilter;		/**< display filter */
    gboolean    is_tempfile;
	/* from SHB, use summary_fill_shb_inf() to get values */
    gchar       *opt_comment;   	/**< comment from SHB block */
    gchar       *shb_hardware;		/**< Capture HW from SHB block */
    gchar       *shb_os;			/**< The OS the capture was made on from SHB block */
    gchar       *shb_user_appl;		/**< The application that made the capture from SHB block */
    /* capture related, use summary_fill_in_capture() to get values */
    GArray	*ifaces;
    gboolean	legacy;
} summary_tally;

extern void
summary_fill_in(capture_file *cf, summary_tally *st);

#ifdef HAVE_LIBPCAP
extern void
summary_fill_in_capture(capture_file *cf, capture_options *capture_opts, summary_tally *st);
#endif
extern void
summary_update_comment(capture_file *cf, gchar *comment);

#endif /* summary.h */





