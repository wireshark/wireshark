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

typedef struct _summary_tally {
    guint64	bytes;		/* total bytes */
    double	start_time;	/* seconds, with msec resolution */
    double	stop_time;	/* seconds, with msec resolution */
    double	elapsed_time;	/* seconds, with msec resolution,
				   includes time before first packet
				   and after last packet */
    int		marked_count;	/* number of marked packets */
    int		packet_count;	/* total number of packets in trace */
    int		filtered_count; /* number of filtered packets */
    guint64	filtered_bytes;	/* total bytes in the filtered packets */
    double 	filtered_start; /* time in seconds, with msec resolution */
    double 	filtered_stop;  /* time in seconds, with msec resolution */
    const char	*filename;
    gint64	file_length;	/* file length in bytes */
    int		encap_type;	/* wiretap encapsulation type */
    gboolean	has_snap;	/* TRUE if maximum capture packet length is known */
    int		snap;		/* Maximum captured packet length */
    gboolean    drops_known;	/* TRUE if number of packet drops is known */
    guint64     drops;		/* number of packet drops */
    const char	*dfilter;	/* display filter */

    /* capture related, use summary_fill_in_capture() to get values */
    const char	*cfilter;	/* capture filter */
    const char	*iface;		/* interface name */
    const char	*iface_descr;/* descriptive interface name */
} summary_tally;

extern void 
summary_fill_in(capture_file *cf, summary_tally *st);

#ifdef HAVE_LIBPCAP
extern void
summary_fill_in_capture(capture_options *capture_opts, summary_tally *st);
#endif

#endif /* summary.h */





