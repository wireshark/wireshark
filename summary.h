/* summary.h
 * Definitions for capture file summary data
 *
 * $Id: summary.h,v 1.5 2000/08/21 18:20:12 deniel Exp $
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

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

typedef struct _summary_tally {
    guint32	bytes;		/* total bytes */
    double	start_time;	/* seconds, with msec resolution */
    double	stop_time;	/* seconds, with msec resolution */
    double	elapsed_time;	/* seconds, with msec resolution,
				   includes time before first packet
				   and after last packet */
    int		filtered_count; /* number of filtered packets */
    int		marked_count;	/* number of marked packets */
    int		packet_count;	/* total number of packets in trace */
    const char	*filename;
    long	file_length;	/* file length in bytes */
    int		encap_type;	/* wiretap encapsulation type */
    int		snap;		/* snapshot length */
    int         drops;		/* number of packet drops */
    const char	*iface;		/* interface name */
    const char	*dfilter;	/* display filter */
    const char	*cfilter;	/* capture filter */
} summary_tally;

void summary_fill_in(summary_tally *st);

#endif /* summary.h */





