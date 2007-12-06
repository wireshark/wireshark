/* proto_hier_stats.h
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

#ifndef PROTO_HIER_STATS_H
#define PROTO_HIER_STATS_H

#include <epan/proto.h>

typedef struct {
	header_field_info	*hfinfo;
	guint			num_pkts_total;
	guint			num_pkts_last;
	guint			num_bytes_total;
	guint			num_bytes_last;
} ph_stats_node_t;


typedef struct {
	guint	tot_packets;
	guint	tot_bytes;
	GNode	*stats_tree;
	double	first_time;	/* seconds (msec resolution) of first packet */
	double	last_time;	/* seconds (msec resolution) of last packet  */
} ph_stats_t;


ph_stats_t* ph_stats_new(void);

void ph_stats_free(ph_stats_t *ps);

#endif
