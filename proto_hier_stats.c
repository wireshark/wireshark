/* proto_hier_stats.c
 * Routines for calculating statistics based on protocol.
 *
 * $Id: proto_hier_stats.c,v 1.1 2001/03/22 23:54:44 gram Exp $
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


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "proto_hier_stats.h"
#include <wtap.h>

#include <stdio.h>
#include <glib.h>

static GNode*
find_stat_node(GNode *parent_node, header_field_info *needle_hfinfo)
{
	GNode			*needle_node;
	field_info		*finfo;
	ph_stats_node_t	*stats;

	needle_node = g_node_first_child(parent_node);

	while (needle_node) {
		finfo = needle_node->data;
		if (finfo && finfo->hfinfo && finfo->hfinfo->id == needle_hfinfo->id) {
			return needle_node;
		}
		needle_node = g_node_next_sibling(needle_node);
	}

	/* None found. Create one. */
	stats = g_new(ph_stats_node_t, 1);

	/* Intialize counters */
	stats->hfinfo = needle_hfinfo;
	stats->num_pkts_total = 0;
	stats->num_pkts_last = 0;
	stats->num_bytes_total = 0;
	stats->num_bytes_last = 0;

	needle_node = g_node_new(stats);
	g_node_append(parent_node, needle_node);
	return needle_node;
}


static void
process_node(proto_item *proto_node, GNode *parent_stat_node, ph_stats_t *ps, guint pkt_len)
{
	field_info		*finfo;
	ph_stats_node_t	*stats;
	proto_item		*proto_sibling_node;
	GNode			*stat_node;

	finfo = proto_node->data;
	g_assert(finfo);

	stat_node = find_stat_node(parent_stat_node, finfo->hfinfo);
	
	/* Assert that the finfo is related to a protocol, not a field. */
	g_assert(finfo->hfinfo->parent == -1);

	stats = stat_node->data;
	stats->num_pkts_total++;
	stats->num_bytes_total += pkt_len;

	proto_sibling_node = g_node_next_sibling(proto_node);

	if (proto_sibling_node) {
		process_node(proto_sibling_node, stat_node, ps, pkt_len);
	}
	else {
		stats->num_pkts_last++;
		stats->num_bytes_last += pkt_len;
	}
}



static void
process_tree(proto_tree *protocol_tree, ph_stats_t* ps, guint pkt_len)
{
	proto_item	*proto_node;

	proto_node = g_node_first_child(protocol_tree);
	if (!proto_node) {
		return;
	}

	process_node(proto_node, ps->stats_tree, ps, pkt_len);
}

static void
process_frame(frame_data *frame, ph_stats_t* ps)
{
	epan_dissect_t			*edt;
	union wtap_pseudo_header	phdr;
	proto_tree			*protocol_tree;
	guint8				pd[WTAP_MAX_PACKET_SIZE];

	protocol_tree = proto_tree_create_root();

	/* Load the frame from the capture file */
	wtap_seek_read(cfile.wth, frame->file_off, &phdr,
			pd, frame->cap_len);

	/* Dissect the frame */
	edt = epan_dissect_new(&phdr, pd, frame, protocol_tree);

	/* Get stats from this protocol tree */
	process_tree(protocol_tree, ps, frame->pkt_len);

	/* Free our memory. */
	epan_dissect_free(edt);
	proto_tree_free(protocol_tree);
}



ph_stats_t*
ph_stats_new(void)
{
	ph_stats_t	*ps;
	frame_data	*frame;
	guint		tot_packets, tot_bytes;

	/* Initialize the data */
	ps = g_new(ph_stats_t, 1);
	ps->tot_packets = 0;
	ps->tot_bytes = 0;
	ps->stats_tree = g_node_new(NULL);

	frame = cfile.plist;
	tot_packets = 0;
	tot_bytes = 0;

	while (frame) {
		/* Skip frames that are hidden due to the display filter */
		if (!frame->flags.passed_dfilter) {
			continue;
		}

		process_frame(frame, ps);

		tot_packets++;
		tot_bytes += frame->pkt_len;

		frame = frame->next;
	}

	ps->tot_packets = tot_packets;
	ps->tot_bytes = tot_bytes;

	return ps;
}

static gboolean
stat_node_free(GNode *node, gpointer data)
{
	ph_stats_node_t	*stats = node->data;

	if (stats) {
		g_free(stats);
	}
}

void
ph_stats_free(ph_stats_t *ps)
{

	if (ps->stats_tree) {
		g_node_traverse(ps->stats_tree, G_IN_ORDER,
				G_TRAVERSE_ALL, -1,
				stat_node_free, NULL);
		g_node_destroy(ps->stats_tree);
	}

	g_free(ps);
}
