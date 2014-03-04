/* stats_tree.h
 * A counter tree API for Wireshark dissectors
 * 2005, Luis E. G. Ontanon
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __STATS_TREE_H
#define __STATS_TREE_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include "../stat_menu.h"
#include "../register.h"
#include "ws_symbol_export.h"

#define STAT_TREE_ROOT "root"

#define	ST_FLG_AVERAGE		0x10000000	/* Calculate overages for nodes, rather than totals */
#define	ST_FLG_ROOTCHILD	0x20000000	/* This node is a direct child of the root node */
#define	ST_FLG_DEF_NOEXPAND	0x01000000	/* This node should not be expanded by default */
#define	ST_FLG_SORT_DESC	0x00800000	/* When sorting, sort ascending instead of decending */
#define	ST_FLG_SORT_TOP		0x00400000	/* When sorting always keep these lines on of list */
#define ST_FLG_SRTCOL_MASK	0x000F0000	/* Mask for sort column ID */
#define	ST_FLG_SRTCOL_SHIFT	16			/* Number of bits to shift masked result */

#define	ST_FLG_MASK			(ST_FLG_AVERAGE|ST_FLG_ROOTCHILD|ST_FLG_DEF_NOEXPAND|\
							ST_FLG_SORT_TOP|ST_FLG_SORT_DESC|ST_FLG_SRTCOL_MASK)

#define ST_SORT_COL_NAME	1		/* Sort nodes by node names */
#define ST_SORT_COL_COUNT	2		/* Sort nodes by node count */
#define ST_SORT_COL_AVG		3		/* Sort nodes by node average */
#define ST_SORT_COL_MIN		4		/* Sort nodes by minimum node value */
#define ST_SORT_COL_MAX		5		/* Sort nodes by maximum node value */
#define ST_SORT_COL_BURSTRATE	6	/* Sort nodes by burst rate */

/* obscure information regarding the stats_tree */
typedef struct _stats_tree stats_tree;

/* tap packet callback for stats_tree */
typedef int  (*stat_tree_packet_cb)(stats_tree*,
				    packet_info*,
				    epan_dissect_t*,
				    const void *);

/* stats_tree initialization callback */
typedef void  (*stat_tree_init_cb)(stats_tree*);

/* stats_tree cleanup callback */
typedef void  (*stat_tree_cleanup_cb)(stats_tree*);

/* registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED
 * abbr: protocol abbr
 * name: protocol display name
 * flags: tap listener flags for per-packet callback
 * packet: per packet callback
 * init: tree initialization callback
 * cleanup: cleanup callback
 */
WS_DLL_PUBLIC void stats_tree_register(const gchar *tapname,
				const gchar *abbr,
				const gchar *name,
				guint flags,
				stat_tree_packet_cb packet,
				stat_tree_init_cb init,
				stat_tree_cleanup_cb cleanup);

/* registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED from a plugin
 * abbr: protocol abbr
 * name: protocol display name
 * flags: tap listener flags for per-packet callback
 * packet: per packet callback
 * init: tree initialization callback
 * cleanup: cleanup callback
 */
WS_DLL_PUBLIC void stats_tree_register_plugin(const gchar *tapname,
				const gchar *abbr,
				const gchar *name,
				guint flags,
				stat_tree_packet_cb packet,
				stat_tree_init_cb init,
				stat_tree_cleanup_cb cleanup);

/* registers a new stats tree
 * abbr: protocol abbr
 * name: protocol display name
 * flags: tap listener flags for per-packet callback
 * packet: per packet callback
 * init: tree initialization callback
 * cleanup: cleanup callback
 * stat_group: the group this stat belongs to
 */
WS_DLL_PUBLIC void stats_tree_register_with_group(const gchar *tapname,
				const gchar *abbr,
				const gchar *name,
				guint flags,
				stat_tree_packet_cb packet,
				stat_tree_init_cb init,
				stat_tree_cleanup_cb cleanup,
				register_stat_group_t stat_group);

WS_DLL_PUBLIC int stats_tree_parent_id_by_name(stats_tree *st, const gchar *parent_name);

/* Creates a node in the tree (to be used in the in init_cb)
* st: the stats_tree in which to create it
* name: the name of the new node
* parent_name: the name of the parent_node (NULL for root)
* with_children: TRUE if this node will have "dynamically created" children
*/
WS_DLL_PUBLIC int stats_tree_create_node(stats_tree *st,
				  const gchar *name,
				  int parent_id,
				  gboolean with_children);

/* creates a node using its parent's tree name */
WS_DLL_PUBLIC int stats_tree_create_node_by_pname(stats_tree *st,
					   const gchar *name,
					   const gchar *parent_name,
					   gboolean with_children);

/* creates a node in the tree, that will contain a ranges list.
 example:
 stats_tree_create_range_node(st,name,parent,
			      "-99","100-199","200-299","300-399","400-", NULL);
*/
WS_DLL_PUBLIC int stats_tree_create_range_node(stats_tree *st,
					const gchar *name,
					int parent_id,
					...);

WS_DLL_PUBLIC int stats_tree_create_range_node_string(stats_tree *st,
					const gchar *name,
					int parent_id,
					int num_str_ranges,
					gchar** str_ranges);

WS_DLL_PUBLIC int stats_tree_range_node_with_pname(stats_tree *st,
					    const gchar *name,
					    const gchar *parent_name,
					    ...);

/* increases by one the ranged node and the sub node to whose range the value belongs */
WS_DLL_PUBLIC int stats_tree_tick_range(stats_tree *st,
				 const gchar *name,
				 int parent_id,
				 int value_in_range);

#define stats_tree_tick_range_by_pname(st,name,parent_name,value_in_range) \
     stats_tree_tick_range((st),(name),stats_tree_parent_id_by_name((st),(parent_name),(value_in_range))

/* */
WS_DLL_PUBLIC int stats_tree_create_pivot(stats_tree *st,
				   const gchar *name,
				   int parent_id);

WS_DLL_PUBLIC int stats_tree_create_pivot_by_pname(stats_tree *st,
					    const gchar *name,
					    const gchar *parent_name);

WS_DLL_PUBLIC int stats_tree_tick_pivot(stats_tree *st,
				 int pivot_id,
				 const gchar *pivot_value);

/*
 * manipulates the value of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node (NULL for root).
 * with_children=TRUE to indicate that the created node will be a parent
 */
typedef enum _manip_node_mode {
	MN_INCREASE,
	MN_SET,
	MN_AVERAGE,
	MN_AVERAGE_NOTICK,
	MN_SET_FLAGS,
	MN_CLEAR_FLAGS
} manip_node_mode;
WS_DLL_PUBLIC int stats_tree_manip_node(manip_node_mode mode,
				 stats_tree *st,
				 const gchar *name,
				 int parent_id,
				 gboolean with_children,
				 gint value);

#define increase_stat_node(st,name,parent_id,with_children,value) \
(stats_tree_manip_node(MN_INCREASE,(st),(name),(parent_id),(with_children),(value)))

#define tick_stat_node(st,name,parent_id,with_children) \
(stats_tree_manip_node(MN_INCREASE,(st),(name),(parent_id),(with_children),1))

#define set_stat_node(st,name,parent_id,with_children,value) \
(stats_tree_manip_node(MN_SET,(st),(name),(parent_id),(with_children),value))

#define zero_stat_node(st,name,parent_id,with_children) \
(stats_tree_manip_node(MN_SET,(st),(name),(parent_id),(with_children),0))

/*
 * Add value to average calculation WITHOUT ticking node. Node MUST be ticked separately!
 *
 * Intention is to allow code to separately tick node (backward compatibility for plugin)
 * and set value to use for averages. Older versions without average support will then at
 * least show a count instead of 0.
 */
#define avg_stat_node_add_value_notick(st,name,parent_id,with_children,value) \
(stats_tree_manip_node(MN_AVERAGE_NOTICK,(st),(name),(parent_id),(with_children),value))

/* Tick node and add a new value to the average calculation for this stats node. */
#define avg_stat_node_add_value(st,name,parent_id,with_children,value) \
(stats_tree_manip_node(MN_AVERAGE,(st),(name),(parent_id),(with_children),value))

/* Set flags for this node. Node created if it does not yet exist. */
#define stat_node_set_flags(st,name,parent_id,with_children,flags) \
(stats_tree_manip_node(MN_SET_FLAGS,(st),(name),(parent_id),(with_children),flags))

/* Clear flags for this node. Node created if it does not yet exist. */
#define stat_node_clear_flags(st,name,parent_id,with_children,flags) \
(stats_tree_manip_node(MN_CLEAR_FLAGS,(st),(name),(parent_id),(with_children),flags))

#endif /* __STATS_TREE_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: ex: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
