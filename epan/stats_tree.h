/* stats_tree.h
 * A counter tree API for Wireshark dissectors
 * 2005, Luis E. G. Ontanon
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __STATS_TREE_H
#define __STATS_TREE_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include "../stat_menu.h"
#include "../register.h"

#define STAT_TREE_ROOT "root"

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
extern void stats_tree_register(const gchar *tapname,
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
extern void stats_tree_register_plugin(const gchar *tapname,
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
extern void stats_tree_register_with_group(const gchar *tapname,
				const gchar *abbr,
				const gchar *name,
				guint flags,
				stat_tree_packet_cb packet,
				stat_tree_init_cb init,
				stat_tree_cleanup_cb cleanup,
				register_stat_group_t stat_group);

extern int stats_tree_parent_id_by_name(stats_tree *st, const gchar *parent_name);

/* Creates a node in the tree (to be used in the in init_cb)
* st: the stats_tree in which to create it
* name: the name of the new node
* parent_name: the name of the parent_node (NULL for root)
* with_children: TRUE if this node will have "dynamically created" children
*/
extern int stats_tree_create_node(stats_tree *st,
				  const gchar *name,
				  int parent_id,
				  gboolean with_children);

/* creates a node using it's parent's tree name */
extern int stats_tree_create_node_by_pname(stats_tree *st,
					   const gchar *name,
					   const gchar *parent_name,
					   gboolean with_children);

/* creates a node in the tree, that will contain a ranges list.
 example:
 stats_tree_create_range_node(st,name,parent,
			      "-99","100-199","200-299","300-399","400-", NULL);
*/
extern int stats_tree_create_range_node(stats_tree *st,
					const gchar *name,
					int parent_id,
					...);

extern int stats_tree_create_range_node_string(stats_tree *st,
					const gchar *name,
					int parent_id,
					int num_str_ranges,
					gchar** str_ranges);

extern int stats_tree_range_node_with_pname(stats_tree *st,
					    const gchar *name,
					    const gchar *parent_name,
					    ...);

/* increases by one the ranged node and the sub node to whose range the value belongs */
extern int stats_tree_tick_range(stats_tree *st,
				 const gchar *name,
				 int parent_id,
				 int value_in_range);

#define stats_tree_tick_range_by_pname(st,name,parent_name,value_in_range) \
     stats_tree_tick_range((st),(name),stats_tree_parent_id_by_name((st),(parent_name),(value_in_range))

/* */
extern int stats_tree_create_pivot(stats_tree *st,
				   const gchar *name,
				   int parent_id);

extern int stats_tree_create_pivot_by_pname(stats_tree *st,
					    const gchar *name,
					    const gchar *parent_name);

extern int stats_tree_tick_pivot(stats_tree *st,
				 int pivot_id,
				 const gchar *pivot_value);

/*
 * manipulates the value of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node (NULL for root).
 * with_children=TRUE to indicate that the created node will be a parent
 */
typedef enum _manip_node_mode { MN_INCREASE, MN_SET } manip_node_mode;
extern int stats_tree_manip_node(manip_node_mode mode,
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

#endif /* __STATS_TREE_H */
