/* stats_tree.h
 * A counter tree API for ethereal dissectors
 * 2005, Luis E. G. Ontanon
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
#ifndef __STATS_TREE_H
#define __STATS_TREE_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include "../register.h"

#define STAT_TREE_ROOT "root"

/* obscure information regarding the stats_tree */ 
typedef struct _stats_tree stats_tree;

/* tap packet callback for stats_tree */
typedef int  (*stat_tree_packet_cb)(stats_tree*,
									packet_info*,
									epan_dissect_t*,
									const void *);

/* stats_tree initilaization callback */
typedef void  (*stat_tree_init_cb)(stats_tree*);

/* registers a new stats tree 
 * abbr: protocol abbr
 * name: protocol name
 * packet: per packet callback
 * init: tree initialization callback
 */
extern void register_stats_tree(guint8* tapname,
								guint8* abbr, 
								guint8* name,
								stat_tree_packet_cb packet,
								stat_tree_init_cb init );

extern int get_parent_id_by_name(stats_tree* st, const gchar* parent_name);

/* Creates a node in the tree (to be used in the in init_cb)
* st: the stats_tree in which to create it
* name: the name of the new node
* parent_name: the name of the parent_node (NULL for root)
* with_children: TRUE if this node will have "dynamically created" children
*/
extern int create_node(stats_tree* st,
						const gchar* name,
						int parent_id,
						gboolean with_children);

extern int create_node_with_parent_name(stats_tree* st,
						  const gchar* name,
						  const gchar* parent_name,
						  gboolean with_children);

/* creates a node in the tree, that will contain a ranges list.
 example:
 create_range_node(st,name,parent,
				   "-99","100-199","200-299","300-399","400-", NULL);
*/
extern int create_range_node(stats_tree* st,
								const gchar* name,
								int parent_id,
								...);

extern int create_range_node_with_parent_name(stats_tree* st,
											  const gchar* name,
											  const gchar* parent_name,
											  ...);
/* */

extern int tick_range(stats_tree* st,
						 const gchar* name,
						 int parent_id,
						 int value_in_range);

extern int tick_range_with_parent_name(stats_tree* st,
						 const gchar* name,
						 const gchar* parent_name,
						 int value_in_range);

/* */
extern int create_pivot_node(stats_tree* st,
							 const gchar* name,
							 int parent_id);

extern int create_pivot_node_with_parent_name(stats_tree* st,
											  const gchar* name,
											  const gchar* parent_name);

extern int tick_pivot(stats_tree* st,
					  int pivot_id,
					  const gchar* pivot_value);

/*
 * manipulates the value of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node (NULL for root).
 * with_children=TRUE to indicate that the created node will be a parent
 */
typedef enum _manip_node_mode { MN_INCREASE, MN_SET } manip_node_mode;
extern guint8* manip_stat_node(manip_node_mode mode,
							   stats_tree* st,
							   const guint8* name,
							   int parent_id,
							   gboolean with_children,
							   gint value);

#define increase_stat_node(st,name,parent_id,with_children,value) \
(manip_stat_node(MN_INCREASE,(st),(name),(parent_id),(with_children),(value)))

#define tick_stat_node(st,name,parent_id,with_children) \
(manip_stat_node(MN_INCREASE,(st),(name),(parent_id),(with_children),1))

#define set_stat_node(st,name,parent_id,with_children,value) \
(manip_stat_node(MN_SET,(st),(name),(parent_id),(with_children),value))

#define zero_stat_node(st,name,parent_id,with_children) \
(manip_stat_node(MN_SET,(st),(name),(parent_id),(with_children),0))

#endif /* __STATS_TREE_H */
