/* proto_hier_tree_model.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __PROTO_HIER_TREE_MODEL_H__
#define __PROTO_HIER_TREE_MODEL_H__

#include <glib.h>

#define PROTOHIER_TYPE_TREE (proto_hier_tree_get_type())

#define PROTOHIER_TREE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), PROTOHIER_TYPE_TREE, ProtoHierTreeModel))
#define PROTOHIER_IS_TREE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), PROTOHIER_TYPE_TREE))

typedef struct {
	GObject parent; /** MUST be first */

	/** Random integer to check whether an iter belongs to our model. */
	gint stamp;
} ProtoHierTreeModel;

typedef struct {
	GObjectClass parent_class;

} ProtoHierTreeModelClass;

GType proto_hier_tree_get_type(void);
ProtoHierTreeModel *proto_hier_tree_model_new(void);

#endif /* __PROTO_HIER_TREE_MODEL_H__ */
