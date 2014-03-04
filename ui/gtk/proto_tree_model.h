/* proto_tree_model.h
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

#ifndef __PROTO_TREE_MODEL_H__
#define __PROTO_TREE_MODEL_H__

#include <glib.h>

#define PROTO_TYPE_TREE (proto_tree_model_get_type())

#define PROTO_TREE_MODEL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), PROTO_TYPE_TREE, ProtoTreeModel))
#define PROTO_IS_TREE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), PROTO_TYPE_TREE))

struct proto_tree_model;
typedef struct proto_tree_model ProtoTreeModel;

GType proto_tree_model_get_type(void);
ProtoTreeModel *proto_tree_model_new(proto_tree *protocol_tree, int display_hidden_proto_items);
void proto_tree_model_force_resolv(ProtoTreeModel *model, const e_addr_resolve *resolv_flags);

#endif /* __PROTO_TREE_MODEL_H__ */
