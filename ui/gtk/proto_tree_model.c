/* proto_tree_model.c
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

/* This code was originally based on the GTK+ Tree View tutorial at
 * http://scentric.net/tutorial */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/addr_resolv.h>
#include <epan/proto.h>

static GObjectClass *parent_class = NULL;

typedef struct {
	GObjectClass parent_class;

} ProtoTreeModelClass;

struct proto_tree_model {
	GObject parent; /** MUST be first */

	/** Random integer to check whether an iter belongs to our model. */
	gint stamp;

	proto_tree *protocol_tree;
	int with_hidden;

	gboolean resolv_forced;
	e_addr_resolve resolv_flags;
};

#include "proto_tree_model.h"

static GtkTreeModelFlags
proto_tree_model_get_flags(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PROTO_IS_TREE(tree_model), (GtkTreeModelFlags)0);

	return GTK_TREE_MODEL_ITERS_PERSIST;
}

static gint
proto_tree_model_get_n_columns(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PROTO_IS_TREE(tree_model), 0);

	return 2;
}

static GType
proto_tree_model_get_column_type(GtkTreeModel *tree_model, gint idx)
{
	g_return_val_if_fail(PROTO_IS_TREE(tree_model), G_TYPE_INVALID);
	g_return_val_if_fail(idx == 0 || idx == 1, G_TYPE_INVALID);

	switch (idx) {
		case 0:
			return G_TYPE_STRING;
		case 1:
			return G_TYPE_POINTER;
	}
	/* never here */
	return G_TYPE_INVALID;
}

static gboolean
proto_tree_model_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent, gint n)
{
	ProtoTreeModel *model;
	proto_node *node;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), FALSE);
	model = (ProtoTreeModel *) tree_model;

	if (parent) {
		g_return_val_if_fail(parent->stamp == model->stamp, FALSE);
		node = (proto_node *)parent->user_data;
	} else
		node = model->protocol_tree;

	if (!node)
		return FALSE;

	node = node->first_child;
	while (node != NULL) {
		if (model->with_hidden || !PROTO_ITEM_IS_HIDDEN(node)) {
			if (!n)
				break;
			n--;
		}
		node = node->next;
	}

	/* not found? */
	if (!node)
		return FALSE;

	iter->stamp = model->stamp;
	iter->user_data = node;
	return TRUE;
}

static gboolean
proto_tree_model_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreePath *path)
{
	gint *indices, depth;

	g_assert(PROTO_IS_TREE(tree_model));
	g_assert(path != NULL);

	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	g_return_val_if_fail(depth > 0, FALSE);

	if (!proto_tree_model_iter_nth_child(tree_model, iter, NULL, indices[0]))
		return FALSE;

	while (--depth) {
		indices++;
		if (!proto_tree_model_iter_nth_child(tree_model, iter, iter, *indices))
			return FALSE;
	}
	return TRUE;
}

static char *
fi_get_string(field_info *fi)
{
	gchar         label_str[ITEM_LABEL_LENGTH];
	gchar        *label_ptr;

	if (!fi->rep) {
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	} else
		label_ptr = fi->rep->representation;

	if (FI_GET_FLAG(fi, FI_GENERATED)) {
		if (FI_GET_FLAG(fi, FI_HIDDEN))
			label_ptr = g_strdup_printf("<[%s]>", label_ptr);
		else
			label_ptr = g_strdup_printf("[%s]", label_ptr);

	} else if (FI_GET_FLAG(fi, FI_HIDDEN))
		label_ptr = g_strdup_printf("<%s>", label_ptr);
	else
		label_ptr = g_strdup(label_ptr);

	return label_ptr;
}

static void
proto_tree_model_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter, gint column, GValue *value)
{
	ProtoTreeModel *model;
	proto_node *node;
	field_info *fi;

	g_return_if_fail(PROTO_IS_TREE(tree_model));
	model = (ProtoTreeModel *) tree_model;

	g_return_if_fail(iter != NULL);
	g_return_if_fail(iter->stamp == model->stamp);
	g_return_if_fail(column == 0 || column == 1);

	node = (proto_node *)iter->user_data;
	fi = PNODE_FINFO(node);

	/* dissection with an invisible proto tree? */
	g_assert(fi);

	switch (column) {
		case 0:
		{
			g_value_init(value, G_TYPE_STRING);
			if (model->resolv_forced) {
				e_addr_resolve old_flags = gbl_resolv_flags;

				gbl_resolv_flags = model->resolv_flags;
				g_value_take_string(value, fi_get_string(fi));
				gbl_resolv_flags = old_flags;

			} else
				g_value_take_string(value, fi_get_string(fi));
			break;
		}

		case 1:
			g_value_init(value, G_TYPE_POINTER);
			g_value_set_pointer(value, fi);
			break;
	}
}

static gboolean
proto_tree_model_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoTreeModel *model;
	proto_node *current;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), FALSE);
	model = (ProtoTreeModel *) tree_model;

	g_return_val_if_fail(iter->stamp == model->stamp, FALSE);

	current = (proto_node *)iter->user_data;
	current = current->next;
	while (current) {
		if (model->with_hidden || !PROTO_ITEM_IS_HIDDEN(current)) {
			iter->user_data = current;
			return TRUE;
		}
		current = current->next;
	}
	return FALSE;
}

static gboolean
proto_tree_model_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent)
{
	return proto_tree_model_iter_nth_child(tree_model, iter, parent, 0);
}

static gint
proto_tree_model_iter_n_children(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoTreeModel *model;
	proto_node *node;
	gint count;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), 0);
	model = (ProtoTreeModel *) tree_model;

	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, 0);

	if (iter) {
		g_return_val_if_fail(iter->stamp == model->stamp, 0);
		node = (proto_node *)iter->user_data;
	} else
		node = model->protocol_tree;

	if (!node)
		return 0;

	count = 0;
	node = node->first_child;
	while (node != NULL) {
		if (model->with_hidden || !PROTO_ITEM_IS_HIDDEN(node))
			count++;
		node = node->next;
	}
	return count;
}

static GtkTreePath *
proto_tree_model_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoTreeModel *model;
	GtkTreePath *path;
	proto_node *node;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), NULL);
	model = (ProtoTreeModel *) tree_model;

	g_return_val_if_fail(iter != NULL, NULL);
	g_return_val_if_fail(iter->stamp == model->stamp, NULL);

	node = (proto_node *)iter->user_data;
	g_return_val_if_fail(node != model->protocol_tree, NULL);

	path = gtk_tree_path_new();
	do {
		proto_node *cur = node;
		proto_node *node_i;
		int pos;

		node = node->parent;

		pos = 0;
		for (node_i = node->first_child; node_i; node_i = node_i->next) {
			if (model->with_hidden || !PROTO_ITEM_IS_HIDDEN(node_i)) {
				if (node_i == cur)
					break;
				pos++;
			}
		}

		g_assert(node_i != NULL);
		gtk_tree_path_prepend_index(path, pos);
	} while (node != model->protocol_tree);

	return path;
}

static gboolean
proto_tree_model_iter_has_child(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	/* optimized version of:
	 *    return proto_tree_model_iter_n_children(tree_model, iter) != 0;
	 * synchronize when changed!
	 */
	ProtoTreeModel *model;
	proto_node *node;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), FALSE);
	model = (ProtoTreeModel *) tree_model;

	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, FALSE);

	if (iter) {
		g_return_val_if_fail(iter->stamp == model->stamp, FALSE);
		node = (proto_node *)iter->user_data;
	} else
		node = model->protocol_tree;

	if (!node)
		return FALSE;

	node = node->first_child;
	while (node != NULL) {
		if (model->with_hidden || !PROTO_ITEM_IS_HIDDEN(node))
			return TRUE;
		node = node->next;
	}
	return FALSE;
}

static gboolean
proto_tree_model_iter_parent(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *child)
{
	ProtoTreeModel *model;
	proto_node *node;

	g_return_val_if_fail(PROTO_IS_TREE(tree_model), FALSE);
	model = (ProtoTreeModel *) tree_model;

	g_return_val_if_fail(iter != NULL, FALSE);
	g_return_val_if_fail(child->stamp == model->stamp, FALSE);

	node = (proto_node *)child->user_data;
	if (node->parent == model->protocol_tree)
		return FALSE;
	g_return_val_if_fail(node->parent != NULL, FALSE);
	iter->stamp = model->stamp;
	iter->user_data = node->parent;
	return TRUE;
}

static void
proto_tree_model_tree_init(GtkTreeModelIface *iface)
{
	iface->get_flags = proto_tree_model_get_flags;
	iface->get_n_columns = proto_tree_model_get_n_columns;
	iface->get_column_type = proto_tree_model_get_column_type;
	iface->get_iter = proto_tree_model_get_iter;
	iface->get_path = proto_tree_model_get_path;
	iface->get_value = proto_tree_model_get_value;
	iface->iter_next = proto_tree_model_iter_next;
	iface->iter_children = proto_tree_model_iter_children;
	iface->iter_has_child = proto_tree_model_iter_has_child;
	iface->iter_n_children = proto_tree_model_iter_n_children;
	iface->iter_nth_child = proto_tree_model_iter_nth_child;
	iface->iter_parent = proto_tree_model_iter_parent;
}

static void
proto_tree_model_init(ProtoTreeModel *model)
{
	/* To check whether an iter belongs to our model. */
	model->stamp = g_random_int();
}

static void
_class_finalize(GObject *object)
{
	/* must chain up - finalize parent */
	(*parent_class->finalize)(object);
}

static void
proto_tree_model_class_init(ProtoTreeModelClass *klass)
{
	GObjectClass *object_class;

	parent_class = (GObjectClass*) g_type_class_peek_parent(klass);
	object_class = (GObjectClass*) klass;

	object_class->finalize = _class_finalize;
}

GType
proto_tree_model_get_type(void)
{
	static GType proto_tree_type = 0;

	if (proto_tree_type == 0) {
		static const GTypeInfo proto_tree_info = {
			sizeof(ProtoTreeModelClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc) proto_tree_model_class_init,
			NULL, /* class finalize */
			NULL, /* class_data */
			sizeof(ProtoTreeModel),
			0, /* n_preallocs */
			(GInstanceInitFunc) proto_tree_model_init,
			NULL /* value_table */
		};

		static const GInterfaceInfo tree_model_info = {
			(GInterfaceInitFunc) proto_tree_model_tree_init,
			NULL,
			NULL
		};

		/* Register the new derived type with the GObject type system */
		proto_tree_type = g_type_register_static(G_TYPE_OBJECT,
							  "ProtoTreeModel",
							  &proto_tree_info,
							  (GTypeFlags)0);

		g_type_add_interface_static(proto_tree_type,
						GTK_TYPE_TREE_MODEL,
						&tree_model_info);
	}
	return proto_tree_type;
}

void
proto_tree_model_force_resolv(ProtoTreeModel *model, const e_addr_resolve *flags)
{
	model->resolv_forced = TRUE;
	model->resolv_flags  = *flags;
}

ProtoTreeModel *
proto_tree_model_new(proto_tree *protocol_tree, int display_hidden_proto_items)
{
	ProtoTreeModel *model;

	model = (ProtoTreeModel *) g_object_new(PROTO_TYPE_TREE, NULL);

	g_assert(model != NULL);
	model->protocol_tree = protocol_tree;
	model->with_hidden   = display_hidden_proto_items;
	model->resolv_forced = FALSE;

	return model;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
