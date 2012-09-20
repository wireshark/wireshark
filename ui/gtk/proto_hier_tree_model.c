/* proto_hier_tree_model.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/* This code was originally based on the GTK+ Tree View tutorial at
 * http://scentric.net/tutorial */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>
#include <glib.h>

#include "proto_hier_tree_model.h"

#include <epan/proto.h>

static GObjectClass *parent_class = NULL;

static GtkTreeModelFlags
proto_hier_tree_get_flags(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), (GtkTreeModelFlags)0);

	return GTK_TREE_MODEL_ITERS_PERSIST;
}

static gint
proto_hier_tree_get_n_columns(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), 0);

	return 2;
}

static GType
proto_hier_tree_get_column_type(GtkTreeModel *tree_model, gint idx)
{
	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), G_TYPE_INVALID);
	g_return_val_if_fail(idx == 0 || idx == 1, G_TYPE_INVALID);

	switch (idx) {
		case 0:
			return G_TYPE_POINTER;
		case 1:
			return G_TYPE_STRING;
	}
	/* never here */
	return G_TYPE_INVALID;
}

static gboolean
proto_hier_tree_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent, gint n)
{
	ProtoHierTreeModel *model;

	gint proto_id;
	void *cookie;

	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), FALSE);
	model = (ProtoHierTreeModel *) tree_model;

	if (parent) {
		header_field_info *hfinfo;

		g_return_val_if_fail(parent->stamp == model->stamp, FALSE);

		/* no child of field */
		if (parent->user_data2 != NULL)
			return FALSE;

		proto_id = proto_get_data_protocol(parent->user_data);

		/* get n-th field of protocol */
		hfinfo = proto_get_first_protocol_field(proto_id, &cookie);
		while (hfinfo) {
			if (hfinfo->same_name_prev == NULL) {
				if (!n)
					break;
				n--;
			}
			hfinfo = proto_get_next_protocol_field(&cookie);
		}

		/* not found? */
		if (!hfinfo)
			return FALSE;

		iter->stamp = model->stamp;
		iter->user_data = parent->user_data;
		iter->user_data2 = cookie;
		iter->user_data3 = hfinfo;
		return TRUE;
	}

	/* get n-th enabled protocol */
	proto_id = proto_get_first_protocol(&cookie);
	while (proto_id != -1) {
		protocol_t *p = find_protocol_by_id(proto_id);

		if (proto_is_protocol_enabled(p)) {
			if (!n)
				break;
			n--;
		}
		proto_id = proto_get_next_protocol(&cookie);
	}

	/* not found? */
	if (proto_id == -1)
		return FALSE;

	iter->stamp = model->stamp;
	iter->user_data = cookie;
	iter->user_data2 = NULL;
	iter->user_data3 = proto_registrar_get_nth(proto_id);
	return TRUE;
}

static gboolean
proto_hier_tree_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreePath *path)
{
	gint *indices, depth;

	g_assert(PROTOHIER_IS_TREE(tree_model));
	g_assert(path != NULL);

	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	g_assert(depth == 1 || depth == 2);

	if (!proto_hier_tree_iter_nth_child(tree_model, iter, NULL, indices[0]))
		return FALSE;

	if (depth == 2) {
		if (!proto_hier_tree_iter_nth_child(tree_model, iter, iter, indices[1]))
			return FALSE;
	}
	return TRUE;
}

static char *
hfinfo_to_name(const header_field_info *hfinfo)
{
	if (hfinfo->parent == -1) {
		protocol_t *protocol = find_protocol_by_id(hfinfo->id);

		return g_strdup_printf("%s - %s", proto_get_protocol_short_name(protocol), proto_get_protocol_long_name(protocol));
	}
	if (hfinfo->blurb != NULL && hfinfo->blurb[0] != '\0')
		return g_strdup_printf("%s - %s (%s)", hfinfo->abbrev, hfinfo->name, hfinfo->blurb);
	else
		return g_strdup_printf("%s - %s", hfinfo->abbrev, hfinfo->name);
}

static void
proto_hier_tree_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter, gint column, GValue *value)
{
	ProtoHierTreeModel *model;
	header_field_info *hfinfo;

	g_return_if_fail(PROTOHIER_IS_TREE(tree_model));
	model = (ProtoHierTreeModel *) tree_model;

	g_return_if_fail(iter != NULL);
	g_return_if_fail(iter->stamp == model->stamp);
	g_return_if_fail(column == 0 || column == 1);

	hfinfo = iter->user_data3;

	switch (column) {
		case 0:	/* hfinfo */
			g_value_init(value, G_TYPE_POINTER);
			g_value_set_pointer(value, hfinfo);
			break;

		case 1:	/* field name */
			g_value_init(value, G_TYPE_STRING);
			g_value_take_string(value, hfinfo_to_name(hfinfo));
			break;
	}
}

static gboolean
proto_hier_tree_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoHierTreeModel *model;

	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), FALSE);
	model = (ProtoHierTreeModel *) tree_model;

	g_return_val_if_fail(iter->stamp == model->stamp, FALSE);

	/* protocol */
	if (iter->user_data2 == NULL) {
		void *cookie = iter->user_data;
		int proto_id;

		proto_id = proto_get_next_protocol(&cookie);
		/* get next enabled protocol */
		while (proto_id != -1) {
			protocol_t *p = find_protocol_by_id(proto_id);

			if (proto_is_protocol_enabled(p))
				break;
			proto_id = proto_get_next_protocol(&cookie);
		}

		if (proto_id == -1)
			return FALSE;

		iter->user_data = cookie;
		iter->user_data3 = proto_registrar_get_nth(proto_id);
		return TRUE;
	}

	/* field */
	{
		void *cookie2 = iter->user_data2;
		header_field_info *hfinfo;

		hfinfo = proto_get_next_protocol_field(&cookie2);
		/* get next field */
		while (hfinfo) {
			if (hfinfo->same_name_prev == NULL)
				break;
			hfinfo = proto_get_next_protocol_field(&cookie2);
		}

		/* not found? */
		if (!hfinfo)
			return FALSE;

		iter->user_data2 = cookie2;
		iter->user_data3 = hfinfo;
		return TRUE;
	}
}

static gboolean
proto_hier_tree_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *parent)
{
	return proto_hier_tree_iter_nth_child(tree_model, iter, parent, 0);
}

static gint
proto_hier_tree_iter_n_children(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoHierTreeModel *model;
	gint count = 0;

	int p_id;
	void *cookie;

	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), 0);
	model = (ProtoHierTreeModel *) tree_model;

	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, 0);

	if (iter) {
		header_field_info *hfinfo;

		g_return_val_if_fail(iter->stamp == model->stamp, 0);

		/* field has no child */
		if (iter->user_data2 != NULL)
			return 0;

		p_id = proto_get_data_protocol(iter->user_data);

		/* count not-duplicated fields */
		for (hfinfo = proto_get_first_protocol_field(p_id, &cookie); hfinfo; hfinfo = proto_get_next_protocol_field(&cookie)) {
			if (hfinfo->same_name_prev)
				continue;
			count++;
		}

	} else {
		/* count enabled protocols */
		for (p_id = proto_get_first_protocol(&cookie); p_id != -1; p_id = proto_get_next_protocol(&cookie)) {
			protocol_t *p = find_protocol_by_id(p_id);

			if (!proto_is_protocol_enabled(p))
				continue;
			count++;
		}
	}

	return count;
}

static GtkTreePath *
proto_hier_tree_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	ProtoHierTreeModel *model;
	GtkTreePath *path;
	int pos;

	int p_id;
	void *cookie;
	
	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), NULL);
	model = (ProtoHierTreeModel *) tree_model;

	g_return_val_if_fail(iter != NULL, NULL);
	g_return_val_if_fail(iter->stamp == model->stamp, FALSE);

	p_id = proto_get_data_protocol(iter->user_data);

	path = gtk_tree_path_new();

	/* protocol */
	{
		int id;

		/* XXX, assuming that protocols can't be disabled! */
		pos = 0;
		for (id = proto_get_first_protocol(&cookie); id != p_id && id != -1; id = proto_get_next_protocol(&cookie)) {
			protocol_t *p = find_protocol_by_id(id);

			if (!proto_is_protocol_enabled(p))
				continue;
			pos++;
		}
		gtk_tree_path_append_index(path, pos);
	}

	/* field */
	if (iter->user_data2 != NULL) {
		header_field_info *hfinfo;

		pos = 0;
		for (hfinfo = proto_get_first_protocol_field(p_id, &cookie); hfinfo && hfinfo != iter->user_data3; hfinfo = proto_get_next_protocol_field(&cookie)) {
			if (hfinfo->same_name_prev)
				continue;
			pos++;
		}
		gtk_tree_path_append_index(path, pos);
	}

	return path;
}

static gboolean
proto_hier_tree_iter_has_child(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	/* no need to optimize? */
	return proto_hier_tree_iter_n_children(tree_model, iter) != 0;
}

static gboolean
proto_hier_tree_iter_parent(GtkTreeModel *tree_model, GtkTreeIter *iter, GtkTreeIter *child)
{
	ProtoHierTreeModel *model;

	g_return_val_if_fail(PROTOHIER_IS_TREE(tree_model), FALSE);
	model = (ProtoHierTreeModel *) tree_model;

	g_return_val_if_fail(iter != NULL, FALSE);
	g_return_val_if_fail(child->stamp == model->stamp, FALSE);

	/* from field to protocol */
	if (child->user_data2 != NULL) {
		int p_id = proto_get_data_protocol(child->user_data);

		iter->stamp = model->stamp;
		iter->user_data = child->user_data;
		iter->user_data2 = NULL;
		iter->user_data3 = proto_registrar_get_nth(p_id);

		return TRUE;
	}
	/* protocol has no parent */
	return FALSE;
}

static void
proto_hier_tree_model_tree_init(GtkTreeModelIface *iface)
{
	iface->get_flags = proto_hier_tree_get_flags;
	iface->get_n_columns = proto_hier_tree_get_n_columns;
	iface->get_column_type = proto_hier_tree_get_column_type;
	iface->get_iter = proto_hier_tree_get_iter;
	iface->get_path = proto_hier_tree_get_path;
	iface->get_value = proto_hier_tree_get_value;
	iface->iter_next = proto_hier_tree_iter_next;
	iface->iter_children = proto_hier_tree_iter_children;
	iface->iter_has_child = proto_hier_tree_iter_has_child;
	iface->iter_n_children = proto_hier_tree_iter_n_children;
	iface->iter_nth_child = proto_hier_tree_iter_nth_child;
	iface->iter_parent = proto_hier_tree_iter_parent;
}

static void
proto_hier_tree_model_init(ProtoHierTreeModel *model)
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
proto_hier_tree_class_init(ProtoHierTreeModelClass *klass)
{
	GObjectClass *object_class;

	parent_class = (GObjectClass*) g_type_class_peek_parent(klass);
	object_class = (GObjectClass*) klass;

	object_class->finalize = _class_finalize;
}

GType 
proto_hier_tree_get_type(void)
{
	static GType proto_hier_tree_type = 0;

	if (proto_hier_tree_type == 0) {
		static const GTypeInfo proto_hier_tree_info = {
			sizeof(ProtoHierTreeModelClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc) proto_hier_tree_class_init,
			NULL, /* class finalize */
			NULL, /* class_data */
			sizeof(ProtoHierTreeModel),
			0, /* n_preallocs */
			(GInstanceInitFunc) proto_hier_tree_model_init,
			NULL /* value_table */
		};

		static const GInterfaceInfo tree_model_info = {
			(GInterfaceInitFunc) proto_hier_tree_model_tree_init,
			NULL,
			NULL
		};

		/* Register the new derived type with the GObject type system */
		proto_hier_tree_type = g_type_register_static(G_TYPE_OBJECT,
							  "ProtoHierTreeModel",
							  &proto_hier_tree_info,
							  (GTypeFlags)0);

		g_type_add_interface_static(proto_hier_tree_type,
						GTK_TYPE_TREE_MODEL,
						&tree_model_info);
	}
	return proto_hier_tree_type;
}

ProtoHierTreeModel *
proto_hier_tree_model_new(void)
{
	ProtoHierTreeModel *model;

	model = (ProtoHierTreeModel *) g_object_new(PROTOHIER_TYPE_TREE, NULL);

	g_assert(model != NULL);

	return model;
}

