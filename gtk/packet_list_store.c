/* packet_list_store.c
 * Routines to implement a custom GTK+ list model for Wireshark's packet list
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
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

/* This code is based on the GTK+ Tree View tutorial at http://scentric.net */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef NEW_PACKET_LIST

#include <string.h>

#include <gtk/gtk.h>
#include <glib.h>

#include "epan/column_info.h"
#include "epan/column.h"

#include "packet_list_store.h"
#include "globals.h"

static void packet_list_init(PacketList *pkg_tree);
static void packet_list_class_init(PacketListClass *klass);
static void packet_list_tree_model_init(GtkTreeModelIface *iface);
static void packet_list_finalize(GObject *object);
static GtkTreeModelFlags packet_list_get_flags(GtkTreeModel *tree_model);
static gint packet_list_get_n_columns(GtkTreeModel *tree_model);
static GType packet_list_get_column_type(GtkTreeModel *tree_model, gint index);
static gboolean packet_list_get_iter(GtkTreeModel *tree_model,
				     GtkTreeIter *iter, GtkTreePath *path);
static GtkTreePath *packet_list_get_path(GtkTreeModel *tree_model,
					 GtkTreeIter *iter);
static void packet_list_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter,
				  gint column, GValue *value);
static gboolean packet_list_iter_next(GtkTreeModel *tree_model,
				      GtkTreeIter *iter);
static gboolean packet_list_iter_children(GtkTreeModel *tree_model,
					  GtkTreeIter *iter,
					  GtkTreeIter *parent);
static gboolean packet_list_iter_has_child(GtkTreeModel *tree_model _U_,
					   GtkTreeIter *iter _U_);
static gint packet_list_iter_n_children(GtkTreeModel *tree_model,
					GtkTreeIter *iter);
static gboolean packet_list_iter_nth_child(GtkTreeModel *tree_model,
					   GtkTreeIter *iter,
					   GtkTreeIter *parent,
					   gint n);
static gboolean packet_list_iter_parent(GtkTreeModel *tree_model _U_,
					GtkTreeIter *iter _U_,
					GtkTreeIter *child _U_);

static gboolean packet_list_sortable_get_sort_column_id(GtkTreeSortable
							*sortable,
							gint *sort_col_id,
							GtkSortType *order);
static void packet_list_sortable_set_sort_column_id(GtkTreeSortable *sortable,
						    gint sort_col_id,
						    GtkSortType order);
static void packet_list_sortable_set_sort_func(GtkTreeSortable *sortable,
					       gint sort_col_id,
					       GtkTreeIterCompareFunc sort_func,
					       gpointer user_data,
					       GtkDestroyNotify destroy_func);
static void packet_list_sortable_set_default_sort_func(GtkTreeSortable
						       *sortable,
						       GtkTreeIterCompareFunc
						       sort_func,
						       gpointer user_data,
						       GtkDestroyNotify
						       destroy_func);
static gboolean packet_list_sortable_has_default_sort_func(GtkTreeSortable
							   *sortable);
static void packet_list_sortable_init(GtkTreeSortableIface *iface);
static gint packet_list_compare_records(gint sort_id _U_, PacketListRecord *a,
					PacketListRecord *b);
static gint packet_list_qsort_compare_func(PacketListRecord **a,
					   PacketListRecord **b,
					   PacketList *packet_list);
static void packet_list_resort(PacketList *packet_list);

static GObjectClass *parent_class = NULL;


GType
packet_list_get_type(void)
{
	static GType packet_list_type = 0;

	if(packet_list_type == 0) {
		static const GTypeInfo packet_list_info = {
			sizeof(PacketListClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc) packet_list_class_init,
			NULL, /* class finalize */
			NULL, /* class_data */
			sizeof(PacketList),
			0, /* n_preallocs */
			(GInstanceInitFunc) packet_list_init,
			NULL /* value_table */
		};

		static const GInterfaceInfo tree_model_info = {
			(GInterfaceInitFunc) packet_list_tree_model_init,
			NULL,
			NULL
		};

		static const GInterfaceInfo tree_sortable_info = {
				(GInterfaceInitFunc) packet_list_sortable_init,
				NULL,
				NULL
		};

		/* Register the new derived type with the GObject type system */
		packet_list_type = g_type_register_static(G_TYPE_OBJECT,
							  "PacketList",
							  &packet_list_info,
							  (GTypeFlags)0);

		g_type_add_interface_static(packet_list_type,
					    GTK_TYPE_TREE_MODEL,
					    &tree_model_info);
							  

		/* Register our GtkTreeModel interface with the type system */
		g_type_add_interface_static(packet_list_type,
					    GTK_TYPE_TREE_SORTABLE,
					    &tree_sortable_info);
	}

	return packet_list_type;
}

static void
packet_list_sortable_init(GtkTreeSortableIface *iface)
{
	iface->get_sort_column_id = packet_list_sortable_get_sort_column_id;
	iface->set_sort_column_id = packet_list_sortable_set_sort_column_id;
	/* The following three functions are not implemented */
	iface->set_sort_func = packet_list_sortable_set_sort_func;
	iface->set_default_sort_func =
		packet_list_sortable_set_default_sort_func;
	iface->has_default_sort_func =
		packet_list_sortable_has_default_sort_func;
}

static void
packet_list_class_init(PacketListClass *klass)
{
	GObjectClass *object_class;

	parent_class = (GObjectClass*) g_type_class_peek_parent(klass);
	object_class = (GObjectClass*) klass;

	object_class->finalize = packet_list_finalize;

	/* XXX this seems to affect TreeView Application wide
	 * Move to main.c ??? as it's not a bad thing(tm)
	 */
	gtk_rc_parse_string (
		"style \"PacketList-style\"\n"
		"{\n"
		"  GtkTreeView::horizontal-separator = 0\n"
		"} widget_class \"*TreeView*\""
		" style \"PacketList-style\"");

}

static void
packet_list_tree_model_init(GtkTreeModelIface *iface)
{
	iface->get_flags = packet_list_get_flags;
	iface->get_n_columns = packet_list_get_n_columns;
	iface->get_column_type = packet_list_get_column_type;
	iface->get_iter = packet_list_get_iter;
	iface->get_path = packet_list_get_path;
	iface->get_value = packet_list_get_value;
	iface->iter_next = packet_list_iter_next;
	iface->iter_children = packet_list_iter_children;
	iface->iter_has_child = packet_list_iter_has_child;
	iface->iter_n_children = packet_list_iter_n_children;
	iface->iter_nth_child = packet_list_iter_nth_child;
	iface->iter_parent = packet_list_iter_parent;
}

/* This is called every time a new packet list object instance is created in
 * packet_list_new.  Initialize the list structure's fields here. */
static void
packet_list_init(PacketList *packet_list)
{
	guint i;
	gint fmt;

	for(i = 0; i < (guint)cfile.cinfo.num_cols; i++) {
		/* Get the format of the column, see column_info.h */
		fmt = get_column_format(i);
		switch(fmt){
			/* if we wish to store data rater than strings for some
			 * colum types add case statements to the switch.
			 */
			case COL_NUMBER:
			default:
				packet_list->column_types[i] = G_TYPE_STRING;
				break;
		}
	}
	
	packet_list->n_columns = (guint)cfile.cinfo.num_cols;
	packet_list->num_rows = 0;
	packet_list->rows = NULL;

	packet_list->sort_id = 0; /* defaults to first column for now */
	packet_list->sort_order = GTK_SORT_ASCENDING;

	packet_list->stamp = g_random_int(); /* To check whether an iter belongs
					      * to our model. */
}

/* This function is called just before a packet list is destroyed.  Free
 * dynamically allocated memory here. */
static void
packet_list_finalize(GObject *object)
{
	/* PacketList *packet_list = PACKET_LIST(object); */

	/* XXX - Free all records and free all memory used by the list */

	/* must chain up - finalize parent */
	(* parent_class->finalize) (object);
}

static GtkTreeModelFlags
packet_list_get_flags(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model),
			     (GtkTreeModelFlags)0);

	return (GTK_TREE_MODEL_LIST_ONLY | GTK_TREE_MODEL_ITERS_PERSIST);
}

static gint
packet_list_get_n_columns(GtkTreeModel *tree_model)
{
	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), 0);

	return PACKET_LIST(tree_model)->n_columns;
}

static GType
packet_list_get_column_type(GtkTreeModel *tree_model, gint index)
{
	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), G_TYPE_INVALID);
	g_return_val_if_fail(index < PACKET_LIST(tree_model)->n_columns &&
			     index >= 0, G_TYPE_INVALID);

	return PACKET_LIST(tree_model)->column_types[index];
}

static gboolean
packet_list_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter,
		     GtkTreePath *path)
{
	PacketList *packet_list;
	PacketListRecord *record;
	gint *indices, depth;
	guint n;

	g_assert(PACKETLIST_IS_LIST(tree_model));
	g_assert(path != NULL);

	packet_list = PACKET_LIST(tree_model);

	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	/* we do not allow children since it's just a list */
	g_assert(depth == 1);

	n = indices[0]; /* the n-th top level row */

	if(n >= packet_list->num_rows)
		return FALSE;

	record = packet_list->rows[n];

	g_assert(record != NULL);
	g_assert(record->pos == n);

	/* We simply store a pointer to our custom record in the iter */
	iter->stamp = packet_list->stamp;
	iter->user_data = record;
	iter->user_data2 = NULL;
	iter->user_data3 = NULL;

	return TRUE;
}

static GtkTreePath *
packet_list_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	GtkTreePath *path;
	PacketListRecord *record;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), NULL);
	g_return_val_if_fail(iter != NULL, NULL);
	g_return_val_if_fail(iter->user_data != NULL, NULL);

	packet_list = PACKET_LIST(tree_model);

	record = (PacketListRecord*) iter->user_data;

	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, record->pos);

	return path;
}

static void
packet_list_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter, gint column,
		      GValue *value)
{
	PacketListRecord *record;
	PacketList *packet_list;
	GType type;

	g_return_if_fail(PACKETLIST_IS_LIST(tree_model));
	g_return_if_fail(iter != NULL);
	g_return_if_fail(column < PACKET_LIST(tree_model)->n_columns);

	type = PACKET_LIST(tree_model)->column_types[column];
	g_value_init(value, type);

	packet_list = PACKET_LIST(tree_model);

	record = (PacketListRecord*) iter->user_data;

	if(record->pos >= packet_list->num_rows)
		g_return_if_reached();

	/* XXX Probably the switch should be on column or 
	 * should we allways return the pointer and read the data as required??
	 * If we use FOREGROUND_COLOR_COL etc we'll need a couple of "internal" columns
	 */ 
	switch(type){
		case G_TYPE_POINTER:
			g_value_set_pointer(value, record);
			break;
		case G_TYPE_STRING:
			g_value_set_string(value, record->col_text[column]);
			break;
		default:
			g_warning ("%s: Unsupported type (%s) retrieved.", G_STRLOC, g_type_name (value->g_type));
			break;
	}
}

/* Takes an iter structure and sets it to point to the next row. */
static gboolean
packet_list_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	PacketListRecord *record, *nextrecord;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), FALSE);

	if(iter == NULL || iter->user_data == NULL)
		return FALSE;

	packet_list = PACKET_LIST(tree_model);

	record = (PacketListRecord*) iter->user_data;

	/* Is this the last record in the list? */
	if((record->pos + 1) >= packet_list->num_rows)
		return FALSE;

	nextrecord = packet_list->rows[(record->pos + 1)];

	g_assert(nextrecord != NULL);
	g_assert(nextrecord->pos == (record->pos + 1));

	iter->stamp = packet_list->stamp;
	iter->user_data = nextrecord;

	return TRUE;
}

static gboolean
packet_list_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter,
			  GtkTreeIter *parent)
{
	PacketList *packet_list;

	g_return_val_if_fail(parent == NULL || parent->user_data != NULL,
			     FALSE);

	/* This is a list, nodes have no children. */
	if(parent)
		return FALSE;

	/* parent == NULL is a special case; we need to return the first top-
	 * level row */

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), FALSE);

	packet_list = PACKET_LIST(tree_model);

	/* No rows => no first row */
	if(packet_list->num_rows == 0)
		return FALSE;

	/* Set iter to first item in list */
	iter->stamp = packet_list->stamp;
	iter->user_data = packet_list->rows[0];

	return TRUE;
}

static gboolean
packet_list_iter_has_child(GtkTreeModel *tree_model _U_, GtkTreeIter *iter _U_)
{
	return FALSE; /* Lists have no children */
}

static gint
packet_list_iter_n_children(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), -1);
	g_return_val_if_fail(iter == NULL || iter->user_data != NULL, FALSE);

	packet_list = PACKET_LIST(tree_model);

	/* special case: if iter == NULL, return number of top-level rows */
	if(!iter)
		return packet_list->num_rows;

	return 0; /* Lists have zero children */
}

static gboolean
packet_list_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter,
			   GtkTreeIter *parent, gint n)
{
	PacketListRecord *record;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), FALSE);

	packet_list = PACKET_LIST(tree_model);

	/* A list only has top-level rows */
	if(parent)
		return FALSE;

	/* Special case: if parent == NULL, set iter to n-th
	 * top-level row. */
	if((guint)n >= packet_list->num_rows)
		return FALSE;

	record = packet_list->rows[n];

	g_assert(record != NULL);
	g_assert(record->pos == (guint)n);

	iter->stamp = packet_list->stamp;
	iter->user_data = record;

	return TRUE;
}

static gboolean
packet_list_iter_parent(GtkTreeModel *tree_model _U_, GtkTreeIter *iter _U_,
			GtkTreeIter *child _U_)
{
	return FALSE; /* No parents since no children in a list */
}

PacketList *
new_packet_list_new(void)
{
	PacketList *newpacketlist;

	newpacketlist = (PacketList*) g_object_new(PACKETLIST_TYPE_LIST, NULL);

	g_assert(newpacketlist != NULL);

	return newpacketlist;
}

#if 0
static void
packet_list_row_deleted(PacketList *packet_list, guint pos)
{
	GtkTreePath *path;

	/* Inform the tree view and other interested objects (such as tree row
	 * references) that we have deleted a row */
	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, pos);

	gtk_tree_model_row_deleted(GTK_TREE_MODEL(packet_list), path);

	gtk_tree_path_free(path);
}
#endif

void
new_packet_list_store_clear(PacketList *packet_list)
{
	g_return_if_fail(packet_list != NULL);
	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	if(packet_list->num_rows == 0)
		return;

	/* Don't issue a row_deleted signal. We rely on our caller to have disconnected
	 * the model from the view.
	for( ; packet_list->num_rows > 0; --packet_list->num_rows)
		packet_list_row_deleted(packet_list, packet_list->num_rows-1);
	*/

	/* XXX - hold on to these rows and reuse them instead */
	g_free(packet_list->rows);
	packet_list->rows = NULL;
	packet_list->num_rows = 0;
}

#if 0
static void
packet_list_row_inserted(PacketList *packet_list, guint pos)
{
	GtkTreeIter iter;
	GtkTreePath *path;

	/* Inform the tree view and other interested objects (such as tree row
	 * references) that we have inserted a new row and where it was
	 * inserted. */
	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, pos);

	packet_list_get_iter(GTK_TREE_MODEL(packet_list), &iter, path);

	gtk_tree_model_row_inserted(GTK_TREE_MODEL(packet_list), path, &iter);

	gtk_tree_path_free(path);
}
#endif

void
packet_list_append_record(PacketList *packet_list, row_data_t *row_data)
{
	PacketListRecord *newrecord;
	guint pos;

	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	pos = packet_list->num_rows;

	packet_list->num_rows++;

 	packet_list->rows = g_renew(PacketListRecord*, packet_list->rows,
				    packet_list->num_rows);

	newrecord = se_alloc(sizeof(PacketListRecord));
	newrecord->col_text = row_data->col_text;
	newrecord->fdata = row_data->fdata;
	newrecord->pos = pos;

	packet_list->rows[pos] = newrecord;

	/* Don't issue a row_inserted signal. We rely on our caller to have disconnected
	 * the model from the view.
	 * packet_list_row_inserted(packet_list, newrecord->pos);
	 */

	/* Don't resort the list for every row, the list will be in packet order any way.
	 * packet_list_resort(packet_list);
	 */
}

static gboolean
packet_list_sortable_get_sort_column_id(GtkTreeSortable *sortable,
					gint *sort_col_id,
					GtkSortType *order)
{
	PacketList *packet_list;

	g_return_val_if_fail(sortable != NULL, FALSE);
	g_return_val_if_fail(PACKETLIST_IS_LIST(sortable), FALSE);

	packet_list = PACKET_LIST(sortable);

	if(sort_col_id)
		*sort_col_id = packet_list->sort_id;

	if(order)
		*order = packet_list->sort_order;

	return TRUE;
}

static void
packet_list_sortable_set_sort_column_id(GtkTreeSortable *sortable,
					gint sort_col_id,
					GtkSortType order)
{
	PacketList *packet_list;

	g_return_if_fail(sortable != NULL);
	g_return_if_fail(PACKETLIST_IS_LIST(sortable));

	packet_list = PACKET_LIST(sortable);

	if(packet_list->sort_id == sort_col_id &&
	   packet_list->sort_order == order)
		return;

	packet_list->sort_id = sort_col_id;
	packet_list->sort_order = order;

	packet_list_resort(packet_list);

	/* emit "sort-column-changed" signal to tell any tree views
	 * that the sort column has changed (so the little arrow
	 * in the column header of the sort column is drawn
	 * in the right column) */

	gtk_tree_sortable_sort_column_changed(sortable);
}

static void
packet_list_sortable_set_sort_func(GtkTreeSortable *sortable _U_,
				   gint sort_col_id _U_,
				   GtkTreeIterCompareFunc sort_func _U_,
				   gpointer user_data _U_,
				   GtkDestroyNotify destroy_func _U_)
{
	g_warning("%s is not supported by the PacketList model.\n",
		  __FUNCTION__);
}

static void
packet_list_sortable_set_default_sort_func(GtkTreeSortable *sortable _U_,
					   GtkTreeIterCompareFunc sort_func _U_,
					   gpointer user_data _U_,
					   GtkDestroyNotify destroy_func _U_)
{
	g_warning("%s is not supported by the PacketList model.\n",
		  __FUNCTION__);
}

static gboolean
packet_list_sortable_has_default_sort_func(GtkTreeSortable *sortable _U_)
{
	return FALSE; /* Since packet_list_sortable_set_sort_func and
			 set_default_sort_func are not implemented. */
}

static gint
packet_list_compare_records(gint sort_id, PacketListRecord *a,
			    PacketListRecord *b)
{

	/* XXX If we want to store other things than text, we need other sort functions */ 

	if (col_based_on_frame_data(&cfile.cinfo, sort_id))
		return frame_data_compare(a->fdata, b->fdata, cfile.cinfo.col_fmt[sort_id]);

	if((a->col_text[sort_id]) && (b->col_text[sort_id]))
		return strcmp(a->col_text[sort_id], b->col_text[sort_id]);

	if(a->col_text[sort_id] == b->col_text[sort_id])
		return 0; /* both are NULL */
	else
		return (a->col_text[sort_id] == NULL) ? -1 : 1;

	g_return_val_if_reached(0);
}		
static gint
packet_list_qsort_compare_func(PacketListRecord **a, PacketListRecord **b,
			       PacketList *packet_list)
{
	gint ret;

	g_assert((a) && (b) && (packet_list));

	ret = packet_list_compare_records(packet_list->sort_id, *a, *b);

	/* Swap -1 and 1 if sort order is reverse */
	if(ret != 0 && packet_list->sort_order == GTK_SORT_DESCENDING)
		ret = (ret < 0) ? 1 : -1;

	return ret;
}

static void
packet_list_resort(PacketList *packet_list)
{
	GtkTreePath *path;
	gint *neworder;
	guint i;

	g_return_if_fail(packet_list != NULL);
	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	if(packet_list->num_rows == 0)
		return;

	/* resort */
	g_qsort_with_data(packet_list->rows, packet_list->num_rows,
			  sizeof(PacketListRecord*),
			  (GCompareDataFunc) packet_list_qsort_compare_func,
			  packet_list);

	/* let other objects know about the new order */
	neworder = g_new0(gint, packet_list->num_rows);

	for(i = 0; i < packet_list->num_rows; ++i) {
		neworder[i] = (packet_list->rows[i])->pos;
		(packet_list->rows[i])->pos = i;
	}

	path = gtk_tree_path_new();

	gtk_tree_model_rows_reordered(GTK_TREE_MODEL(packet_list), path, NULL,
				      neworder);

	gtk_tree_path_free(path);
	g_free(neworder);
}

#endif /* NEW_PACKET_LIST */
