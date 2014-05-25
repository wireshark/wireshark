/* packet_list_store.c
 * Routines to implement a custom GTK+ list model for Wireshark's packet list
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 * * Co-authors Anders Broman and Kovarththanan Rajaratnam.
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

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>
#include <glib.h>

#include "packet_list_store.h"

#include "ui/progress_dlg.h"
#include "ui/ui_util.h"

#include "ui/gtk/old-gtk-compat.h"

#include <epan/epan_dissect.h>
#include <epan/column-info.h>
#include <epan/column.h>

#include "color.h"
#include "color_filters.h"
#include "frame_tvbuff.h"

#include "globals.h"

/* #define PACKET_PARANOID_CHECKS */

/** PacketListRecord: represents a row */
typedef struct _PacketListRecord {
	/** The column text for some columns */
	const gchar **col_text;
	/**< The length of the column text strings in 'col_text' */
	gushort *col_text_len;

	frame_data *fdata;

	/* admin stuff used by the custom list model */
#ifdef PACKET_PARANOID_CHECKS
	/** position within the physical array */
	guint physical_pos;
#endif
	/** position within the visible array */
	gint visible_pos;

	/** Has this record been colorized? */
	guint colorized : 1;

} PacketListRecord;

static void packet_list_init(PacketList *pkg_tree);
static void packet_list_class_init(PacketListClass *klass);
static void packet_list_tree_model_init(GtkTreeModelIface *iface);
static void packet_list_finalize(GObject *object);
static GtkTreeModelFlags packet_list_get_flags(GtkTreeModel *tree_model);
static gint packet_list_get_n_columns(GtkTreeModel *tree_model);
static GType packet_list_get_column_type(GtkTreeModel *tree_model, gint idx);
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
						   GDestroyNotify destroy_func);
static void packet_list_sortable_set_default_sort_func(GtkTreeSortable
							   *sortable,
							   GtkTreeIterCompareFunc
							   sort_func,
							   gpointer user_data,
							   GDestroyNotify
							   destroy_func);
static gboolean packet_list_sortable_has_default_sort_func(GtkTreeSortable
							   *sortable);
static void packet_list_sortable_init(GtkTreeSortableIface *iface);
static void packet_list_resort(PacketList *packet_list);
static void packet_list_dissect_and_cache_record(PacketList *packet_list, PacketListRecord *record, gboolean dissect_color );

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

#if !GTK_CHECK_VERSION(3,0,0)
	/* XXX this seems to affect TreeView Application wide
	 * Move to main.c ??? as it's not a bad thing(tm)
	 */
	gtk_rc_parse_string (
		"style \"PacketList-style\"\n"
		"{\n"
		"  GtkTreeView::horizontal-separator = 0\n"
		"  GtkTreeView::vertical-separator = 1\n"
		"} widget_class \"*TreeView*\""
		" style \"PacketList-style\"");
#endif

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
	gint i, j;

	/* To check whether an iter belongs to our model. */
	packet_list->stamp = g_random_int();

	packet_list->n_cols = cfile.cinfo.num_cols;
	packet_list->physical_rows = g_ptr_array_new();
	packet_list->visible_rows = g_ptr_array_new();

	packet_list->columnized = FALSE;
	packet_list->sort_id = 0; /* defaults to first column for now */
	packet_list->sort_order = GTK_SORT_ASCENDING;

	packet_list->col_to_text = g_new(int, packet_list->n_cols);
	for (i = 0, j = 0; i < packet_list->n_cols; i++) {
		if (!col_based_on_frame_data(&cfile.cinfo, i)) {
			packet_list->col_to_text[i] = j;
			j++;
		} else
			packet_list->col_to_text[i] = -1;
	}
	packet_list->n_text_cols = j;

#ifdef PACKET_LIST_STATISTICS
	packet_list->const_strings = 0;
#endif
}

/* This function is called just before a packet list is destroyed.	Free
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

	return (GtkTreeModelFlags)(GTK_TREE_MODEL_LIST_ONLY | GTK_TREE_MODEL_ITERS_PERSIST);
}

static gint
packet_list_get_n_columns(GtkTreeModel *tree_model)
{
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), 0);
	packet_list = (PacketList *) tree_model;

	/* Note: We need one extra column to store the entire frame_data */
	return packet_list->n_cols + 1;
}

static GType
packet_list_get_column_type(GtkTreeModel *tree_model, gint idx)
{
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), G_TYPE_INVALID);
	packet_list = (PacketList *) tree_model;

	/* Note: We use one extra column to store the entire frame_data */
	g_return_val_if_fail(idx >= 0 && idx < packet_list->n_cols + 1, G_TYPE_INVALID);

	if (idx >= 0 && idx < packet_list->n_cols)
		return G_TYPE_STRING;
	else if (idx == packet_list->n_cols)
		return G_TYPE_POINTER;
	else
		return G_TYPE_INVALID;
}

static gboolean
packet_list_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter,
			 GtkTreePath *path)
{
	gint *indices, depth;

	g_assert(PACKETLIST_IS_LIST(tree_model));

	g_assert(path != NULL);

	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	/* we do not allow children since it's just a list */
	g_assert(depth == 1);

	return packet_list_iter_nth_child(tree_model, iter, NULL, indices[0]);
}

static GtkTreePath *
packet_list_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	GtkTreePath *path;
	PacketListRecord *record;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), NULL);
	packet_list = (PacketList *) tree_model;

	g_return_val_if_fail(iter != NULL, NULL);
	g_return_val_if_fail(iter->stamp == packet_list->stamp, NULL);
	g_return_val_if_fail(iter->user_data != NULL, NULL);

	record = (PacketListRecord*) iter->user_data;

	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, record->visible_pos);

	return path;
}

static void
packet_list_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter, gint column,
			  GValue *value)
{
	PacketListRecord *record;
	PacketList *packet_list;

	g_return_if_fail(PACKETLIST_IS_LIST(tree_model));
	packet_list = (PacketList *) tree_model;

	g_return_if_fail(iter != NULL);
	g_return_if_fail(iter->stamp == packet_list->stamp);
	g_return_if_fail(iter->user_data != NULL);

	/* Note: We use one extra column to store the entire frame_data */
	g_return_if_fail(column >= 0 && column < packet_list->n_cols + 1);

	record = (PacketListRecord*) iter->user_data;

#ifdef PACKET_PARANOID_CHECKS
	g_return_if_fail(PACKET_LIST_RECORD_INDEX_VALID(packet_list->physical_rows, record->physical_pos));
#endif
	g_return_if_fail(PACKET_LIST_RECORD_INDEX_VALID(packet_list->visible_rows, record->visible_pos));

	if (column >= 0 && column < packet_list->n_cols) {
		int text_column;

		g_value_init(value, G_TYPE_STRING);

		if (record->col_text == NULL || !record->colorized)
			packet_list_dissect_and_cache_record(packet_list, record, !record->colorized);

		text_column = packet_list->col_to_text[column];
		if (text_column == -1) { /* column based on frame_data */
			col_fill_in_frame_data(record->fdata, &cfile.cinfo, column, FALSE);
			g_value_set_string(value, cfile.cinfo.col_data[column]);
		} else {
			g_return_if_fail(record->col_text);
			g_value_set_string(value, record->col_text[text_column]);
		}

	} else if (column == packet_list->n_cols) {
		g_value_init(value, G_TYPE_POINTER);
		g_value_set_pointer(value, record->fdata);
	}
}

static PacketListRecord *
packet_list_iter_next_visible(PacketList *packet_list, PacketListRecord *record)
{
	PacketListRecord *nextrecord;
	gint next_visible_pos;

	g_assert(record->visible_pos >= 0);
	next_visible_pos = record->visible_pos + 1;

	/* Is this the last record in the list? */
	if(!PACKET_LIST_RECORD_INDEX_VALID(packet_list->visible_rows, next_visible_pos))
		return NULL;

	nextrecord = PACKET_LIST_RECORD_GET(packet_list->visible_rows, next_visible_pos);

	g_assert(nextrecord->visible_pos == (record->visible_pos + 1));
#ifdef PACKET_PARANOID_CHECKS
	g_assert(nextrecord->physical_pos >= (record->physical_pos + 1));
#endif

	return nextrecord;
}

/* Takes an iter structure and sets it to point to the next row. */
static gboolean
packet_list_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter)
{
	PacketListRecord *record, *nextrecord;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), FALSE);
	packet_list = (PacketList *) tree_model;

	if(iter == NULL)
		return FALSE;

	g_return_val_if_fail(iter->stamp == packet_list->stamp, FALSE);
	g_return_val_if_fail(iter->user_data, FALSE);

	record = (PacketListRecord*) iter->user_data;
	nextrecord = packet_list_iter_next_visible(packet_list, record);

	if (!nextrecord)
		return FALSE;

	/* iter->stamp = packet_list->stamp; */
	iter->user_data = nextrecord;

	return TRUE;
}

static gboolean
packet_list_iter_children(GtkTreeModel *tree_model, GtkTreeIter *iter,
			  GtkTreeIter *parent)
{
	return packet_list_iter_nth_child(tree_model, iter, parent, 0);
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

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), 0);
	packet_list = (PacketList *) tree_model;

	if(!iter) {
		/* special case: if iter == NULL, return number of top-level rows */
		return PACKET_LIST_RECORD_COUNT(packet_list->visible_rows);
	}
	else {
		g_return_val_if_fail(iter->stamp == packet_list->stamp, 0);
		g_return_val_if_fail(iter->user_data, 0);
		/* Lists have zero children */
		return 0;
	}
}

static gboolean
packet_list_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter,
			   GtkTreeIter *parent, gint n)
{
	PacketListRecord *record;
	PacketList *packet_list;

	g_return_val_if_fail(PACKETLIST_IS_LIST(tree_model), FALSE);
	packet_list = (PacketList *) tree_model;

	/* A list only has top-level rows */
	if(parent) {
		g_return_val_if_fail(parent->stamp == packet_list->stamp, FALSE);
		g_return_val_if_fail(parent->user_data, FALSE);
		return FALSE;
	}

	/* Special case: if parent == NULL, set iter to n-th top-level row. */
	if(!PACKET_LIST_RECORD_INDEX_VALID(packet_list->visible_rows, n))
		return FALSE;

	record = PACKET_LIST_RECORD_GET(packet_list->visible_rows, n);

	g_assert(record->visible_pos == n);

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
packet_list_new(void)
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
packet_list_store_clear(PacketList *packet_list)
{
	g_return_if_fail(packet_list != NULL);
	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	/* Don't issue a row_deleted signal. We rely on our caller to have disconnected
	 * the model from the view.
	for( ; packet_list->num_rows > 0; --packet_list->num_rows)
		packet_list_row_deleted(packet_list, packet_list->num_rows-1);
	*/

	/* XXX - hold on to these rows and reuse them instead */
	if(packet_list->physical_rows)
		g_ptr_array_free(packet_list->physical_rows, TRUE);
	if(packet_list->visible_rows)
		g_ptr_array_free(packet_list->visible_rows, TRUE);
	packet_list->physical_rows = g_ptr_array_new();
	packet_list->visible_rows = g_ptr_array_new();

	packet_list->columnized = FALSE;

	/* Generate new number */
	packet_list->stamp = g_random_int();

#ifdef PACKET_LIST_STATISTICS
	g_warning("Const strings: %u", packet_list->const_strings);
	packet_list->const_strings = 0;
#endif
}

gint
packet_list_append_record(PacketList *packet_list, frame_data *fdata)
{
	PacketListRecord *newrecord;

	g_return_val_if_fail(PACKETLIST_IS_LIST(packet_list), -1);

	newrecord = se_new(PacketListRecord);
	newrecord->colorized    = FALSE;
	newrecord->col_text_len = NULL;
	newrecord->col_text     = NULL;
	newrecord->fdata        = fdata;
#ifdef PACKET_PARANOID_CHECKS
	newrecord->physical_pos = PACKET_LIST_RECORD_COUNT(packet_list->physical_rows);
#endif

	if (fdata->flags.passed_dfilter || fdata->flags.ref_time) {
		newrecord->visible_pos = PACKET_LIST_RECORD_COUNT(packet_list->visible_rows);
		PACKET_LIST_RECORD_APPEND(packet_list->visible_rows, newrecord);
	}
	else
		newrecord->visible_pos = -1;

	PACKET_LIST_RECORD_APPEND(packet_list->physical_rows, newrecord);

	packet_list->columnized = FALSE;   /* XXX, dissect? */

	/*
	 * Issue a row_inserted signal if the model is connected
	 * and the row is visible.
	 */
	if (gtk_tree_view_get_model(GTK_TREE_VIEW(packet_list->view)) && newrecord->visible_pos != -1) {
		GtkTreeIter iter;
		GtkTreePath *path;

		path = gtk_tree_path_new();
		gtk_tree_path_append_index(path, newrecord->visible_pos);

		iter.stamp = packet_list->stamp;
		iter.user_data = newrecord;

		gtk_tree_model_row_inserted(GTK_TREE_MODEL(packet_list), path, &iter);
		gtk_tree_path_free(path);
	}

	/* XXXX If the model is connected and sort column != frame_num we should
	 * probably resort.
	 * Don't resort the list for every row, the list will be in packet order any way.
	 * packet_list_resort(packet_list);
	 */

	return newrecord->visible_pos;
}

static void
packet_list_change_record(PacketList *packet_list, PacketListRecord *record, gint col, column_info *cinfo)
{
	gchar *str;
	size_t col_text_len;
	int text_col;

	text_col = packet_list->col_to_text[col];

	/* Column based on frame_data or it already contains a value */
	if (text_col == -1 || record->col_text[text_col] != NULL)
		return;

	switch (cfile.cinfo.col_fmt[col]) {
		case COL_DEF_SRC:
		case COL_RES_SRC:	/* COL_DEF_SRC is currently just like COL_RES_SRC */
		case COL_UNRES_SRC:
		case COL_DEF_DL_SRC:
		case COL_RES_DL_SRC:
		case COL_UNRES_DL_SRC:
		case COL_DEF_NET_SRC:
		case COL_RES_NET_SRC:
		case COL_UNRES_NET_SRC:
		case COL_DEF_DST:
		case COL_RES_DST:	/* COL_DEF_DST is currently just like COL_RES_DST */
		case COL_UNRES_DST:
		case COL_DEF_DL_DST:
		case COL_RES_DL_DST:
		case COL_UNRES_DL_DST:
		case COL_DEF_NET_DST:
		case COL_RES_NET_DST:
		case COL_UNRES_NET_DST:
		case COL_PROTOCOL:
		case COL_INFO:
		case COL_IF_DIR:
		case COL_DCE_CALL:
		case COL_8021Q_VLAN_ID:
		case COL_EXPERT:
		case COL_FREQ_CHAN:
			if (cinfo->col_data[col] && cinfo->col_data[col] != cinfo->col_buf[col]) {
				col_text_len = strlen(cinfo->col_data[col]);
				if (col_text_len > G_MAXUSHORT)
					col_text_len = G_MAXUSHORT;

				/* This is a constant string, so we don't have to copy it */
				record->col_text[text_col] = (gchar *) cinfo->col_data[col];
				record->col_text_len[text_col] = (gushort) col_text_len;
#ifdef PACKET_LIST_STATISTICS
				++packet_list->const_strings;
#endif
				break;
			}
		/* !! FALL-THROUGH!! */

		default:
			if(cinfo->col_data[col]){
				col_text_len = strlen(cinfo->col_data[col]);
				if (col_text_len > G_MAXUSHORT)
					col_text_len = G_MAXUSHORT;

				record->col_text_len[text_col] = (gushort) col_text_len;
			}
			if (!record->col_text_len[text_col]) {
				record->col_text[text_col] = "";
#ifdef PACKET_LIST_STATISTICS
				++packet_list->const_strings;
#endif
				break;
			}

			if(!packet_list->string_pool)
				packet_list->string_pool = g_string_chunk_new(32);
			if (!get_column_resolved (col) && cinfo->col_expr.col_expr_val[col]) {
				/* Use the unresolved value in col_expr_val */
				str = g_string_chunk_insert_const (packet_list->string_pool, (const gchar *)cinfo->col_expr.col_expr_val[col]);
			} else {
				str = g_string_chunk_insert_const (packet_list->string_pool, (const gchar *)cinfo->col_data[col]);
			}
			record->col_text[text_col] = str;
			break;
	}
}

static gboolean
packet_list_sortable_get_sort_column_id(GtkTreeSortable *sortable,
					gint *sort_col_id,
					GtkSortType *order)
{
	PacketList *packet_list;

	g_return_val_if_fail(sortable != NULL, FALSE);
	g_return_val_if_fail(PACKETLIST_IS_LIST(sortable), FALSE);

	packet_list = (PacketList *) sortable;

	if(sort_col_id)
		*sort_col_id = packet_list->sort_id;

	if(order)
		*order = packet_list->sort_order;

	return TRUE;
}

static gboolean
packet_list_column_contains_values(PacketList *packet_list, gint sort_col_id)
{
	if (packet_list->columnized || col_based_on_frame_data(&cfile.cinfo, sort_col_id))
		return TRUE;
	else
		return FALSE;
}

/* packet_list_dissect_and_cache_all()
 *  returns:
 *   TRUE   if columnization completed;
 *            packet_list->columnized set to TRUE;
 *   FALSE: columnization did not complete (i.e., was stopped by the user);
 *            packet_list->columnized unchanged (i.e., FALSE).
 */

static gboolean
packet_list_dissect_and_cache_all(PacketList *packet_list)
{
	PacketListRecord *record;

	int 		progbar_nextstep;
	int 		progbar_quantum;
	gboolean	progbar_stop_flag;
	GTimeVal	progbar_start_time;
	float		progbar_val;
	progdlg_t  *progbar = NULL;
	gchar		progbar_status_str[100];
	gint		progbar_loop_max;
	gint		progbar_loop_var;
	gint		progbar_updates = 100 /* 100% */;

	g_assert(packet_list->columnized == FALSE);

	progbar_loop_max = PACKET_LIST_RECORD_COUNT(packet_list->physical_rows);
	/* Update the progress bar when it gets to this value. */
	progbar_nextstep = 0;
	/* When we reach the value that triggers a progress bar update,
	   bump that value by this amount. */
	progbar_quantum = progbar_loop_max/progbar_updates;
	/* Progress so far. */
	progbar_val = 0.0f;

	progbar_stop_flag = FALSE;
	g_get_current_time(&progbar_start_time);

	main_window_update();

	for (progbar_loop_var = 0; progbar_loop_var < progbar_loop_max; ++progbar_loop_var) {
		record = PACKET_LIST_RECORD_GET(packet_list->physical_rows, progbar_loop_var);
		packet_list_dissect_and_cache_record(packet_list, record, FALSE);

		/* Create the progress bar if necessary.
		   We check on every iteration of the loop, so that it takes no
		   longer than the standard time to create it (otherwise, for a
		   large file, we might take considerably longer than that standard
		   time in order to get to the next progress bar step). */
		if (progbar == NULL)
			/* Note: The following may call gtk_main_iteration() which will */
			/*       allow certain "interupts" to happen during this code.  */
			/*       (Note that the progress_dlg window is set to "modal"   */
			/*        so that clicking on other windows is disabled).       */
			progbar = delayed_create_progress_dlg(gtk_widget_get_window(packet_list->view),
							      "Construct", "Columns",
							      TRUE, &progbar_stop_flag,
							      &progbar_start_time, progbar_val);

		if (progbar_loop_var >= progbar_nextstep) {
			/* let's not divide by zero. We should never be started
			 * with count == 0, so let's assert that */
			g_assert(progbar_loop_max > 0);

			progbar_val = (gfloat) progbar_loop_var / progbar_loop_max;

			if (progbar != NULL) {
				g_snprintf(progbar_status_str, sizeof(progbar_status_str),
					   "%u of %u frames", progbar_loop_var+1, progbar_loop_max);
				/* Note: See comment above re use of gtk_main_iteration() */
				update_progress_dlg(progbar, progbar_val, progbar_status_str);
			}

			progbar_nextstep += progbar_quantum;
		}

		if (progbar_stop_flag) {
			/* Well, the user decided to abort ... */
			break;
		}
	}

	/* We're done; destroy the progress bar if it was created. */
	if (progbar != NULL)
		destroy_progress_dlg(progbar);

	if (progbar_stop_flag) {
		return FALSE; /* user aborted before columnization completed */
	}

	packet_list->columnized = TRUE;
	return TRUE;
}

/* packet_list_do_packet_list_dissect_and_cache_all()
 *  returns:
 *    TRUE:  if columnization not needed or columnization completed;
 *    FALSE: columnization did not complete (i.e., stopped by the user)
 */
gboolean
packet_list_do_packet_list_dissect_and_cache_all(PacketList *packet_list, gint sort_col_id)
{
	if (!packet_list_column_contains_values(packet_list, sort_col_id)) {
		return packet_list_dissect_and_cache_all(packet_list);
	}
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

	packet_list = (PacketList *) sortable;

	if(packet_list->sort_id == sort_col_id &&
	   packet_list->sort_order == order)
		return;

	packet_list->sort_id = sort_col_id;
	packet_list->sort_order = order;

	if(PACKET_LIST_RECORD_COUNT(packet_list->physical_rows) == 0)
		return;

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
				   GDestroyNotify destroy_func _U_)
{
	g_warning(G_STRLOC ": is not supported by the PacketList model.\n");
}

static void
packet_list_sortable_set_default_sort_func(GtkTreeSortable *sortable _U_,
					   GtkTreeIterCompareFunc sort_func _U_,
					   gpointer user_data _U_,
					   GDestroyNotify destroy_func _U_)
{
	g_warning(G_STRLOC ": is not supported by the PacketList model.\n");
}

static gboolean
packet_list_sortable_has_default_sort_func(GtkTreeSortable *sortable _U_)
{
	return FALSE; /* Since packet_list_sortable_set_sort_func and
			 set_default_sort_func are not implemented. */
}

static gint
packet_list_compare_custom(gint sort_id, gint text_sort_id, PacketListRecord *a, PacketListRecord *b)
{
	header_field_info *hfi;

	hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[sort_id]);

	if (hfi == NULL) {
		return frame_data_compare(cfile.epan, a->fdata, b->fdata, COL_NUMBER);
	} else if ((hfi->strings == NULL) &&
		   (((IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)) &&
		     ((hfi->display == BASE_DEC) || (hfi->display == BASE_DEC_HEX) ||
		      (hfi->display == BASE_OCT))) ||
		    (hfi->type == FT_DOUBLE) || (hfi->type == FT_FLOAT) ||
		    (hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
		    (hfi->type == FT_RELATIVE_TIME)))
	  {
		/* Attempt to convert to numbers */
		double num_a = atof(a->col_text[text_sort_id]);
		double num_b = atof(b->col_text[text_sort_id]);

		if (num_a < num_b)
			return -1;
		else if (num_a > num_b)
			return 1;
		else
			return 0;
	  }

	return strcmp(a->col_text[text_sort_id], b->col_text[text_sort_id]);
}

static gint
_packet_list_compare_records(gint sort_id, gint text_sort_id, PacketListRecord *a, PacketListRecord *b)
{
	g_assert(a->col_text);
	g_assert(b->col_text);
	g_assert(a->col_text[text_sort_id]);
	g_assert(b->col_text[text_sort_id]);

	if(a->col_text[text_sort_id] == b->col_text[text_sort_id])
		return 0; /* no need to call strcmp() */

	if (cfile.cinfo.col_fmt[sort_id] == COL_CUSTOM)
		return packet_list_compare_custom(sort_id, text_sort_id, a, b);

	return strcmp(a->col_text[text_sort_id], b->col_text[text_sort_id]);
}

static gint
packet_list_compare_records(gint sort_id, gint text_sort_id, PacketListRecord *a, PacketListRecord *b)
{
	gint ret;

	if (text_sort_id == -1)	/* based on frame_data ? */
		return frame_data_compare(cfile.epan, a->fdata, b->fdata, cfile.cinfo.col_fmt[sort_id]);

	ret = _packet_list_compare_records(sort_id, text_sort_id, a, b);
	if (ret == 0)
		ret = frame_data_compare(cfile.epan, a->fdata, b->fdata, COL_NUMBER);
	return ret;
}

static gint
packet_list_qsort_physical_compare_func(PacketListRecord **a, PacketListRecord **b,
				   PacketList *packet_list)
{
	gint ret;
	gint sort_id = packet_list->sort_id;

	g_assert((a) && (b) && (packet_list));

	ret = packet_list_compare_records(sort_id, packet_list->col_to_text[sort_id], *a, *b);

	/* Swap -1 and 1 if sort order is reverse */
	if(ret != 0 && packet_list->sort_order == GTK_SORT_DESCENDING)
		ret = (ret < 0) ? 1 : -1;

	return ret;
}

static void
packet_list_resort(PacketList *packet_list)
{
	PacketListRecord *record;
	GtkTreePath *path;
	gint *neworder;
	guint phy_idx;
	guint vis_idx;

	g_return_if_fail(packet_list != NULL);
	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	if(PACKET_LIST_RECORD_COUNT(packet_list->visible_rows) == 0)
		return;

	/* resort physical rows according to sorting column */
	g_ptr_array_sort_with_data(packet_list->physical_rows,
			  (GCompareDataFunc) packet_list_qsort_physical_compare_func,
			  packet_list);

	/* let other objects know about the new order */
	neworder = g_new0(gint, PACKET_LIST_RECORD_COUNT(packet_list->visible_rows));

	for(phy_idx = 0, vis_idx = 0; phy_idx < PACKET_LIST_RECORD_COUNT(packet_list->physical_rows); ++phy_idx) {
		record = PACKET_LIST_RECORD_GET(packet_list->physical_rows, phy_idx);
#ifdef PACKET_PARANOID_CHECKS
		record->physical_pos = phy_idx;
#endif
		g_assert(record->visible_pos >= -1);
		if (record->visible_pos >= 0) {
			g_assert(record->fdata->flags.passed_dfilter || record->fdata->flags.ref_time);
			neworder[vis_idx] = record->visible_pos;
			PACKET_LIST_RECORD_SET(packet_list->visible_rows, vis_idx, record);
			record->visible_pos = vis_idx;
			++vis_idx;
		}
	}

	g_assert(vis_idx == PACKET_LIST_RECORD_COUNT(packet_list->visible_rows));

	path = gtk_tree_path_new();

	gtk_tree_model_rows_reordered(GTK_TREE_MODEL(packet_list), path, NULL,
					  neworder);

	gtk_tree_path_free(path);
	g_free(neworder);
}

guint
packet_list_recreate_visible_rows_list(PacketList *packet_list)
{
	guint phy_idx;
	guint vis_idx;
	PacketListRecord *record;

	g_return_val_if_fail(packet_list != NULL, 0);
	g_return_val_if_fail(PACKETLIST_IS_LIST(packet_list), 0);

	if(PACKET_LIST_RECORD_COUNT(packet_list->physical_rows) == 0)
		return 0;

	if(packet_list->visible_rows)
		g_ptr_array_free(packet_list->visible_rows, TRUE);

	packet_list->visible_rows = g_ptr_array_new();

	for(phy_idx = 0, vis_idx = 0; phy_idx < PACKET_LIST_RECORD_COUNT(packet_list->physical_rows); ++phy_idx) {
		record = PACKET_LIST_RECORD_GET(packet_list->physical_rows, phy_idx);
		if (record->fdata->flags.passed_dfilter || record->fdata->flags.ref_time) {
			record->visible_pos = vis_idx++;
			PACKET_LIST_RECORD_APPEND(packet_list->visible_rows, record);
		}
		else
			record->visible_pos = -1;
	}

	return vis_idx;
}

static void
packet_list_dissect_and_cache_record(PacketList *packet_list, PacketListRecord *record, gboolean dissect_color)
{
	epan_dissect_t edt;
	frame_data *fdata;
	column_info *cinfo;
	gint col;
	gboolean create_proto_tree;
	struct wtap_pkthdr phdr; /* Packet header */
	Buffer buf; /* Packet data */
	gboolean dissect_columns = (record->col_text == NULL);

	g_return_if_fail(packet_list);
	g_return_if_fail(PACKETLIST_IS_LIST(packet_list));

	memset(&phdr, 0, sizeof(struct wtap_pkthdr));

	fdata = record->fdata;

	if (dissect_columns) {
		cinfo = &cfile.cinfo;

		record->col_text     = (const gchar **)se_alloc0(sizeof(*record->col_text) * packet_list->n_text_cols);
		record->col_text_len = (gushort *)se_alloc0(sizeof(*record->col_text_len) * packet_list->n_text_cols);
	} else
		cinfo = NULL;

	buffer_init(&buf, 1500);
	if (!cf_read_record_r(&cfile, fdata, &phdr, &buf)) {
		/*
		 * Error reading the record.
		 *
		 * Don't set the color filter for now (we might want
		 * to colorize it in some fashion to warn that the
		 * row couldn't be filled in or colorized), and
		 * set the columns to placeholder values, except
		 * for the Info column, where we'll put in an
		 * error message.
		 */
		if (dissect_columns) {
			col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);

			for(col = 0; col < cinfo->num_cols; ++col)
				packet_list_change_record(packet_list, record, col, cinfo);
		}
		if (dissect_color) {
			fdata->color_filter = NULL;
			record->colorized = TRUE;
		}
		buffer_free(&buf);
		return;	/* error reading the record */
	}

	create_proto_tree = (dissect_color && color_filters_used()) ||
						(dissect_columns && have_custom_cols(cinfo));

	epan_dissect_init(&edt, cfile.epan,
					  create_proto_tree,
					  FALSE /* proto_tree_visible */);

	if (dissect_color)
		color_filters_prime_edt(&edt);
	if (dissect_columns)
		col_custom_prime_edt(&edt, cinfo);

	/*
	 * XXX - need to catch an OutOfMemoryError exception and
	 * attempt to recover from it.
	 */
	epan_dissect_run(&edt, cfile.cd_t, &phdr, frame_tvbuff_new_buffer(fdata, &buf), fdata, cinfo);

	if (dissect_color)
		fdata->color_filter = color_filters_colorize_packet(&edt);

	if (dissect_columns) {
		/* "Stringify" non frame_data vals */
		epan_dissect_fill_in_columns(&edt, FALSE, FALSE /* fill_fd_columns */);

		for(col = 0; col < cinfo->num_cols; ++col)
			packet_list_change_record(packet_list, record, col, cinfo);
	}

	if (dissect_color)
		record->colorized = TRUE;

	epan_dissect_cleanup(&edt);
	buffer_free(&buf);
}

void
packet_list_reset_colorized(PacketList *packet_list)
{
	PacketListRecord *record;
	guint i;

	for(i = 0; i < PACKET_LIST_RECORD_COUNT(packet_list->physical_rows); ++i) {
		record = PACKET_LIST_RECORD_GET(packet_list->physical_rows, i);
		record->colorized = FALSE;
	}
}

const char*
packet_list_get_widest_column_string(PacketList *packet_list, gint col)
{
	int text_col;

	g_return_val_if_fail(packet_list != NULL, NULL);
	g_return_val_if_fail(PACKETLIST_IS_LIST(packet_list), NULL);
	/* We need real column here, so not packet_list->n_cols+1 */
	g_return_val_if_fail(col >= 0 && col < packet_list->n_cols, NULL);

	if (PACKET_LIST_RECORD_COUNT(packet_list->visible_rows) == 0)
		return "";

	text_col = packet_list->col_to_text[col];

	if (text_col == -1) {	/* column based on frame data */
		PacketListRecord *record;
		guint vis_idx;

		guint widest_packet = 0;
		gint widest_column_len = -1;

		for(vis_idx = 0; vis_idx < PACKET_LIST_RECORD_COUNT(packet_list->visible_rows); ++vis_idx) {
			gint column_len;

			record = PACKET_LIST_RECORD_GET(packet_list->visible_rows, vis_idx);

			col_fill_in_frame_data(record->fdata, &cfile.cinfo, col, FALSE);
			column_len = (gint) strlen(cfile.cinfo.col_buf[col]);
			if (column_len > widest_column_len) {
				widest_column_len = column_len;
				widest_packet = vis_idx;
			}
		}

		if (widest_column_len != -1) {
			record = PACKET_LIST_RECORD_GET(packet_list->visible_rows, widest_packet);
			col_fill_in_frame_data(record->fdata, &cfile.cinfo, col, FALSE);

			return cfile.cinfo.col_buf[col];
		} else
			return "";
	}
	else {
		PacketListRecord *record;
		guint vis_idx;

		const gchar *widest_column_str = NULL;
		guint widest_column_len = 0;

		if (!packet_list->columnized)
			packet_list_dissect_and_cache_all(packet_list); /* XXX: need to handle case of "incomplete" ? */

		for(vis_idx = 0; vis_idx < PACKET_LIST_RECORD_COUNT(packet_list->visible_rows); ++vis_idx) {
			record = PACKET_LIST_RECORD_GET(packet_list->visible_rows, vis_idx);
			if (record->col_text_len[text_col] > widest_column_len) {
				widest_column_str = record->col_text[text_col];
				widest_column_len = record->col_text_len[text_col];
			}
		}

		return widest_column_str;
	}
}
