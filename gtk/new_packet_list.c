/* new_packet_list.c
 * Routines to implement a new GTK2 packet list using our custom model
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 * Co-authors Anders Broman and Kovarththanan Rajaratnam.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef NEW_PACKET_LIST

#ifdef HAVE_STRING_H
#include "string.h"
#endif

#include <stdio.h>
#include <gtk/gtk.h>
#include <glib.h>

#include "gui_utils.h"
#include "packet_list_store.h"
#include "gtk/new_packet_list.h"
#include "epan/column_info.h"
#include "epan/prefs.h"
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include "../ui_util.h"
#include "../progress_dlg.h"
#include "../simple_dialog.h"
#include "epan/emem.h"
#include "globals.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "gtk/packet_history.h"
#include "epan/column.h"
#include "gtk/recent.h"
#include "gtk/keys.h"
#include "gtk/menus.h"
#include "color.h"
#include "color_filters.h"
#include "gtk/color_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/main_statusbar.h"
#include "gtk/packet_win.h"

static PacketList *packetlist;
static gboolean last_at_end = FALSE;
static gboolean enable_color;

static GtkWidget *create_view_and_model(void);
static void scroll_to_and_select_iter(GtkTreeModel *model, GtkTreeSelection *selection, GtkTreeIter *iter);
static void new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_);
static void new_packet_list_double_click_cb(GtkTreeView *treeview,
					    GtkTreePath *path,
					    GtkTreeViewColumn *col _U_,
					    gpointer userdata _U_);
static void show_cell_data_func(GtkTreeViewColumn *col,
				GtkCellRenderer *renderer,
				GtkTreeModel *model,
				GtkTreeIter *iter,
				gpointer data);
static guint row_number_from_iter(GtkTreeIter *iter);

GtkWidget *
new_packet_list_create(void)
{
	GtkWidget *view, *scrollwin;

	scrollwin = scrolled_window_new(NULL, NULL);

	view = create_view_and_model();

	gtk_container_add(GTK_CONTAINER(scrollwin), view);

	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, view);

	return scrollwin;
}

guint
new_packet_list_append(column_info *cinfo _U_, frame_data *fdata, packet_info *pinfo _U_)
{
	/* fdata should be filled with the stuff we need
	 * strings are built at display time.
	 */

	/* Return the _visible_ position */
	return packet_list_append_record(packetlist, fdata);
}

static gboolean
right_justify_column (gint col)
{
	header_field_info *hfi;
	gboolean right_justify = FALSE;

	switch (cfile.cinfo.col_fmt[col]) {

	case COL_NUMBER:
	case COL_PACKET_LENGTH:
	case COL_CUMULATIVE_BYTES:
		right_justify = TRUE;
		break;

	case COL_CUSTOM:
		hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[col]);
		/* Check if this is a valid field and we have no strings lookup table */
		if ((hfi != NULL) && (hfi->strings == NULL)) {
			/* Check for bool, framenum and decimal/octal integer types */
			if ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
				(((hfi->display == BASE_DEC) || (hfi->display == BASE_OCT)) &&
				 (IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)))) {
				right_justify = TRUE;
			}
		}
		break;

	default:
		break;
	}

	return right_justify;
}

static GtkWidget *
create_view_and_model(void)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	PangoLayout *layout;
	gint i, col_width;

	packetlist = new_packet_list_new();

	packetlist->view = tree_view_new(GTK_TREE_MODEL(packetlist));

#if GTK_CHECK_VERSION(2,6,0)
	gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(packetlist->view),
						TRUE);
#endif
	g_signal_connect(packetlist->view, "cursor-changed",
			 G_CALLBACK(new_packet_list_select_cb), NULL);
	g_signal_connect(packetlist->view, "row-activated",
			 G_CALLBACK(new_packet_list_double_click_cb),
			 g_object_get_data(G_OBJECT(popup_menu_object),
					   PM_PACKET_LIST_KEY));
	g_signal_connect(packetlist->view, "button_press_event", G_CALLBACK(popup_menu_handler),
				   g_object_get_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, packetlist);

	/*		g_object_unref(packetlist); */ /* Destroy automatically with view for now */ /* XXX - Messes up freezing & thawing */

	gtk_widget_modify_font(packetlist->view, user_font_get_regular());


	/* We need one extra column to store the entire PacketListRecord */
	for(i = 0; i < cfile.cinfo.num_cols; i++) {
		renderer = gtk_cell_renderer_text_new();
		if (right_justify_column (i)) {
			g_object_set(G_OBJECT(renderer),
				"xalign",
				1.0,
				NULL);
		}
		g_object_set(renderer,
				 "ypad", 0,
				 NULL);
		col = gtk_tree_view_column_new();
		gtk_tree_view_column_pack_start(col, renderer, TRUE);
		gtk_tree_view_column_set_cell_data_func(col, renderer,
							show_cell_data_func,
							GINT_TO_POINTER(i),
							NULL);
		gtk_tree_view_column_set_title(col, cfile.cinfo.col_title[i]);
		gtk_tree_view_column_set_sort_column_id(col, i);
		gtk_tree_view_column_set_resizable(col, TRUE);
		gtk_tree_view_column_set_sizing(col,GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_reorderable(col, TRUE); /* XXX - Should this be saved in the prefs? */

		/* The column can't be adjusted to a size smaller than this
		 * XXX Should we use a different value for different column formats?
		 */
		gtk_tree_view_column_set_min_width(col, 40);

		/* Set the size the column will be displayed with */
		col_width = recent_get_column_width(i);
		if(col_width < 1) {
			gint fmt;
			const gchar *long_str;

			fmt = get_column_format(i);
			long_str = get_column_width_string(fmt, i);
			layout = gtk_widget_create_pango_layout(packetlist->view, long_str);
			/*  the logical width and height of a PangoLayout in device units */
			pango_layout_get_pixel_size(layout,
				&col_width, /* width */
				NULL); /* height */
			if (col_width < 1){
				g_warning("*** Error: A column width of %u passed to gtk_tree_view_column_set_fixed_width()\n"
					"column %u Long string  %s format %u",col_width,i,long_str, fmt );
			}
			gtk_tree_view_column_set_fixed_width(col, col_width);
			g_object_unref(G_OBJECT(layout));
		}else{
			gtk_tree_view_column_set_fixed_width(col, col_width);
		}
		gtk_tree_view_append_column(GTK_TREE_VIEW(packetlist->view), col);
	}

	return packetlist->view;
}

static PacketListRecord *
new_packet_list_get_record(GtkTreeModel *model, GtkTreeIter *iter)
{
	PacketListRecord *record;
	/* The last column is reserved for the entire PacketListRecord */
	gint record_column = gtk_tree_model_get_n_columns(model)-1;

	gtk_tree_model_get(model, iter,
			   record_column,
			   &record,
			   -1);

	return record;
}

void
new_packet_list_clear(void)
{
	packet_history_clear();

	new_packet_list_store_clear(packetlist);
	gtk_widget_queue_draw(packetlist->view);
}

void
new_packet_list_freeze(void)
{
	/* So we don't lose the model by the time we want to thaw it */
	g_object_ref(packetlist);

	/* Detach view from model */
	gtk_tree_view_set_model(GTK_TREE_VIEW(packetlist->view), NULL);
}

void
new_packet_list_thaw(void)
{
	/* Apply model */
	gtk_tree_view_set_model( GTK_TREE_VIEW(packetlist->view), GTK_TREE_MODEL(packetlist));

	/* Remove extra reference added by new_packet_list_freeze() */
	g_object_unref(packetlist);

	packets_bar_update();
}

void
new_packet_list_recreate_visible_rows(void)
{

	packet_list_recreate_visible_rows(packetlist);

}

void new_packet_list_resize_column(gint col)
{
	PangoLayout *layout;
	GtkTreeViewColumn *column;
	gint col_width;

	column = gtk_tree_view_get_column (GTK_TREE_VIEW(packetlist->view), col);
	layout = gtk_widget_create_pango_layout(packetlist->view,
										  packet_list_get_widest_column_string(packetlist, col));
	pango_layout_get_pixel_size(layout, &col_width, NULL);
	gtk_tree_view_column_set_fixed_width(column, col_width);
	g_object_unref(G_OBJECT(layout));
}

static void
new_packet_list_resize_columns(void)
{
	gint		progbar_loop_max;
	gint		progbar_loop_var;

	progbar_loop_max = cfile.cinfo.num_cols;

	for (progbar_loop_var = 0; progbar_loop_var < progbar_loop_max; ++progbar_loop_var)
		new_packet_list_resize_column(progbar_loop_var);
}

void
new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	new_packet_list_resize_columns();
}

void
new_packet_list_next(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkWidget *focus = gtk_window_get_focus(GTK_WINDOW(top_level));

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	if (!gtk_tree_selection_get_selected(selection, &model, &iter))
		return;

	if (!gtk_tree_model_iter_next(model, &iter))
		return;

	scroll_to_and_select_iter(model, selection, &iter);

	/* Set the focus back where it was */
	if (focus)
		gtk_window_set_focus(GTK_WINDOW(top_level), focus);
}

void
new_packet_list_prev(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkWidget *focus = gtk_window_get_focus(GTK_WINDOW(top_level));

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	if (!gtk_tree_selection_get_selected(selection, &model, &iter))
		return;

	path = gtk_tree_model_get_path(model, &iter);

	if (!gtk_tree_path_prev(path))
		return;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	scroll_to_and_select_iter(model, selection, &iter);

	gtk_tree_path_free(path);

	/* Set the focus back where it was */
	if (focus)
		gtk_window_set_focus(GTK_WINDOW(top_level), focus);
}

static void
scroll_to_and_select_iter(GtkTreeModel *model, GtkTreeSelection *selection, GtkTreeIter *iter)
{
	GtkTreePath *path;

	g_assert(model);

	/* Select the row */
	if(!selection)
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, iter);
	path = gtk_tree_model_get_path(model, iter);
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			TRUE,	/* use_align */
			0.5,	/* row_align determines where the row is placed, 0.5 means center */
			0); 	/* The horizontal alignment of the column */
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);

	gtk_tree_path_free(path);
}

void
new_packet_list_select_first_row(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;

	if(!gtk_tree_model_get_iter_first(model, &iter))
		return;

	scroll_to_and_select_iter(model, NULL, &iter);
}

void
new_packet_list_select_last_row(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	gint children;
	guint last_row;

	if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
		return;

	last_row = children-1;
	if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
		return;

	scroll_to_and_select_iter(model, NULL, &iter);
}

void
new_packet_list_moveto_end(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GtkTreePath *path;
	gint children;
	guint last_row;

	if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
		return;

	last_row = children-1;
	if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
		return;

	path = gtk_tree_model_get_path(model, &iter);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));

	if (!gtk_tree_selection_path_is_selected(selection, path)) {
		/* XXX - this doesn't seem to work, i.e. gtk_tree_selection_path_is_selected() is always false? */
		gtk_tree_selection_select_path(selection, path);
		gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
				path,
				NULL,
				TRUE,	/* use_align */
				0.5,	/* row_align determines where the row is placed, 0.5 means center */
				0); 	/* The horizontal alignment of the column */
	}

	gtk_tree_path_free(path);
}

gboolean
new_packet_list_check_end(void)
{
	gboolean at_end = FALSE;
	GtkAdjustment *adj;

	adj = gtk_tree_view_get_vadjustment(GTK_TREE_VIEW(packetlist->view));
	g_return_val_if_fail(adj != NULL, FALSE);

	if (adj->value >= adj->upper - adj->page_size) {
		at_end = TRUE;
	}
#ifdef HAVE_LIBPCAP
	if (adj->value > 0 && at_end != last_at_end && at_end != auto_scroll_live) {
		menu_auto_scroll_live_changed(at_end);
	}
#endif
	last_at_end = at_end;
	return at_end;
}

gint
new_packet_list_find_row_from_data(gpointer data, gboolean select)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	frame_data *fdata_needle = data;

	/* Initializes iter with the first iterator in the tree (the one at the path "0")
	 * and returns TRUE. Returns FALSE if the tree is empty
	 */
	if(!gtk_tree_model_get_iter_first(model, &iter))
		return -1;

	do {
		PacketListRecord *record;
		frame_data *fdata;

		record = new_packet_list_get_record(model, &iter);
		fdata = record->fdata;

		if(fdata == fdata_needle) {
			if(select)
				scroll_to_and_select_iter(model, NULL, &iter);

			return fdata->num;
		}
	} while (gtk_tree_model_iter_next(model, &iter));

	return -1;
}

void
new_packet_list_set_selected_row(gint row)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GtkTreePath *path;

	path = gtk_tree_path_new_from_indices(row-1, -1);

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	/* Select the row */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, &iter);
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);

	gtk_tree_path_free(path);
}

static guint
row_number_from_iter(GtkTreeIter *iter)
{
	guint row;
	gint *indices;
	GtkTreePath *path;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	path = gtk_tree_model_get_path(model, iter);
	indices = gtk_tree_path_get_indices(path);
	g_assert(indices);
	/* Indices start from 0, but rows start from 1. Hence +1 */
	row = indices[0] + 1;

	gtk_tree_path_free(path);

	return row;
}

static void
new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;

	selection = gtk_tree_view_get_selection(tree_view);
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
		return;

	/* Remove the hex display tab pages */
	while(gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0))
		gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

	row = row_number_from_iter(&iter);

	cf_select_packet(&cfile, row);
	gtk_widget_grab_focus(packetlist->view);

	/* Add newly selected frame to packet history (breadcrumbs) */
	packet_history_add(row);
}

static void
new_packet_list_double_click_cb(GtkTreeView *treeview, GtkTreePath *path _U_,
    GtkTreeViewColumn *col _U_, gpointer userdata _U_)
{
        new_window_cb(GTK_WIDGET(treeview));
}

gboolean
new_packet_list_get_event_row_column(GdkEventButton *event_button,
								 gint *physical_row, gint *row, gint *column)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreePath *path;
	GtkTreeViewColumn *view_column;

	if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(packetlist->view),
									  (gint) event_button->x,
									  (gint) event_button->y,
									  &path, &view_column, NULL, NULL)) {
		GtkTreeIter iter;
		GList *cols;
		gint *indices;
		PacketListRecord *record;

		/* Fetch indices */
		gtk_tree_model_get_iter(model, &iter, path);
		indices = gtk_tree_path_get_indices(path);
		g_assert(indices);
		/* Indices start from 0. Hence +1 */
		*row = indices[0] + 1;
		gtk_tree_path_free(path);

		/* Fetch physical row */
		record = new_packet_list_get_record(model, &iter);
		*physical_row = record->fdata->num;

		/* Fetch column */
		/* XXX -doesn't work if columns are re-arranged? */
		cols = gtk_tree_view_get_columns(GTK_TREE_VIEW(packetlist->view));
		*column = g_list_index(cols, (gpointer) view_column);
		g_list_free(cols);

		return TRUE;
	}
	else
		return FALSE;
}

frame_data *
new_packet_list_get_row_data(gint row)
{
	GtkTreePath *path = gtk_tree_path_new();
	GtkTreeIter iter;
	PacketListRecord *record;

	gtk_tree_path_append_index(path, row-1);
	gtk_tree_model_get_iter(GTK_TREE_MODEL(packetlist), &iter, path);

	record = new_packet_list_get_record(GTK_TREE_MODEL(packetlist), &iter);

	gtk_tree_path_free(path);

	return record->fdata;
}

static void
show_cell_data_func(GtkTreeViewColumn *col _U_, GtkCellRenderer *renderer,
			GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	guint col_num = GPOINTER_TO_INT(data);
	frame_data *fdata;
	const gchar *cell_text;
	PacketListRecord *record;

	record = new_packet_list_get_record(model, iter);
	fdata = record->fdata;

	if (!record->columnized || !record->colorized) {
		packet_list_dissect_and_cache_iter(packetlist, iter,
									  !record->columnized,
									  !record->colorized);
	}

	g_assert(fdata->col_text);

	if (col_based_on_frame_data(&cfile.cinfo, col_num)) {
		col_fill_in_frame_data(fdata, &cfile.cinfo, col_num, FALSE);
		cell_text = cfile.cinfo.col_data[col_num];
	}else
		cell_text = fdata->col_text[col_num];

	g_assert(cell_text);

	if((fdata->color_filter)||(fdata->flags.marked)){
		gboolean color_on = enable_color;
		GdkColor fg_gdk;
		GdkColor bg_gdk;
		if(fdata->flags.marked){
			color_t_to_gdkcolor(&fg_gdk, &prefs.gui_marked_fg);
			color_t_to_gdkcolor(&bg_gdk, &prefs.gui_marked_bg);
			color_on = TRUE;
		}else{
			color_t fg_color_t;
			color_t bg_color_t;
			color_filter_t *color_filter = fdata->color_filter;

			fg_color_t = color_filter->fg_color;
			bg_color_t = color_filter->bg_color;
			color_t_to_gdkcolor(&fg_gdk, &fg_color_t);
			color_t_to_gdkcolor(&bg_gdk, &bg_color_t);
		}
		g_object_set(renderer,
			 "text", cell_text,
			 "foreground-gdk", &fg_gdk,
			 "foreground-set", color_on,
			 "background-gdk", &bg_gdk,
			 "background-set", color_on,
			 NULL);
	}else{
		g_object_set(renderer,
			 "text", cell_text,
			 "foreground-set", FALSE,
			 "background-set", FALSE,
			 NULL);
	}
}

void
new_packet_list_enable_color(gboolean enable)
{
	enable_color = enable;
	gtk_widget_queue_draw (packetlist->view);
}

void
new_packet_list_queue_draw(void)
{
	gtk_widget_queue_draw (packetlist->view);
}

/* call this after last set_frame_mark is done */
static void mark_frames_ready(void)
{
	file_save_update_dynamics();
	packets_bar_update();
}

static void
set_frame_mark(gboolean set, frame_data *fdata)
{
	if (set)
		cf_mark_frame(&cfile, fdata);
	else
		cf_unmark_frame(&cfile, fdata);
}

static void mark_all_frames(gboolean set)
{
	frame_data *fdata;

	/* XXX: we might need a progressbar here */
	for (fdata = cfile.plist_start; fdata != NULL; fdata = fdata->next) {
		set_frame_mark(set, fdata);
	}
	mark_frames_ready();
	new_packet_list_queue_draw();
}

void new_packet_list_mark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	mark_all_frames(TRUE);
}

void new_packet_list_unmark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	mark_all_frames(FALSE);
}

void
new_packet_list_set_font(PangoFontDescription *font)
{
	gtk_widget_modify_font(packetlist->view, font);
}

void new_packet_list_mark_frame_cb(GtkWidget *w _U_, gpointer data _U_)
{
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	PacketListRecord *record;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	gtk_tree_selection_get_selected(selection, &model, &iter);
	record = new_packet_list_get_record(model, &iter);

	set_frame_mark(!record->fdata->flags.marked, record->fdata);
	mark_frames_ready();
}

static gboolean
get_col_text_from_record( PacketListRecord *record, gint col_num, gchar** cell_text){

	if (col_based_on_frame_data(&cfile.cinfo, col_num)) {
		col_fill_in_frame_data(record->fdata, &cfile.cinfo, col_num, FALSE);
		*cell_text = g_strdup(cfile.cinfo.col_data[col_num]);
	}else
		*cell_text = g_strdup(record->fdata->col_text[col_num]);

	return TRUE;
}
/* XXX fore some reason this does not work in th .h file XXX*/
/* Different modes of copying summary data */
typedef enum {
	CS_TEXT, /* Packet summary data (tab separated) */
	CS_CSV	 /* Packet summary data (comma separated) */
} copy_summary_type;

void
new_packet_list_copy_summary_cb(GtkWidget * w _U_, gpointer data _U_, gint copy_type)
{
	gint col;
	gchar *celltext;
	GString* text;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	PacketListRecord *record;

	if(CS_CSV == copy_type) {
		text = g_string_new("\"");
	} else {
		text = g_string_new("");
	}

	if (cfile.current_frame) {
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
		/* model is filled with the current model as a convenience.  */
		gtk_tree_selection_get_selected(selection, &model, &iter);
		record = new_packet_list_get_record(model, &iter);
		for(col = 0; col < cfile.cinfo.num_cols; ++col) {
			if(col != 0) {
				if(CS_CSV == copy_type) {
					g_string_append(text,"\",\"");
				} else {
					g_string_append_c(text, '\t');
				}
			}
			if(get_col_text_from_record( record, col, &celltext)){
				g_string_append(text,celltext);
				g_free(celltext);
			}
		}
		if(CS_CSV == copy_type) {
			g_string_append_c(text,'"');
		}
		copy_to_clipboard(text);
	}
	g_string_free(text,TRUE);
}

/* XXX for some reason this does not work in the .h file XXX*/
#define RECENT_KEY_COL_WIDTH				"column.width"

void
new_packet_list_recent_write_all(FILE *rf)
{
	gint col, width;
	GtkTreeViewColumn *tree_column;

	fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
	for (col = 0; col < cfile.cinfo.num_cols; col++) {
		if (cfile.cinfo.col_fmt[col] == COL_CUSTOM) {
			fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
		} else {
			fprintf (rf, " %s,", col_format_to_string(cfile.cinfo.col_fmt[col]));
		}
		tree_column = gtk_tree_view_get_column(GTK_TREE_VIEW(GTK_TREE_VIEW(packetlist->view)), col);
		width = gtk_tree_view_column_get_width(tree_column);
		if (width == 0) {
			/* We have not initialized the packet list yet, use old values */
			width = recent_get_column_width (col);
		}
		fprintf (rf, " %d", width);
		if (col != cfile.cinfo.num_cols-1) {
			fprintf (rf, ",");
		}
	}
	fprintf (rf, "\n");
}

GtkWidget *
new_packet_list_get_widget(void)
{
	g_assert(packetlist);
	g_assert(packetlist->view);
	return packetlist->view;
}

void new_packet_list_colorize_packets(void)
{
	packet_list_reset_colorized(packetlist);
	gtk_widget_queue_draw (packetlist->view);
}

#endif /* NEW_PACKET_LIST */

