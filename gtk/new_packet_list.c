/* new_packet_list.c
 * Routines to implement a new GTK2 packet list using our custom model
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef NEW_PACKET_LIST

#ifdef HAVE_STRING_H
#include "string.h"
#endif

#include <gtk/gtk.h>
#include <glib.h>

#include "gui_utils.h"
#include "packet_list_store.h"
#include "epan/column_info.h"
#include "epan/prefs.h"
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include "../ui_util.h"
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

static PacketList *packetlist;

static gboolean enable_color;

static GtkWidget *create_view_and_model(void);
static guint row_from_iter(GtkTreeIter *iter);
static gboolean iter_from_row(GtkTreeIter *iter, guint row);
static void scroll_to_and_select_iter(GtkTreeIter *iter);
static void new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_);
static void show_cell_data_func(GtkTreeViewColumn *col,
				GtkCellRenderer *renderer,
				GtkTreeModel *model,
				GtkTreeIter *iter,
				gpointer data);

GtkWidget *
new_packet_list_create(void)
{
	GtkWidget *view, *scrollwin;

	scrollwin = scrolled_window_new(NULL, NULL);

	view = create_view_and_model();

	gtk_container_add(GTK_CONTAINER(scrollwin), view);

	/* XXX - Implement me
	g_signal_connect(view, "row-activated",
			 G_CALLBACK(popup_menu_handler),
			 g_object_get_data(G_OBJECT(popup_menu_object),
					   PM_PACKET_LIST_KEY));
	g_signal_connect(view, "button_press_event",
			 G_CALLBACK(new_packet_list_button_pressed_cb), NULL);
	*/

	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, view);

	return scrollwin;
}

guint
new_packet_list_append(column_info *cinfo, frame_data *fdata, packet_info *pinfo _U_)
{
	gint i;
	row_data_t row_data;

	if (cinfo) {
		/* Allocate the array holding column data, the size is the current number of columns */
		row_data.col_text = se_alloc(sizeof(row_data.col_text)*packetlist->n_columns);
		g_assert(packetlist->n_columns == cinfo->num_cols);
		for(i = 0; i < cinfo->num_cols; i++) {
			if (col_based_on_frame_data(cinfo, i) ||
				/* We handle custom columns lazily */
				cinfo->col_fmt[i] == COL_CUSTOM)
				/* We already store the value in frame_data, so don't duplicate this. */
				row_data.col_text[i] = NULL;
			else
				row_data.col_text[i] = se_strdup(cinfo->col_data[i]);
		}
	}
	else
		row_data.col_text = NULL;

	row_data.fdata = fdata;

	packet_list_append_record(packetlist, &row_data);

	return packetlist->num_rows; /* XXX - Check that this is the right # */
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
	g_signal_connect(packetlist->view, "button_press_event", G_CALLBACK(popup_menu_handler),
				   g_object_get_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, packetlist);

	/*     	g_object_unref(packetlist); */ /* Destroy automatically with view for now */ /* XXX - Messes up freezing & thawing */

	renderer = gtk_cell_renderer_text_new();
	g_object_set(renderer,
		     "ypad", 0,
		     NULL);		   
	gtk_widget_modify_font(packetlist->view, user_font_get_regular());

	for(i = 0; i < cfile.cinfo.num_cols; i++) {
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

		col_width = recent_get_column_width(i);
		if(col_width == -1) {
			layout = gtk_widget_create_pango_layout(packetlist->view, get_column_width_string(get_column_format(i), i));
			pango_layout_get_pixel_size(layout, &col_width, NULL);
			gtk_tree_view_column_set_min_width(col, col_width);
			g_object_unref(G_OBJECT(layout));
		}

		gtk_tree_view_append_column(GTK_TREE_VIEW(packetlist->view), col);
	}

	return packetlist->view;
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
	/* Remove extra reference added by new_packet_list_freeze() */
	g_object_unref(packetlist);

	/* Re-attach view to the model */
	gtk_tree_view_set_model(GTK_TREE_VIEW(packetlist->view),
				GTK_TREE_MODEL(packetlist));
}

void
new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	g_warning("*** new_packet_list_resize_columns_cb() not yet implemented.");
}

void
new_packet_list_next(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
		return;

	row = row_from_iter(&iter);
	if (!iter_from_row(&iter, row+1))
		return;

	scroll_to_and_select_iter(&iter);
}

void
new_packet_list_prev(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
		return;

	row = row_from_iter(&iter);
	if (!iter_from_row(&iter, row-1))
		return;

	scroll_to_and_select_iter(&iter);
}

static void
scroll_to_and_select_iter(GtkTreeIter *iter)
{
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);
	GtkTreeSelection *selection;
	GtkTreePath *path;

	/* Select the row */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, iter);
	path = gtk_tree_model_get_path(model, iter);
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			TRUE,	/* use_align */
			0.5,	/* row_align determines where the row is placed, 0.5 means center */
			0);		/* The horizontal alignment of the column */
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);
}

void
new_packet_list_select_first_row(void)
{
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);
	GtkTreeIter iter;

	if(!gtk_tree_model_get_iter_first(model, &iter))
		return;

	scroll_to_and_select_iter(&iter);
}

void
new_packet_list_select_last_row(void)
{
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);
	GtkTreeIter iter;
	gint children;

	if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
		return;

	if(!iter_from_row(&iter, children-1))
		return;

	scroll_to_and_select_iter(&iter);
}

gint
new_packet_list_find_row_from_data(gpointer data, gboolean select)
{
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);
	GtkTreeIter iter;
	frame_data *fdata;
	gint row;

	/* Initializes iter with the first iterator in the tree (the one at the path "0") 
	 * and returns TRUE. Returns FALSE if the tree is empty
	 */
	if(!gtk_tree_model_get_iter_first(model, &iter))
		return -1;

	do {
		row = row_from_iter(&iter);
		fdata = new_packet_list_get_row_data(row);

		if(fdata == (frame_data*)data){
			if(select)
				scroll_to_and_select_iter(&iter);

			return row;
		}
	} while (gtk_tree_model_iter_next (model,&iter));

    return -1;
}

void
new_packet_list_set_selected_row(gint row)
{
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);
	GtkTreeSelection *selection;
	GtkTreePath *path;

	if (!iter_from_row(&iter, row))
		return;

	/* Select the row */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, &iter);
	path = gtk_tree_model_get_path(model, &iter);
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);
}

static void
new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;
	frame_data *fdata;

	selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_get_selected(selection, NULL, &iter);

	/* Remove the hex display tab pages */
	while(gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0))
		gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

	row = row_from_iter(&iter);

	cf_select_packet(&cfile, row);

	/* Add newly selected frame to packet history (breadcrumbs) */
	fdata = new_packet_list_get_row_data(row);
	if (fdata != NULL)
		packet_history_add(fdata->num);
}

gboolean
new_packet_list_get_event_row_column(GtkWidget *w _U_, GdkEventButton *event_button,
                                 gint *row, gint *column)
{
    GtkTreePath *path;
    GtkTreeViewColumn *view_column;

    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(packetlist->view),
                                      (gint) event_button->x,
                                      (gint) event_button->y,
                                      &path, &view_column, NULL, NULL)) {
        GtkTreeIter iter;
        GList *cols;

        /* Fetch row */
        gtk_tree_model_get_iter (GTK_TREE_MODEL(packetlist), &iter, path);
        *row = row_from_iter(&iter);
        gtk_tree_path_free(path);

        /* Fetch column */
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
	PacketListRecord *record;

	record = packetlist->rows[row];

	return record->fdata;
}

static guint
row_from_iter(GtkTreeIter *iter)
{
	PacketListRecord *record;

	record = iter->user_data;

	return record->pos;
}

/* XXX: will this work with display filters? */
static gboolean
iter_from_row(GtkTreeIter *iter, guint row)
{
	GtkTreeModel *model = GTK_TREE_MODEL(packetlist);

	return gtk_tree_model_iter_nth_child(model, iter, NULL, row);
}

static void
new_packet_list_dissect(frame_data *fdata, gboolean col_text_present)
{
	epan_dissect_t edt;
	int err;
	gchar *err_info;
	column_info *cinfo;

	/* We need to construct the columns if we skipped the columns entirely
	 * when reading the file or if we have custom columns enabled */
	if (have_custom_cols(&cfile.cinfo) || !col_text_present)
		cinfo = &cfile.cinfo;
	else
		cinfo = NULL;

	if (!wtap_seek_read(cfile.wth, fdata->file_off, &cfile.pseudo_header,
		cfile.pd, fdata->cap_len, &err, &err_info)) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			cf_read_error_message(err, err_info), cfile.filename);
			return;
	}

	epan_dissect_init(&edt, TRUE /* create_proto_tree */, FALSE /* proto_tree_visible */);
	color_filters_prime_edt(&edt);
	col_custom_prime_edt(&edt, &cfile.cinfo);
	epan_dissect_run(&edt, &cfile.pseudo_header, cfile.pd, fdata, cinfo);
	fdata->color_filter = color_filters_colorize_packet(0 /* row - unused */, &edt);

	/* "Stringify" non frame_data vals */
	if (!col_text_present)
		epan_dissect_fill_in_columns(&edt, FALSE /* fill_fd_colums */);

	epan_dissect_cleanup(&edt);
}

static void
cache_columns(frame_data *fdata, guint row, gboolean col_text_present)
{
	int col;

	/* None of the columns are present. Fill them out in the record */
	if (!col_text_present) {
		for(col = 0; col < cfile.cinfo.num_cols; ++col) {
			/* Skip columns based om frame_data because we  already store those. */
			if (!col_based_on_frame_data(&cfile.cinfo, col))
				packet_list_change_record(packetlist, row, col, &cfile.cinfo);
		}
		return;
	}

	/* Custom columns are present. Fill them out in the record */
	if (have_custom_cols(&cfile.cinfo))
		for (col = cfile.cinfo.col_first[COL_CUSTOM];
			 col <= cfile.cinfo.col_last[COL_CUSTOM];
			 ++col)
			if (cfile.cinfo.col_fmt[col] == COL_CUSTOM)
				packet_list_change_record(packetlist, row, col, &cfile.cinfo);
}

static void
show_cell_data_func(GtkTreeViewColumn *col _U_, GtkCellRenderer *renderer,
		    GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	guint row;
	guint col_num = GPOINTER_TO_INT(data);
	frame_data *fdata;
	color_filter_t *color_filter;
	color_t fg_color_t;
	color_t bg_color_t;
	GdkColor fg_gdk;
	GdkColor bg_gdk;
	gchar *cell_text;
	PacketListRecord *record;

	/* XXX column zero is a temp hack 
	 * Get the pointer to the record that makes the data for all columns
	 * avalable.
	 */
	gtk_tree_model_get(model, iter,
			   0, (PacketListRecord*) &record,
			   -1);

	fdata = record->fdata;
	row = record->pos;

	if (record->dissected)
		color_filter = fdata->color_filter;
	else {
		gboolean col_text_present = FALSE;
		if(record->col_text != NULL)
			col_text_present = TRUE;

		new_packet_list_dissect(fdata, col_text_present);
		record->dissected = TRUE;
		cache_columns(fdata, row, col_text_present);
		color_filter = fdata->color_filter;
	}

	if (col_based_on_frame_data(&cfile.cinfo, col_num)) {
		col_fill_in_frame_data(fdata, &cfile.cinfo, col_num);
		cell_text = g_strdup(cfile.cinfo.col_data[col_num]);
	}else{
		cell_text = g_strdup(record->col_text[col_num]);
	}

	if((fdata->color_filter)||(fdata->flags.marked)){
		gboolean color_on = enable_color;
		if(fdata->flags.marked){
			color_t_to_gdkcolor(&fg_gdk, &prefs.gui_marked_fg);
			color_t_to_gdkcolor(&bg_gdk, &prefs.gui_marked_bg);
			color_on = TRUE;
		}else{
			color_filter = fdata->color_filter;
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
		     NULL);
	}

	g_free(cell_text);
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
set_frame_mark(gboolean set, frame_data *frame)
{
  if (set) {
    cf_mark_frame(&cfile, frame);
  } else {
    cf_unmark_frame(&cfile, frame);
  }
}

void
new_packet_list_set_font(PangoFontDescription *font)
{
	gtk_widget_modify_font(packetlist->view, font);
}

void new_packet_list_mark_frame_cb(GtkWidget *w _U_, gpointer data _U_) 
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;
	frame_data *fdata;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_get_selected(selection, NULL, &iter);
	row = row_from_iter(&iter);
	
	fdata = new_packet_list_get_row_data(row);
	if (fdata != NULL){
		set_frame_mark(!fdata->flags.marked, fdata);
	}
    mark_frames_ready();
}

#endif /* NEW_PACKET_LIST */
