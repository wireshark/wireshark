/* new_packet_list.c
 * Routines to implement a new GTK2 packet list using our custom model
 * Copyright 2008-2009, Stephen Fisher <stephentfisher@yahoo.com>
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

#include "../ui_util.h"

#include "gui_utils.h"
#include "packet_list_store.h"
#include "epan/column_info.h"
#include "epan/emem.h"
#include "globals.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "epan/column.h"
#include "gtk/recent.h"
#include "gtk/keys.h"
#include "gtk/menus.h"

static PacketList *packetlist;

static GtkWidget *create_view_and_model(void);
static guint row_from_iter(GtkTreeIter *iter);
static void new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_);

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
new_packet_list_append(column_info cinfo, frame_data *fdata)
{
	gint i;
	row_data_t *row_data;

	row_data = g_new0(row_data_t, NUM_COL_FMTS+1);

	for(i = 0; i < cfile.cinfo.num_cols; i++) {
		row_data->col_text[cinfo.col_fmt[i]] =
			se_strdup(cinfo.col_data[i]);
	}

	row_data->fdata = fdata;

	packet_list_append_record(packetlist, row_data);

	g_free(row_data);

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

	gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(packetlist->view),
					    TRUE);

	g_signal_connect(packetlist->view, "cursor-changed",
			 G_CALLBACK(new_packet_list_select_cb), NULL);

	/*     	g_object_unref(packetlist); */ /* Destroy automatically with view for now */ /* XXX - Messes up freezing & thawing */

	renderer = gtk_cell_renderer_text_new();
	g_object_set(renderer, "ypad", 0, "font-desc", user_font_get_regular(),
		     NULL);		     

	for(i = 0; i < cfile.cinfo.num_cols; i++) {
		col = gtk_tree_view_column_new();
		gtk_tree_view_column_pack_start(col, renderer, TRUE);
		gtk_tree_view_column_add_attribute(col, renderer, "text",
						   cfile.cinfo.col_fmt[i]);
		gtk_tree_view_column_set_title(col, cfile.cinfo.col_title[i]);
		gtk_tree_view_column_set_sort_column_id(col, i);
		gtk_tree_view_column_set_resizable(col, TRUE);
		gtk_tree_view_column_set_sizing(col,GTK_TREE_VIEW_COLUMN_FIXED);

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
	g_warning("*** new_packet_list_next() not yet implemented.");
}

void
new_packet_list_prev(void)
{
	g_warning("*** new_packet_list_prev() not yet implemented.");
}

static void
new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	guint row;

	selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_get_selected(selection, NULL, &iter);

	/* Remove the hex display tab pages */
	while(gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0))
		gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

	row = row_from_iter(&iter);

	cf_select_packet(&cfile, row);
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

#endif /* NEW_PACKET_LIST */
