/*
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "epan/filesystem.h"

#include "../globals.h"
#include "../simple_dialog.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/sctp_stat.h"


static GtkWidget *sctp_error_dlg=NULL;
static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static sctp_error_info_t* selected_packet = NULL;/* current selection */

enum
{
	FRAME_COLUMN,
	INFO_COLUMN,
	TEXT_COLUMN,
	N_COLUMN
};


static void
dlg_destroy(GtkWidget *w _U_, gpointer user_data _U_)
{
	sctp_error_dlg=NULL;
}

static void
sctp_error_on_select_row(GtkTreeSelection *sel, gpointer user_data _U_)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
		gtk_tree_model_get(model, &iter,
			FRAME_COLUMN, &(selected_packet->frame_number),
			TEXT_COLUMN, &(selected_packet->chunk_info),
			INFO_COLUMN, &(selected_packet->info_text),
			-1);
		}
}

static
GtkWidget *create_list(void)
{
	GtkListStore *list_store;
	GtkWidget * list;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkTreeView *list_view;
	GtkTreeSelection *selection;

	list_store = gtk_list_store_new(N_COLUMN,
		G_TYPE_UINT, /* Frame number*/
		G_TYPE_STRING, /* Chunk type*/
		G_TYPE_STRING );/* Info */

	/* Create a view */
	list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

	list_view = GTK_TREE_VIEW(list);

	/* Speed up the list display */
	gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

	gtk_tree_view_set_headers_clickable(list_view, TRUE);

	/* The view now holds a reference.  We can get rid of our own reference */
	g_object_unref (G_OBJECT (list_store));

	/*
	 * Create the first column packet, associating the "text" attribute of the
	 * cell_renderer to the first column of the model
	 */
	/* 1:st column */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Framenumber", renderer,
		    "text",	FRAME_COLUMN,
		    NULL);

	gtk_tree_view_column_set_sort_column_id(column, FRAME_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 80);

	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	/* 2:nd column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Chunk Types", renderer,
		    "text", TEXT_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, INFO_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_append_column (list_view, column);

	/* 3:d column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Info", renderer,
		    "text", INFO_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, TEXT_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 200);
	gtk_tree_view_append_column (list_view, column);


	/* Now enable the sorting of each column */
	gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(list_view), TRUE);
	gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list_view), TRUE);

	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
	g_signal_connect(selection, "changed", G_CALLBACK(sctp_error_on_select_row), NULL);
	return list;
}


static void add_to_clist(sctp_error_info_t* errinfo)
{
    GtkListStore *list_store = NULL;
    GtkTreeIter  iter;

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (clist))); /* Get store */

    gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
		FRAME_COLUMN,			errinfo->frame_number,
		TEXT_COLUMN,			errinfo->chunk_info,
		INFO_COLUMN,			errinfo->info_text,
         -1);
}

static void
sctp_error_on_unselect(GtkButton *button _U_, gpointer user_data _U_)
{
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(clist)));
}

static void sctp_error_dlg_update(GList *list)
{
	GList *ilist=NULL;

	if (sctp_error_dlg != NULL)
	{
		gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(clist))));
		ilist=list;

		while (ilist)
		{
			add_to_clist((sctp_error_info_t*)(ilist->data));
			ilist = g_list_next(ilist);
		}

		sctp_error_on_unselect(NULL, NULL);
	}
	last_list = ilist;
}



static void
sctp_error_on_frame (GtkButton *button _U_, gpointer user_data _U_)
{

	if (selected_packet==NULL)
		return;

	if (selected_packet)
		cf_goto_frame(&cfile, selected_packet->frame_number);
}


static void
sctp_error_on_close (GtkButton *button _U_, gpointer user_data _U_)
{
	gtk_grab_remove(sctp_error_dlg);
	gtk_widget_destroy(sctp_error_dlg);
}

static void
gtk_sctperror_dlg(void)
{
	GtkWidget *sctp_error_dlg_w;
	GtkWidget *vbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *hbuttonbox2;
	GtkWidget *bt_unselect;
	GtkWidget *bt_frame;
	GtkWidget *bt_close;

	sctp_error_dlg_w = window_new (GTK_WINDOW_TOPLEVEL, "Wireshark: SCTP Associations");
	gtk_window_set_position (GTK_WINDOW (sctp_error_dlg_w), GTK_WIN_POS_CENTER);
	g_signal_connect(sctp_error_dlg_w, "destroy", G_CALLBACK(dlg_destroy), NULL);

	/* Container for each row of widgets */
	vbox1 = gtk_vbox_new(FALSE, 2);
	gtk_container_set_border_width(GTK_CONTAINER(vbox1), 8);
	gtk_container_add(GTK_CONTAINER(sctp_error_dlg_w), vbox1);
	gtk_widget_show(vbox1);

	scrolledwindow1 = scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

	clist = create_list();
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	gtk_widget_set_size_request(clist, 500, 200);

	gtk_widget_show(sctp_error_dlg_w);


	hbuttonbox2 = gtk_hbutton_box_new ();
	gtk_widget_show (hbuttonbox2);
	gtk_box_pack_start (GTK_BOX (vbox1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_box_set_spacing (GTK_BOX (hbuttonbox2), 5);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);


	bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_widget_show (bt_unselect);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_unselect);

	bt_frame = gtk_button_new_with_label ("Go to Frame");
	gtk_widget_show (bt_frame);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_frame);

	bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_widget_show (bt_close);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);

	g_signal_connect(sctp_error_dlg_w, "destroy", G_CALLBACK(dlg_destroy), NULL);
	g_signal_connect(bt_unselect, "clicked", G_CALLBACK(sctp_error_on_unselect), NULL);
	g_signal_connect(bt_frame, "clicked", G_CALLBACK(sctp_error_on_frame), NULL);
	g_signal_connect(bt_close, "clicked", G_CALLBACK(sctp_error_on_close), NULL);

	sctp_error_dlg = sctp_error_dlg_w;

}


void sctp_error_dlg_show(sctp_assoc_info_t* assoc)
{
	GList *list;

	list =assoc->error_info_list;
	if (list != NULL)
	{
		if (sctp_error_dlg != NULL) {
			/* There's already a dialog box; reactivate it. */
			reactivate_window(sctp_error_dlg);
			/* Another list since last call? */
			if (list != last_list) {
				sctp_error_dlg_update(list);
			}
		}
		else {
			/* Create and show the dialog box */
			gtk_sctperror_dlg();
			sctp_error_dlg_update(list);
		}
	}
	else
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "No errors found!");
}
