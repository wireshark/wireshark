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
#include <string.h>

#include <gtk/gtk.h>

#include "epan/filesystem.h"

#include "../globals.h"
#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"
#include "gtk/sctp_stat.h"
#include "gtk/gtkglobals.h"

static GtkWidget *sctp_stat_dlg=NULL;
static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static gchar *filter_string = NULL;
static sctp_assoc_info_t* selected_stream=NULL;  /* current selection */
static sctp_allassocs_info_t *sctp_assocs=NULL;
static guint16 n_children=0;
static GtkWidget *bt_afilter = NULL, *bt_unselect=NULL, *bt_analyse=NULL, *bt_filter=NULL;
static gboolean prevent_update = FALSE, filter_applied = FALSE;

enum
{
	PORT1_COLUMN,
	PORT2_COLUMN,
	PACKETS_COLUMN,
	CHECKSUM_TYPE_COLUMN,
	CHECKSUM_ERRORS_COLUMN,
	DATA_CHUNKS_COLUMN,
	DATA_BYTES_COLUMN,
	VTAG1_COLUMN,
	VTAG2_COLUMN,
	N_COLUMN
};


static void
sctp_stat_on_select_row(GtkTreeSelection *sel, gpointer user_data _U_)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GList *list;
	sctp_assoc_info_t* assoc;
	gboolean stream_found=FALSE;
	guint32 port2, port1;
	guint32 checksum, data_chunks, data_bytes, packets, vtag1, vtag2;

	if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
		gtk_tree_model_get(model, &iter,
			PORT1_COLUMN, &port1,
			PORT2_COLUMN, &port2,
			PACKETS_COLUMN, &packets,
			CHECKSUM_ERRORS_COLUMN, &checksum,
			DATA_CHUNKS_COLUMN, &data_chunks,
			DATA_BYTES_COLUMN, &data_bytes,
			VTAG1_COLUMN, &vtag1,
			VTAG2_COLUMN, &vtag2,
			-1);
	} else {
		/* Nothing selected */
		return;
	}

	list = g_list_first(sctp_assocs->assoc_info_list);

	while (list)
	{
		assoc = (sctp_assoc_info_t*)(list->data);
		if (assoc->port1==port1 && assoc->port2==port2
		&& assoc->n_packets==packets && assoc->n_data_chunks==data_chunks && assoc->n_data_bytes==data_bytes
		&& assoc->verification_tag1==vtag1 && assoc->verification_tag2==vtag2)
		{
			selected_stream=assoc;
			stream_found=TRUE;
			break;
		}
		list=g_list_next(list);
	}

	if (!stream_found)
		selected_stream = NULL;

	gtk_widget_set_sensitive(bt_unselect,TRUE);
	gtk_widget_set_sensitive(bt_analyse,TRUE);
	gtk_widget_set_sensitive(bt_filter,TRUE);
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
		G_TYPE_UINT, /* Port1*/
		G_TYPE_UINT, /* Port2*/
		G_TYPE_UINT, /* number of packets */
		G_TYPE_STRING, /* checksum type */
		G_TYPE_UINT, /* number of checksum errors */
		G_TYPE_UINT, /* number of data chunks */
		G_TYPE_UINT, /* number of data bytes */
		G_TYPE_UINT, /* vtag1 */
		G_TYPE_UINT); /* vtag2 */

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
	column = gtk_tree_view_column_new_with_attributes ("Port 1", renderer,
		"text",	PORT1_COLUMN,
		NULL);

	gtk_tree_view_column_set_sort_column_id(column, PORT1_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 80);

	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	/* 2:nd column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Port 2", renderer,
		    "text", PORT2_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, PORT2_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 80);
	gtk_tree_view_append_column (list_view, column);

	/* 3:d column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("No of Packets", renderer,
		    "text", PACKETS_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, PACKETS_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* 4:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Checksum", renderer,
		    "text", CHECKSUM_TYPE_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, CHECKSUM_TYPE_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* 5:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("No of Errors", renderer,
		    "text", CHECKSUM_ERRORS_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, CHECKSUM_ERRORS_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* 6:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Data Chunks", renderer,
		    "text", DATA_CHUNKS_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, DATA_CHUNKS_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* 7:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Data Bytes", renderer,
		    "text", DATA_BYTES_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, DATA_BYTES_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* 8:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("VTag 1", renderer,
		    "text", VTAG1_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, VTAG1_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);


	/* 9:th column... */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("VTag 2", renderer,
		    "text", VTAG2_COLUMN,
		    NULL);
	gtk_tree_view_column_set_sort_column_id(column, VTAG2_COLUMN);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 120);
	gtk_tree_view_append_column (list_view, column);

	/* Now enable the sorting of each column */
	gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(list_view), TRUE);
	gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list_view), TRUE);

	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
	g_signal_connect(selection, "changed", G_CALLBACK(sctp_stat_on_select_row), NULL);
	return list;
}

static void
dlg_destroy(GtkWidget *w _U_, gpointer user_data _U_)
{
	guint32 i, j;
	GList *list;
	struct sctp_analyse *child_data;

	j=n_children;
	for (i=0; i<j; i++)
	{
		list=g_list_last(sctp_assocs->children);
		child_data=(struct sctp_analyse *)list->data;
		gtk_grab_remove(GTK_WIDGET(child_data->window));
		gtk_widget_destroy(GTK_WIDGET(child_data->window));
	}
	g_list_free(sctp_assocs->children);
	sctp_assocs->children = NULL;
	sctp_stat_dlg = NULL;
	prevent_update = FALSE;
	filter_applied = FALSE;
}

void
decrease_analyse_childcount(void)
{
	n_children--;
}

void
increase_analyse_childcount(void)
{
	n_children++;
}

void
set_analyse_child(struct sctp_analyse *child)
{
	sctp_assocs->children=g_list_append(sctp_assocs->children, child);
}

void
remove_analyse_child(struct sctp_analyse *child)
{
	sctp_assocs->children=g_list_remove(sctp_assocs->children, child);
}



static void add_to_clist(sctp_assoc_info_t* assinfo)
{
    GtkListStore *list_store = NULL;
    GtkTreeIter  iter;

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (clist))); /* Get store */

    gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
		PORT1_COLUMN,			(guint32)assinfo->port1,
		PORT2_COLUMN,			(guint32)assinfo->port2,
		PACKETS_COLUMN,			assinfo->n_packets,
		CHECKSUM_TYPE_COLUMN,	assinfo->checksum_type,
		CHECKSUM_ERRORS_COLUMN,	assinfo->n_checksum_errors,
		DATA_CHUNKS_COLUMN,		assinfo->n_data_chunks,
		DATA_BYTES_COLUMN,		assinfo->n_data_bytes,
		VTAG1_COLUMN,			assinfo->verification_tag1,
		VTAG2_COLUMN,			assinfo->verification_tag2,
         -1);
}

static void
sctp_stat_on_unselect(GtkButton *button _U_, gpointer user_data _U_)
{
	if (filter_string != NULL) {
		g_free(filter_string);
		filter_string = NULL;
	}

	selected_stream = NULL;
	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), "");
	main_filter_packets(&cfile, "", FALSE);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(clist)));
	gtk_widget_set_sensitive(bt_unselect,FALSE);
	gtk_widget_set_sensitive(bt_filter,FALSE);
	gtk_widget_set_sensitive(bt_analyse,FALSE);
	gtk_widget_set_sensitive(bt_afilter,FALSE);
	prevent_update = FALSE;
	filter_applied = FALSE;
}

void sctp_stat_dlg_update(void)
{
	GList *list;

	list=(sctp_stat_get_info()->assoc_info_list);
	if (sctp_stat_dlg != NULL && !prevent_update)
	{
		gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(clist))));
		list = g_list_first(sctp_stat_get_info()->assoc_info_list);

		while (list)
		{
			add_to_clist((sctp_assoc_info_t*)(list->data));
			list = g_list_next(list);
		}
	}
	last_list = list;
}



static void
sctp_stat_on_apply_filter (GtkButton *button _U_, gpointer user_data _U_)
{
	GList *list;
	sctp_assoc_info_t* assoc;
	guint16 port1, port2;
	guint32 data_chunks, data_bytes, packets, vtag1, vtag2;

	if (filter_string != NULL)
	{
		port1 = selected_stream->port1;
		port2 = selected_stream->port2;
		data_chunks = selected_stream->n_data_chunks;
		data_bytes = selected_stream->n_data_bytes;
		packets = selected_stream->n_packets;
		vtag1 = selected_stream->verification_tag1;
		vtag2 = selected_stream->verification_tag2;
		main_filter_packets(&cfile, filter_string, FALSE);
		list = g_list_first(sctp_assocs->assoc_info_list);

		while (list)
		{
			assoc = (sctp_assoc_info_t*)(list->data);
			if (assoc->port1==port1 && assoc->port2==port2
			&& assoc->n_packets==packets && assoc->n_data_chunks==data_chunks && assoc->n_data_bytes==data_bytes
			&& assoc->verification_tag1==vtag1 && assoc->verification_tag2==vtag2)
			{
				selected_stream=assoc;
				break;
			}
			list=g_list_next(list);
		}
		gtk_widget_set_sensitive(bt_afilter,FALSE);
		prevent_update=TRUE;
		filter_applied = TRUE;
	}
}

static void
sctp_stat_on_filter (GtkButton *button _U_, gpointer user_data _U_)
{
	gchar *f_string = NULL;
	GList *srclist, *dstlist;
	gchar *str=NULL;
	GString *gstring=NULL;
	struct sockaddr_in *infosrc=NULL;
	struct sockaddr_in *infodst=NULL;

	if (selected_stream==NULL) {
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), "");
		return;
	}

	if (selected_stream->check_address==FALSE)
	{
		f_string = g_strdup_printf("((sctp.srcport==%u && sctp.dstport==%u && "
			"((sctp.verification_tag==0x%x && sctp.verification_tag!=0x0) || "
			"(sctp.verification_tag==0x0 && sctp.initiate_tag==0x%x) || "
			"(sctp.verification_tag==0x%x && (sctp.abort_t_bit==1 || "
			"sctp.shutdown_complete_t_bit==1)))) ||"
			"(sctp.srcport==%u && sctp.dstport==%u && ((sctp.verification_tag==0x%x "
			"&& sctp.verification_tag!=0x0) || "
			"(sctp.verification_tag==0x0 && sctp.initiate_tag==0x%x) ||"
			"(sctp.verification_tag==0x%x && (sctp.abort_t_bit==1 ||"
			" sctp.shutdown_complete_t_bit==1)))))",
		selected_stream->port1,
		selected_stream->port2,
		selected_stream->verification_tag1,
		selected_stream->initiate_tag,
		selected_stream->verification_tag2,
		selected_stream->port2,
		selected_stream->port1,
		selected_stream->verification_tag2,
		selected_stream->initiate_tag,
		selected_stream->verification_tag1);
		filter_string = f_string;
	}
	else
	{

		srclist = g_list_first(selected_stream->addr1);
		infosrc=(struct sockaddr_in *) (srclist->data);
		gstring = g_string_new(g_strdup_printf("((sctp.srcport==%u && sctp.dstport==%u && (ip.src==%s",
			selected_stream->port1, selected_stream->port2, ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr))));
		srclist= g_list_next(srclist);

		while (srclist)
		{
			infosrc=(struct sockaddr_in *) (srclist->data);
			str =g_strdup_printf("|| ip.src==%s",ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
			g_string_append(gstring, str);
			srclist= g_list_next(srclist);
		}
		dstlist = g_list_first(selected_stream->addr2);
		infodst=(struct sockaddr_in *) (dstlist->data);
		str = g_strdup_printf(") && (ip.dst==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
		g_string_append(gstring, str);
		dstlist= g_list_next(dstlist);
		while (dstlist)
		{
			infodst=(struct sockaddr_in *) (dstlist->data);
			str =g_strdup_printf("|| ip.dst==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
			g_string_append(gstring, str);
			dstlist= g_list_next(dstlist);
		}
		srclist = g_list_first(selected_stream->addr1);
		infosrc=(struct sockaddr_in *) (srclist->data);
		str = g_strdup_printf(")) || (sctp.dstport==%u && sctp.srcport==%u && (ip.dst==%s",
			selected_stream->port1, selected_stream->port2, ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
		g_string_append(gstring, str);
		srclist= g_list_next(srclist);

		while (srclist)
		{
			infosrc=(struct sockaddr_in *) (srclist->data);
			str =g_strdup_printf("|| ip.dst==%s",ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
			g_string_append(gstring, str);
			srclist= g_list_next(srclist);
		}

		dstlist = g_list_first(selected_stream->addr2);
		infodst=(struct sockaddr_in *) (dstlist->data);
		str = g_strdup_printf(") && (ip.src==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
		g_string_append(gstring, str);
		dstlist= g_list_next(dstlist);
		while (dstlist)
		{
			infodst=(struct sockaddr_in *) (dstlist->data);
			str =g_strdup_printf("|| ip.src==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
			g_string_append(gstring, str);
			dstlist= g_list_next(dstlist);
		}
		str = g_strdup_printf(")))");
		g_string_append(gstring, str);
		filter_string = gstring->str;
		g_string_free(gstring,FALSE);
	}

	if (filter_string != NULL) {
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string);
	} else {
		g_assert_not_reached();
	}
	gtk_widget_set_sensitive(bt_afilter,TRUE);
	gtk_widget_set_sensitive(bt_filter,FALSE);
	prevent_update = TRUE;
	filter_applied = FALSE;
}


static void
sctp_stat_on_close (GtkWidget *button _U_, gpointer user_data _U_)
{
	gtk_grab_remove(sctp_stat_dlg);
	gtk_widget_destroy(sctp_stat_dlg);
	prevent_update = FALSE;
	filter_applied = FALSE;
}

static void
sctp_stat_on_analyse (GtkButton *button _U_, gpointer user_data _U_)
{
	if (selected_stream==NULL)
		return;
	else
		assoc_analyse(selected_stream);
	gtk_widget_set_sensitive(bt_analyse,FALSE);
	if (!filter_applied)
		gtk_widget_set_sensitive(bt_filter,TRUE);
	prevent_update = TRUE;
}


static void
gtk_sctpstat_dlg(void)
{
	GtkWidget *sctp_stat_dlg_w;
	GtkWidget *vbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *hbuttonbox2;
	GtkWidget *bt_close;

	sctp_stat_dlg_w = window_new (GTK_WINDOW_TOPLEVEL, "Wireshark: SCTP Associations");
	gtk_window_set_position (GTK_WINDOW (sctp_stat_dlg_w), GTK_WIN_POS_CENTER);
	g_signal_connect(sctp_stat_dlg_w, "destroy", G_CALLBACK(dlg_destroy), NULL);

	/* Container for each row of widgets */
	vbox1 = gtk_vbox_new(FALSE, 2);
	gtk_container_set_border_width(GTK_CONTAINER(vbox1), 8);
	gtk_container_add(GTK_CONTAINER(sctp_stat_dlg_w), vbox1);
	gtk_widget_show(vbox1);

	scrolledwindow1 = scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

	clist = create_list();
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	gtk_widget_set_size_request(clist, 1050, 200);

	gtk_widget_show(sctp_stat_dlg_w);

	hbuttonbox2 = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbuttonbox2), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing(GTK_BOX (hbuttonbox2), 0);
	gtk_widget_show(hbuttonbox2);

	bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_unselect);
	gtk_widget_show (bt_unselect);
	gtk_widget_set_sensitive(bt_unselect,FALSE);

	bt_filter = gtk_button_new_with_label ("Set filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_filter);
	gtk_widget_show (bt_filter);
	gtk_widget_set_sensitive(bt_filter,FALSE);

	bt_afilter = gtk_button_new_with_label ("Apply filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_afilter);
	gtk_widget_show (bt_afilter);
	gtk_widget_set_sensitive(bt_afilter,FALSE);

	bt_analyse = gtk_button_new_with_label ("Analyse");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_analyse);
	gtk_widget_show (bt_analyse);
	gtk_widget_set_sensitive(bt_analyse,FALSE);

	bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_default(bt_close, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
#endif
	window_set_cancel_button( sctp_stat_dlg_w, bt_close, sctp_stat_on_close);
	gtk_widget_grab_focus(bt_close);
	gtk_widget_show (bt_close);

	g_signal_connect(sctp_stat_dlg_w, "destroy", G_CALLBACK(dlg_destroy), NULL);
	g_signal_connect(bt_unselect, "clicked", G_CALLBACK(sctp_stat_on_unselect), NULL);
	g_signal_connect(bt_filter, "clicked", G_CALLBACK(sctp_stat_on_filter), NULL);
	g_signal_connect(bt_afilter, "clicked", G_CALLBACK(sctp_stat_on_apply_filter), NULL);
	g_signal_connect(bt_analyse, "clicked", G_CALLBACK(sctp_stat_on_analyse), NULL);

	sctp_stat_dlg = sctp_stat_dlg_w;
	cf_retap_packets(&cfile);
	gdk_window_raise(sctp_stat_dlg_w->window);

}

static void sctp_stat_dlg_show(void)
{
	if (sctp_stat_dlg != NULL)
	{
		/* There's already a dialog box; reactivate it. */
		reactivate_window(sctp_stat_dlg);
		/* Another list since last call? */
		if ((sctp_stat_get_info()->assoc_info_list) != last_list)
			sctp_stat_dlg_update();
	}
	else
	{
		/* Create and show the dialog box */
		gtk_sctpstat_dlg();
		sctp_stat_dlg_update();
	}
}


static void sctp_stat_start(GtkWidget *w _U_, gpointer data _U_)
{
	prevent_update = FALSE;
	filter_applied = FALSE;
	sctp_assocs = g_malloc(sizeof(sctp_allassocs_info_t));
	sctp_assocs = (sctp_allassocs_info_t*)sctp_stat_get_info();
	/* Register the tap listener */
	if (sctp_stat_get_info()->is_registered==FALSE)
	register_tap_listener_sctp_stat();
	/*  (redissect all packets) */
	sctp_stat_scan();

	/* Show the dialog box with the list of streams */
	sctp_stat_dlg_show();
}

/****************************************************************************/
void
register_tap_listener_sctp_stat_dlg(void)
{
	register_stat_menu_item("S_CTP/Show All Associations...", REGISTER_STAT_GROUP_TELEPHONY,
	    sctp_stat_start, NULL, NULL, NULL);
}


GtkWidget* get_stat_dlg(void)
{
	return sctp_stat_dlg;
}
