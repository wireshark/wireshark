/* content_list_http.c
 * Routines for tracking & saving content found in HTTP streams
 * Copyright 2007, Stephen Fisher <stephentfisher@yahoo.com>
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
# include "config.h"
#endif

#include <glib.h>
#include <gtk/gtk.h>

/* This feature has not been ported to GTK1 */
#if GTK_MAJOR_VERSION >= 2

#include <alert_box.h>
#include <epan/dissectors/packet-http.h>
#include <epan/emem.h>
#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <file.h>
#include <globals.h>
#include <stat_menu.h>
#include <gtk/compat_macros.h>
#include <gtk/dlg_utils.h>
#include <gtk/file_dlg.h>
#include <gtk/gui_stat_menu.h>
#include <gtk/gui_utils.h>
#include <gtk/main.h>
#include <simple_dialog.h>
#include <wiretap/file_util.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

enum {
	PKT_NUM,
	HOSTNAME_COLUMN,
	CONTENT_TYPE_COLUMN,
	BYTES_COLUMN,
	FILENAME_COLUMN,
	NUM_CONTENT_LIST_COLUMNS /* must be last */
};

typedef struct _cl_http_t {
	GSList *entries;
	GtkWidget *tree, *dlg;
	GtkTreeView *tree_view;
	GtkTreeIter *iter;
	GtkTreeStore *store;
	gint slist_pos, row_selected;
} cl_http_t;

typedef struct _cl_http_entry_t {
	guint32 pkt_num;
	gchar *hostname;
	gchar *content_type;
	gchar *filename;
	guint payload_len;
	guint8 *payload_data;
} cl_http_entry_t;


static void
remember_this_row(GtkTreeModel *model _U_, GtkTreePath *path,
		  GtkTreeIter *iter _U_, gpointer arg)
{
	cl_http_t *content_list = arg;

	gint *path_index;

	if((path_index = gtk_tree_path_get_indices(path)) == NULL)
		return;

	content_list->row_selected = path_index[0];
}

static void
remember_row_num(GtkTreeSelection *sel, gpointer data)
{
	gtk_tree_selection_selected_foreach(sel, remember_this_row, data);
}

static void
cl_http_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
        cl_http_t *content_list = data;

        protect_thread_critical_region();
        remove_tap_listener(content_list);
        unprotect_thread_critical_region();

	g_free(content_list);
}


static void
cl_http_reset(void *tapdata)
{
	cl_http_t *content_list = tapdata;

	if(content_list->entries) {
		g_slist_free(content_list->entries);
		content_list->entries = NULL;
	}

	content_list->iter = NULL;
}

static int
cl_http_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	       const void *data)
{
	cl_http_t *content_list = tapdata;
	const http_info_value_t *stat_info = data;
	cl_http_entry_t *entry;

	if(stat_info->content_type &&
	   g_ascii_strncasecmp(stat_info->content_type, "<NULL>", 6) != 0) {
		entry = g_malloc(sizeof(cl_http_entry_t));

		entry->pkt_num = pinfo->fd->num;
		entry->hostname = g_strdup(stat_info->http_host);
		entry->content_type = g_strdup(stat_info->content_type);
		entry->filename = g_path_get_basename(stat_info->request_uri);
		entry->payload_len = stat_info->payload_len;
		entry->payload_data = g_memdup(stat_info->payload_data,
					       stat_info->payload_len);

		content_list->entries = g_slist_append(content_list->entries, entry);
		return 1;
	} else {
		return 0;
	}
}

static void
cl_http_draw(void *tapdata)
{
	cl_http_t *content_list = tapdata;

	cl_http_entry_t *cl_entry;
	GSList *slist_entry = NULL;
	GSList *last_slist_entry = NULL;
	gint last_slist_entry_num;
	GtkTreeIter new_iter;
	gchar *column_text[NUM_CONTENT_LIST_COLUMNS];

	last_slist_entry = g_slist_last(content_list->entries);
	last_slist_entry_num = g_slist_position(content_list->entries,
						last_slist_entry);

	while(content_list->slist_pos <= last_slist_entry_num &&
	      last_slist_entry_num != -1) {
		slist_entry = g_slist_nth(content_list->entries,
					  content_list->slist_pos);
		cl_entry = slist_entry->data;
		
		column_text[0] = g_strdup_printf("%u", cl_entry->pkt_num);
		column_text[1] = g_strdup_printf("%s", cl_entry->hostname);
		column_text[2] = g_strdup_printf("%s", cl_entry->content_type);
		column_text[3] = g_strdup_printf("%u", cl_entry->payload_len);
		column_text[4] = g_strdup_printf("%s", cl_entry->filename);

		gtk_tree_store_append(content_list->store, &new_iter, content_list->iter);

		gtk_tree_store_set(content_list->store, &new_iter,
				   PKT_NUM, column_text[0],
				   HOSTNAME_COLUMN, column_text[1],
				   CONTENT_TYPE_COLUMN, column_text[2],
				   BYTES_COLUMN, column_text[3],
				   FILENAME_COLUMN, column_text[4],
				   -1);

		g_free(column_text[0]);
		g_free(column_text[1]);
		g_free(column_text[2]);
		g_free(column_text[3]);
		g_free(column_text[4]);

		content_list->slist_pos++;
	}
}

static void
cl_http_save_clicked_cb(GtkWidget *widget, cl_http_entry_t *entry)
{
	int to_fd;
	gchar *save_as_filename;

	save_as_filename = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widget)));

	to_fd = eth_open(save_as_filename, O_WRONLY | O_CREAT | O_TRUNC |
			 O_BINARY, 0644);
	if(to_fd == -1) {
		open_failure_alert_box(save_as_filename, errno, TRUE);
		g_free(save_as_filename);
		return;
	}

	if(eth_write(to_fd, entry->payload_data, entry->payload_len) < 0) {
		write_failure_alert_box(save_as_filename, errno);
		eth_close(to_fd);
		g_free(save_as_filename);
		return;
	}

	if (eth_close(to_fd) < 0) {
		write_failure_alert_box(save_as_filename, errno);
		g_free(save_as_filename);
		return;
	}

	g_free(save_as_filename);
}


static void
cl_http_save_entry_cb(GtkWidget *widget _U_, gpointer arg)
{
	GtkWidget *save_as_w;
	cl_http_entry_t *entry;
	cl_http_t *content_list = arg;

	entry = g_slist_nth_data(content_list->entries,
				 content_list->row_selected);

	if(!entry)
		return;

	save_as_w = file_selection_new("Wireshark: Save Content As ...",
				       FILE_SELECTION_SAVE);

	gtk_window_set_transient_for(GTK_WINDOW(save_as_w),
				     GTK_WINDOW(content_list->dlg));

	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(save_as_w),
					  entry->filename);

	if(gtk_dialog_run(GTK_DIALOG(save_as_w)) == GTK_RESPONSE_ACCEPT)
		cl_http_save_clicked_cb(save_as_w, entry);

	window_destroy(save_as_w);
}


static void
cl_http_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	GString *error_msg;
	GtkWidget *sw;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkTreeSelection *selection;
	GtkWidget *vbox, *bbox, *close_bt, *save_bt;

	cl_http_t *content_list = g_malloc0(sizeof(cl_http_t));

	/* Data will be gathered via a tap callback */
	error_msg = register_tap_listener("http", content_list, NULL,
					  cl_http_reset,
					  cl_http_packet,
					  cl_http_draw);

	if (error_msg) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Can't register http tap: %s\n", error_msg->str);
		g_string_free(error_msg, TRUE);
		return;
	}

	content_list->dlg = dlg_window_new("Wireshark: HTTP Content List");
	gtk_window_set_default_size(GTK_WINDOW(content_list->dlg),
				    DEF_WIDTH, DEF_HEIGHT);

	vbox = gtk_vbox_new(FALSE, 5);

        gtk_container_border_width(GTK_CONTAINER(vbox), 5);
        gtk_container_add(GTK_CONTAINER(content_list->dlg), vbox);

	sw = scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw),
					    GTK_SHADOW_IN);

	gtk_container_add(GTK_CONTAINER(vbox), sw);

	content_list->store = gtk_tree_store_new(NUM_CONTENT_LIST_COLUMNS,
						 G_TYPE_STRING, G_TYPE_STRING,
						 G_TYPE_STRING, G_TYPE_STRING,
						 G_TYPE_STRING);

	content_list->tree = tree_view_new(GTK_TREE_MODEL(content_list->store));

	content_list->tree_view = GTK_TREE_VIEW(content_list->tree);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Packet num",
							  renderer,
							  "text",
							  PKT_NUM,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(content_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Hostname",
							  renderer,
							  "text",
							  HOSTNAME_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(content_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Content Type",
							  renderer,
							  "text",
							  CONTENT_TYPE_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(content_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Bytes",
							  renderer,
							  "text",
							  BYTES_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(content_list->tree_view, column);

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Filename",
							  renderer,
							  "text",
							  FILENAME_COLUMN,
							  NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column(content_list->tree_view, column);

	gtk_container_add(GTK_CONTAINER(sw), content_list->tree);

	selection = gtk_tree_view_get_selection(content_list->tree_view);
        SIGNAL_CONNECT(selection, "changed", remember_row_num, content_list);

	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_SAVE, NULL);
        gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
        gtk_widget_show(bbox);

	save_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_SAVE);
	SIGNAL_CONNECT(save_bt, "clicked", cl_http_save_entry_cb, content_list);

        SIGNAL_CONNECT(content_list->dlg, "delete_event",
		       window_delete_event_cb, NULL);
	SIGNAL_CONNECT(content_list->dlg, "destroy",
		       cl_http_win_destroy_cb, NULL);

        close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
       	window_set_cancel_button(content_list->dlg, close_bt,
				 window_cancel_button_cb);

	gtk_widget_show_all(content_list->dlg);
	window_present(content_list->dlg);

	cf_retap_packets(&cfile, FALSE);
}
#endif /* GTK_MAJOR_VERSION >= 2 */


void
register_tap_listener_gtk_cl_http_stat(void)
{
#if GTK_MAJOR_VERSION >= 2
	register_stat_menu_item("HTTP", REGISTER_STAT_GROUP_CONTENT_LIST,
				cl_http_cb, NULL, NULL, NULL);
#endif
}
